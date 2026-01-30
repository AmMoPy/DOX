import sqlite3
import json
import logging
from uuid import UUID
from typing import Optional, Dict, List, Any
from datetime import datetime, timedelta, UTC
from app.config.setting import settings
from app.db.utils_db.async_bridge import async_bridge
from app.db.utils_db.sql_pool_mngr import SQLiteHashPool
from app.db.utils_db.circuit_breaker import sql_cb, DatabaseError
from app.auth.hash_service import TokenHasher # SHA-256
from app.auth.mfa_crypto import mfa_encryption as mfa_crypto # Fernet
from app.auth.pwd_mngr.pwd_utils import hash_password # bcrypt

logger = logging.getLogger(__name__)


class SQLiteAuthStore:
    """Authentication store for SQLite"""
    
    def __init__(
        self, 
        hasher: TokenHasher, # dependency injection
        ):
        self.hasher = hasher
        self.pool = SQLiteHashPool() # direct assignment, no future swapping
        self._initialized = False


    async def initialize(self):
        """Initialize auth tables"""
        if self._initialized:
            return
        
        try:
            logger.debug("Initializing SQLite Auth Store...")
            
            await async_bridge.run_in_db_thread(
                lambda: self.pool.initialize(
                    settings.paths.SQL_DB_PATH / "auth.db",
                    settings.database.HASH_CACHE_POOL_SIZE # TODO: SEPARATE ONE FOR AUTH
                    )
                )

            # Setup own schema
            async with self.pool.get_connection() as conn:
                await sql_cb.execute(
                    async_bridge.run_in_db_thread(
                        lambda: self._setup_schema(conn)
                    )   
                )
            
            self._initialized = True
            logger.debug("SQLite Auth Store initialized")
            
        except Exception as e:
            logger.error(f"Failed to initialize auth store: {e}")
            raise DatabaseError(f"Auth database error: {e}")
    

    def _setup_schema(self, conn: sqlite3.Connection):
        """Setup authentication tables"""
        
        # Users table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY, -- uuid string conversion handled internally
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT,  -- For local auth
                role TEXT NOT NULL CHECK (role IN ('admin', 'user')),
                auth_method TEXT DEFAULT 'local' CHECK (auth_method IN ('local', 'oidc', 'saml')),
                mfa_enabled INTEGER DEFAULT 0,
                sso_provider TEXT,
                sso_id TEXT,
                sso_attributes TEXT DEFAULT '{}',  -- Store SSO claims
                -- created_at INTEGER DEFAULT (strftime('%s', 'now')),
                created_at INTEGER DEFAULT (unixepoch('now')),
                last_login INTEGER DEFAULT (unixepoch('now')),
                is_active INTEGER DEFAULT 1,
                account_locked_until INTEGER,
                failed_login_attempts INTEGER DEFAULT 0, -- For failed login protection
                metadata TEXT DEFAULT '{}'
            )
        ''')
        
        # API Keys table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS api_keys (
                key_id TEXT PRIMARY KEY,
                key_hash TEXT UNIQUE NOT NULL,
                user_id TEXT NOT NULL,
                name TEXT NOT NULL,
                scopes TEXT NOT NULL,
                created_at INTEGER DEFAULT (unixepoch('now')),
                expires_at INTEGER NOT NULL, --no good datetime support, thus conversion to int
                last_used INTEGER,
                is_active INTEGER DEFAULT 1,
                FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
            )
        ''')
        
        # Sessions table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                token_hash TEXT UNIQUE NOT NULL,
                created_at INTEGER DEFAULT (unixepoch('now')),
                expires_at INTEGER NOT NULL,
                ip_address TEXT,
                user_agent TEXT,
                mfa_verified INTEGER DEFAULT 1,
                FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
            )
        ''')

        # Refresh tokens table - Secure token rotation
        conn.execute('''
            CREATE TABLE IF NOT EXISTS refresh_tokens (
                token_id TEXT PRIMARY KEY,
                token_hash TEXT UNIQUE NOT NULL,
                user_id TEXT NOT NULL,
                session_id TEXT,
                created_at INTEGER DEFAULT (unixepoch('now')),
                expires_at INTEGER NOT NULL,
                revoked INTEGER DEFAULT 0,
                revoked_at INTEGER,
                ip_address TEXT,
                user_agent TEXT,
                FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
                FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
            )
        ''')
        
        # MFA secrets table - TOTP configuration storage
        conn.execute('''
            CREATE TABLE IF NOT EXISTS mfa_secrets (
                user_id TEXT PRIMARY KEY,
                method TEXT NOT NULL DEFAULT 'totp' CHECK (method IN ('totp', 'sms', 'email')),
                secret TEXT NOT NULL,
                backup_codes TEXT NOT NULL,  -- JSON array of codes
                created_at INTEGER DEFAULT (unixepoch('now')),
                verified_at INTEGER,
                last_used INTEGER,
                FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
            )
        ''')

        # password reset tokens table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS password_reset_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token_hash TEXT UNIQUE NOT NULL,
                user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
                created_at INTEGER DEFAULT (unixepoch('now')),
                expires_at INTEGER NOT NULL, -- Every INSERT must explicitly provide expires_at
                used INTEGER DEFAULT 0,
                used_at TIMESTAMP,
                ip_address TEXT,

                forced_by_admin INTEGER DEFAULT 0,

                CONSTRAINT valid_expiry CHECK (expires_at > created_at)
            )
        ''')

        # Audit log table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT, -- no need for universal uniqueness
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                user_id TEXT,
                email TEXT,
                ip_address TEXT,
                user_agent TEXT,
                timestamp INTEGER DEFAULT (unixepoch('now')),
                details TEXT DEFAULT '{}',
                success INTEGER DEFAULT 1,
                error_message TEXT,
                FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE SET NULL -- keep for compliance/forensics
            )
        ''')    
        
        indexes = [
            'CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)',
            'CREATE INDEX IF NOT EXISTS idx_users_sso ON users(sso_provider, sso_id)',
            'CREATE INDEX IF NOT EXISTS idx_users_active ON users(is_active)',
            'CREATE INDEX IF NOT EXISTS idx_users_mfa_enabled ON users(mfa_enabled)',

            'CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id)',
            'CREATE INDEX IF NOT EXISTS idx_api_keys_active ON api_keys(is_active, expires_at)',

            'CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)',
            'CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at)',

            'CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id)',
            'CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp DESC)',
            'CREATE INDEX IF NOT EXISTS idx_audit_event_type ON audit_log(event_type)',
            'CREATE INDEX IF NOT EXISTS idx_audit_severity ON audit_log(severity)',
            'CREATE INDEX IF NOT EXISTS idx_audit_email ON audit_log(email)',
            'CREATE INDEX IF NOT EXISTS idx_audit_ip ON audit_log(ip_address)',

            'CREATE INDEX IF NOT EXISTS idx_reset_token_hash ON password_reset_tokens(token_hash)',
            'CREATE INDEX IF NOT EXISTS idx_reset_user ON password_reset_tokens(user_id)',
            'CREATE INDEX IF NOT EXISTS idx_reset_expires ON password_reset_tokens(expires_at)',
            'CREATE INDEX IF NOT EXISTS idx_reset_used ON password_reset_tokens(used)',

            'CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens(user_id)',
            'CREATE INDEX IF NOT EXISTS idx_refresh_tokens_hash ON refresh_tokens(token_hash)',
            'CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires ON refresh_tokens(expires_at)',
            'CREATE INDEX IF NOT EXISTS idx_refresh_tokens_revoked ON refresh_tokens(revoked)',

            'CREATE INDEX IF NOT EXISTS idx_mfa_secrets_user ON mfa_secrets(user_id)',
        ]
        
        for index in indexes:
            try:
                conn.execute(index)
            except Exception as e:
                logger.debug(f"Index creation note: {e}")
            

    async def create_user(
        self, 
        email: str, 
        role: str = 'user',
        auth_method: str = 'local',
        mfa_enabled: Optional[bool] = None,
        password_hash: Optional[str] = None,
        sso_id: Optional[str] = None,
        user_id: Optional[UUID] = None  # Allow custom user_id (if None, auto-generated - optional override)
        ) -> Dict[str, Any]:
        """Create new user"""
        try:
            # default auto-generation.
            # Custom IDs only for migration/import scenarios
            if user_id:
                # Validate custom user_id if provided
                from app.val.file_val import text_validator
                user_id = text_validator.validate_user_id(user_id)
            else:
                user_id = self.hasher.generate_id()

            async with self.pool.get_connection() as conn:
                await sql_cb.execute(
                    async_bridge.run_in_db_thread(
                        lambda: conn.execute('''
                            INSERT INTO users 
                            (user_id, email, role, password_hash, auth_method, mfa_enabled, sso_id)
                            VALUES (?, ?, ?, ?, ?, ?, ?)
                        ''', (user_id, email, role, password_hash, auth_method, 1 if mfa_enabled else 0, sso_id)
                        )
                    )
                )

            logger.info(f"Created user: {email} ({role}), {auth_method})")

            return {
                'user_id': user_id,
                'email': email, 
                'role': role,
                'auth_method': auth_method
            }

        except DatabaseError:
            raise
        except sqlite3.IntegrityError:
            raise ValueError(f"User with email {email} already exists")
        except Exception as e:
            logger.error(f"Failed to create user: {e}")
            raise DatabaseError(f"Unexpected database user creation error: {e}")
    

    async def get_user_by_email(self, email: str, include_pass=False) -> Optional[Dict[str, Any]]:
        """Get user by email"""
        try:
            # main query 
            fields = [
                "user_id", "email", "role", "sso_provider", "sso_id",
                "created_at", "last_login", "account_locked_until",
                "is_active", "auth_method", "mfa_enabled"
            ]

            # pwd hashes should only be queried when
            # absolutely necessary (least privilege)
            if include_pass:
                fields.append("password_hash")

            async with self.pool.get_connection() as conn:
                row = await async_bridge.run_in_db_thread(
                    lambda: conn.execute(f'''
                        SELECT {', '.join(fields)}
                        FROM users 
                        -- WHERE email = ? AND is_active = 1
                        WHERE email = ?
                    ''', (email,)
                    ).fetchone()
                )
                
                if row:
                    # always materialize Row objects to 
                    # dicts while the connection is still active
                    # return dict(row) # <-- might have lazy evaluation issues
                    return {
                        "user_id": UUID(row['user_id']),
                        "email": row['email'],
                        "role": row['role'],
                        "sso_provider": row['sso_provider'],
                        "sso_id": row['sso_id'],
                        "created_at": datetime.fromtimestamp(row['created_at'], UTC).isoformat(),
                        "last_login": datetime.fromtimestamp(row['last_login'], UTC).isoformat(),
                        "account_locked_until": datetime.fromtimestamp(row['account_locked_until'], UTC) if row['account_locked_until'] else None, # datetime object
                        "is_active": row['is_active'],
                        "auth_method": row['auth_method'],
                        "mfa_enabled": row['mfa_enabled'],
                        "password_hash": row['password_hash'] if include_pass else None,
                    }

                return None
            
        except Exception as e:
            logger.error(f"Failed to get user: {e}")
            raise DatabaseError(f"Unexpected database user e-mail check error: {e}")
    

    async def get_user_by_id(self, user_id: UUID, include_pass=False) -> Optional[Dict[str, Any]]:
        """Get user by ID"""
        try:
            fields = [
                "user_id", "email", "role", "sso_provider", "sso_id",
                "created_at", "last_login", "account_locked_until",
                "is_active", "auth_method", "mfa_enabled"
            ]

            if include_pass:
                fields.append("password_hash")

            async with self.pool.get_connection() as conn:
                row = await async_bridge.run_in_db_thread(
                    lambda: conn.execute(f'''
                        SELECT {', '.join(fields)}
                        FROM users 
                        -- WHERE user_id = ? AND is_active = 1
                        WHERE user_id = ?
                    ''', (user_id,)
                    ).fetchone()
                )
            
                if row:
                    # return dict(row)
                    return {
                        "user_id": UUID(row['user_id']),
                        "email": row['email'],
                        "role": row['role'],
                        "sso_provider": row['sso_provider'],
                        "sso_id": row['sso_id'],
                        "created_at": datetime.fromtimestamp(row['created_at'], UTC).isoformat(),
                        "last_login": datetime.fromtimestamp(row['last_login'], UTC).isoformat(),
                        "account_locked_until": datetime.fromtimestamp(row['account_locked_until'], UTC) if row['account_locked_until'] else None,
                        "is_active": row['is_active'],
                        "auth_method": row['auth_method'],
                        "mfa_enabled": row['mfa_enabled'],
                        "password_hash": row['password_hash'] if include_pass else None,
                    }

                return None
            
        except Exception as e:
            logger.error(f"Failed to get user: {e}")
            raise DatabaseError(f"Unexpected database user ID check error: {e}")
    

    async def create_api_key(
        self, 
        user_id: UUID,
        name: str,
        scopes: List[str], 
        expires_days: int = 30
        ) -> Dict[str, Any]:
        """Create API key"""
        try:
            raw_key, key_hash = self.hasher.generate_token(32)  # Returns (raw, hash) tuple
            key_id = self.hasher.generate_id() # UUID
            
            # Golden rule for time handeling:
            # Store: Always UTC (Unix timestamps for sql or UTC datetime for postgress)
            # Retrieve: Always return ISO with 'Z'
            # Display: Browser converts UTC -> local time
            expires_at = int((datetime.now(UTC) + timedelta(days=expires_days)).timestamp())
            scopes_str = ','.join(scopes)
            
            async with self.pool.get_connection() as conn:
                await sql_cb.execute(
                    async_bridge.run_in_db_thread(
                        lambda: conn.execute('''
                            INSERT INTO api_keys (key_id, key_hash, user_id, name, scopes, expires_at)
                            VALUES (?, ?, ?, ?, ?, ?)
                        ''', (key_id, key_hash, user_id, name, scopes_str, expires_at)
                        )
                    )
                )
            
            return {
                'key_id': key_id,
                'key': raw_key,
                'name': name,
                'scopes': scopes,
                'expires_at': datetime.fromtimestamp(expires_at, UTC).isoformat()
            }
        
        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to create API key: {e}")
            raise DatabaseError(f"Unexpected database api key creation error: {e}")
    

    async def verify_api_key(self, raw_key: str) -> Optional[Dict[str, Any]]:
        """Verify API key"""
        try:
            key_hash = self.hasher.hash(raw_key)
            current_time = int(datetime.now(UTC).timestamp())
            
            async with self.pool.get_connection() as conn:
                row = await async_bridge.run_in_db_thread(
                    lambda: conn.execute('''
                        SELECT 
                            ak.key_id, ak.user_id, ak.scopes, ak.expires_at,
                            u.email, u.role, u.mfa_enabled, u.auth_method, 
                            u.is_active as user_active
                        FROM api_keys ak
                        JOIN users u ON ak.user_id = u.user_id
                        WHERE ak.key_hash = ? 
                          AND ak.is_active = 1
                          AND ak.expires_at > ?
                          AND u.is_active = 1
                    ''', (key_hash, current_time)
                    ).fetchone()
                )
                
                if row:
                    # Update last_used
                    await sql_cb.execute(
                        async_bridge.run_in_db_thread(
                            lambda: conn.execute(
                                'UPDATE api_keys SET last_used = ? WHERE key_hash = ?',
                                (current_time, key_hash)
                            )
                        )
                    )

                    return {
                        'key_id': UUID(row['key_id']),
                        'user_id': UUID(row['user_id']),
                        'scopes': row['scopes'].split(','),
                        'expires_at': datetime.fromtimestamp(row['expires_at'], UTC).isoformat(),
                        'email': row['email'],
                        'role': row['role'],
                        'mfa_enabled': row['mfa_enabled'],
                        'auth_method': row['auth_method'],
                        'user_active': row['user_active']
                    }
            
                return None
        
        except DatabaseError:
            raise    
        except Exception as e:
            logger.error(f"Failed to verify API key: {e}")
            # return None
            raise DatabaseError(f"Unexpected database api key verification error: {e}")
    

    async def revoke_api_key(self, key_id: UUID, user_id: UUID):
        """Revoke API key"""
        try:
            async with self.pool.get_connection() as conn:
                await sql_cb.execute(
                    async_bridge.run_in_db_thread(
                        lambda: conn.execute('''
                            UPDATE api_keys 
                            SET is_active = 0 
                            WHERE key_id = ? AND user_id = ?
                        ''', (key_id, user_id)
                        )
                    )
                )
        
        except DatabaseError:
            raise  
        except Exception as e:
            logger.error(f"Failed to revoke API key: {e}")
            raise DatabaseError(f"Unexpected database api keys revocation error: {e}")


    async def list_user_api_keys(self, user_id: UUID) -> List[Dict[str, Any]]:
        """List user's API keys"""
        try:
            async with self.pool.get_connection() as conn:
                rows = await async_bridge.run_in_db_thread(
                    lambda: conn.execute('''
                        SELECT key_id, name, scopes, created_at, expires_at, last_used, is_active
                        FROM api_keys
                        WHERE user_id = ?
                        ORDER BY created_at DESC
                    ''', (user_id,)
                    ).fetchall() 
                )
                
                result = []

                for row in rows:
                    result.append({
                        'key_id': UUID(row['key_id']),
                        'name': row['name'],
                        'scopes': row['scopes'].split(','),
                        "created_at": datetime.fromtimestamp(row['created_at'], UTC).isoformat(),
                        "expires_at": datetime.fromtimestamp(row['expires_at'], UTC).isoformat(),
                        'last_used': datetime.fromtimestamp(row['last_used'], UTC).isoformat() if row['last_used'] else None,
                        'is_active': row['is_active']
                    })
                
                return result
            
        except Exception as e:
            logger.error(f"Failed to list API keys: {e}")
            raise DatabaseError(f"Unexpected database api keys listing error: {e}")


    async def create_session(
        self, 
        user_id: UUID, 
        timedelta: timedelta, # let callers decide
        mfa_verified: bool = True, # only disable at login after mfa activation, seemless transition at intial setup and token refresh
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
        ) -> str:
        """
        Create session token

        Returns:
            Dict with 'access_token', 'session_id', 'expires_at'
        """
        try:
            raw_token, token_hash = self.hasher.generate_token(32)
            session_id = self.hasher.generate_id()
            expires_at = int((datetime.now(UTC) + timedelta).timestamp())
            
            async with self.pool.get_connection() as conn:
                await sql_cb.execute( 
                    async_bridge.run_in_db_thread(
                        lambda: conn.execute('''
                            INSERT INTO sessions 
                            (session_id, user_id, token_hash, expires_at, ip_address, user_agent, mfa_verified)
                            VALUES (?, ?, ?, ?, ?, ?, ?)
                        ''', (session_id, user_id, token_hash, expires_at, ip_address, user_agent, 1 if mfa_verified else 0)
                        )
                    )
                )
                
                return {
                    'access_token': raw_token,
                    'session_id': session_id,
                    'expires_at': datetime.fromtimestamp(expires_at, UTC).isoformat()
                }
        
        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to create session: {e}")
            raise DatabaseError(f"Unexpected database session creation error: {e}")
    

    async def verify_session(self, raw_token: str) -> Optional[Dict[str, Any]]:
        """Verify session token"""
        try:
            token_hash = self.hasher.hash(raw_token)
            current_time = int(datetime.now(UTC).timestamp())
            
            async with self.pool.get_connection() as conn:
                row = await async_bridge.run_in_db_thread(
                    lambda: conn.execute('''
                        SELECT
                            s.session_id, s.user_id, s.expires_at, s.mfa_verified,
                            u.email, u.role, u.is_active, u.auth_method, 
                            u.mfa_enabled
                        FROM sessions s
                        JOIN users u ON s.user_id = u.user_id
                        WHERE s.token_hash = ? 
                          AND s.expires_at > ?
                          AND u.is_active = 1
                    ''', (token_hash, current_time)
                    ).fetchone()
                )
                
                if row:
                    return {
                        'session_id': UUID(row['session_id']),
                        'user_id': UUID(row['user_id']),
                        "expires_at": datetime.fromtimestamp(row['expires_at'], UTC), # datetime object for dynamic use comparison/conversion
                        'email': row['email'],
                        'role': row['role'],
                        'is_active': row['is_active'],
                        'auth_method': row['auth_method'],
                        'mfa_enabled': row['mfa_enabled'],
                        'mfa_verified': row['mfa_verified']
                    }

                return None
            
        except Exception as e:
            logger.error(f"Failed to verify session: {e}")
            # return None
            raise DatabaseError(f"Unexpected database session verification error: {e}")    


    async def revoke_session(self, session_id: UUID) -> bool:
        """Revoke specific session"""
        try:
            async with self.pool.get_connection() as conn:
                cursor = await sql_cb.execute(
                    async_bridge.run_in_db_thread(
                        lambda: conn.execute('''
                            DELETE FROM sessions 
                            WHERE session_id = ?
                        ''', (session_id,)
                        )
                    )
                )
                
                deleted = cursor.rowcount > 0
                
                if deleted:
                    logger.info(f"Session revoked: {session_id}")
                
                return deleted
            
        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to revoke session: {e}")
            return False


    async def increment_failed_login(self, user_id: UUID) -> int:
        """Increment failed login counter and return new count"""
        try:
            async with self.pool.get_connection() as conn:
                # update
                await sql_cb.execute(
                    async_bridge.run_in_db_thread(
                        lambda: conn.execute('''
                            UPDATE users 
                            SET failed_login_attempts = failed_login_attempts + 1
                            WHERE user_id = ?
                        ''', (user_id,)
                        )
                    )
                )

                # Then get the value
                result = await async_bridge.run_in_db_thread(
                    lambda: conn.execute('''
                        SELECT failed_login_attempts 
                        FROM users 
                        WHERE user_id = ?
                    ''', (user_id,)
                    ).fetchone()
                )
                
                return result['failed_login_attempts'] if result else 0

        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to increment failed login: {e}")
            raise DatabaseError(f"Database error: {e}")


    async def lock_account(self, user_id: UUID, locked_until: datetime):
        """Lock user account until specified time"""

        # convert to Unix
        locked_until = int(locked_until.timestamp())

        try:
            async with self.pool.get_connection() as conn:
                await sql_cb.execute(
                    async_bridge.run_in_db_thread(
                        lambda: conn.execute('''
                            UPDATE users 
                            SET account_locked_until = ?
                            WHERE user_id = ?
                        ''', (locked_until, user_id)
                        )
                    )
                )

                logger.info(f"User Account Locked")

                return True

        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to lock account: {e}")
            return False


    async def reset_failed_login(self, user_id: UUID):
        """Reset failed login attempts"""
        try:
            async with self.pool.get_connection() as conn:
                await sql_cb.execute( 
                    async_bridge.run_in_db_thread(
                        lambda: conn.execute('''
                            UPDATE users 
                            SET failed_login_attempts = 0, account_locked_until = NULL
                            WHERE user_id = ?
                        ''', (user_id,)
                        )
                    )
                )

        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to reset failed login: {e}")
            raise DatabaseError(f"Database error: {e}")


    async def update_last_login(self, user_id: UUID):
        """Update last login timestamp"""
        try:
            current_time = int(datetime.now(UTC).timestamp())

            async with self.pool.get_connection() as conn:
                await sql_cb.execute(
                    async_bridge.run_in_db_thread(
                        lambda: conn.execute('''
                            UPDATE users 
                            SET last_login = ?
                            WHERE user_id = ?
                        ''', (current_time, user_id)
                        )
                    )
                )

        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to update last login: {e}")
            raise DatabaseError(f"Database error: {e}")


    async def update_password_hash(self, user_id: UUID, password_hash: str):
        """    
        Update user password hash (internal use only).
    
        WARNING: This method bypasses password validation!
        Don't expose this in public API - Ensure callers
        validate old password/reset tokens beforehand.
        
        Direct usage from endpoints is a SECURITY RISK.
        
        Args:
            user_id: User whose password to update
            password_hash: Pre-hashed password (bcrypt hash)
        """
        try:
            async with self.pool.get_connection() as conn:
                await sql_cb.execute(
                    async_bridge.run_in_db_thread(
                        lambda: conn.execute('''
                            UPDATE users 
                            SET password_hash = ?
                            WHERE user_id = ?
                        ''', (password_hash, user_id)
                        )
                    )
                )

        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to update password: {e}")
            raise DatabaseError(f"Database error: {e}")


    async def list_users(
        self,
        skip: int = 0,
        limit: int = 50,
        role: Optional[str] = None,
        auth_method: Optional[str] = None,
        is_active: Optional[bool] = None,
        search: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List users with filters and pagination"""
        try:
            query = '''
                SELECT user_id, email, role, auth_method, is_active,
                       created_at, last_login, failed_login_attempts,
                       account_locked_until, sso_provider, sso_id
                FROM users
                WHERE 1=1
            '''
            params = []
            
            if role:
                query += ' AND role = ?'
                params.append(role)
            
            if auth_method:
                query += ' AND auth_method = ?'
                params.append(auth_method)
            
            if is_active is not None:
                query += ' AND is_active = ?'
                params.append(1 if is_active else 0)
            
            if search:
                query += ' AND email LIKE ?'
                params.append(f'%{search}%')
            
            query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?'
            params.extend([limit, skip])
            
            async with self.pool.get_connection() as conn:
                rows = await async_bridge.run_in_db_thread(
                    lambda: conn.execute(query, params).fetchall()
                )

                return [
                    {
                        "user_id": UUID(row['user_id']),
                        "email": row['email'],
                        "role": row['role'],
                        "auth_method": row['auth_method'],
                        "is_active": row['is_active'],
                        "created_at": datetime.fromtimestamp(row['created_at'], UTC).isoformat(),
                        "last_login": datetime.fromtimestamp(row['last_login'], UTC).isoformat(),
                        "failed_login_attempts": row['failed_login_attempts'],
                        "account_locked_until": datetime.fromtimestamp(row['account_locked_until'], UTC).isoformat() if row['account_locked_until'] else None,
                        "sso_provider": row['sso_provider'],
                        "sso_id": row['sso_id']
                    }

                    for row in rows
                ]
                
        except Exception as e:
            logger.error(f"Failed to list users: {e}")
            raise DatabaseError(f"Database error: {e}")


    async def count_users(
        self,
        role: Optional[str] = None,
        auth_method: Optional[str] = None,
        is_active: Optional[bool] = None,
        search: Optional[str] = None
    ) -> int:
        """Count users with filters"""
        try:
            query = 'SELECT COUNT(*) FROM users WHERE 1=1'
            params = []
            
            if role:
                query += ' AND role = ?'
                params.append(role)
            
            if auth_method:
                query += ' AND auth_method = ?'
                params.append(auth_method)
            
            if is_active is not None:
                query += ' AND is_active = ?'
                params.append(1 if is_active else 0)
            
            if search:
                query += ' AND email LIKE ?'
                params.append(f'%{search}%')
            
            async with self.pool.get_connection() as conn:
                row = await async_bridge.run_in_db_thread(
                    lambda: conn.execute(query, params).fetchone()
                )
                
                return row[0] if row else 0
                
        except Exception as e:
            logger.error(f"Failed to count users: {e}")
            return 0


    async def get_user_stats(self) -> Dict[str, Any]:
        """Get user statistics"""
        try:
            current_time = int(datetime.now(UTC).timestamp())
            seven_days_ago = current_time - (7 * 24 * 3600)
            one_day_ago = current_time - (24 * 3600)
            
            async with self.pool.get_connection() as conn:
                stats = await async_bridge.run_in_db_thread(
                    lambda: conn.execute('''
                        SELECT 
                            COUNT(*) as total_users,
                            SUM(CASE WHEN is_active = 1 THEN 1 ELSE 0 END) as active_users,
                            SUM(CASE WHEN is_active = 0 THEN 1 ELSE 0 END) as inactive_users,
                            SUM(CASE WHEN role = 'admin' THEN 1 ELSE 0 END) as admin_count,
                            SUM(CASE WHEN role = 'user' THEN 1 ELSE 0 END) as user_count,
                            SUM(CASE WHEN auth_method = 'local' THEN 1 ELSE 0 END) as local_auth_count,
                            SUM(CASE WHEN auth_method = 'oidc' THEN 1 ELSE 0 END) as oidc_auth_count,
                            SUM(CASE WHEN auth_method = 'saml' THEN 1 ELSE 0 END) as saml_auth_count,
                            SUM(CASE WHEN account_locked_until > ? THEN 1 ELSE 0 END) as locked_accounts,
                            SUM(CASE WHEN created_at > ? THEN 1 ELSE 0 END) as recent_signups_7d,
                            SUM(CASE WHEN last_login > ? THEN 1 ELSE 0 END) as recent_logins_24h
                        FROM users
                    ''', (current_time, seven_days_ago, one_day_ago)
                    ).fetchone()
                )
                
                if not stats:
                    return {}
                
                return {
                    "total_users": stats[0],
                    "active_users": stats[1],
                    "inactive_users": stats[2],
                    "by_role": {
                        "admin": stats[3],
                        "user": stats[4]
                    },
                    "by_auth_method": {
                        "local": stats[5],
                        "oidc": stats[6],
                        "saml": stats[7]
                    },
                    "locked_accounts": stats[8],
                    "recent_signups_7d": stats[9],
                    "recent_logins_24h": stats[10]
                }
                
        except Exception as e:
            logger.error(f"Failed to get user stats: {e}")
            return {}


    async def update_user_role(self, user_id: UUID, role: str):
        """Update user role"""
        try:
            async with self.pool.get_connection() as conn:
                await sql_cb.execute(
                    async_bridge.run_in_db_thread(
                        lambda: conn.execute('''
                            UPDATE users 
                            SET role = ?
                            WHERE user_id = ?
                        ''', (role, user_id))
                    )
                )
        
        except DatabaseError:
            raise                  
        except Exception as e:
            logger.error(f"Failed to update user role: {e}")
            raise DatabaseError(f"Database error: {e}")


    async def update_user_status(self, user_id: UUID, is_active: bool):
        """Update user active status"""
        try:
            async with self.pool.get_connection() as conn:
                await sql_cb.execute(
                    async_bridge.run_in_db_thread(
                        lambda: conn.execute('''
                            UPDATE users 
                            SET is_active = ?
                            WHERE user_id = ?
                        ''', (1 if is_active else 0, user_id))
                    )
                )
        
        except DatabaseError:
            raise    
        except Exception as e:
            logger.error(f"Failed to update user status: {e}")
            raise DatabaseError(f"Database error: {e}")


    async def delete_user(self, user_id: UUID) -> bool:
        """permanent user deletion"""
        try:
            async with self.pool.get_connection() as conn:
                await sql_cb.execute(
                    async_bridge.run_in_db_thread(
                        lambda: conn.execute('''
                            DELETE FROM users
                            WHERE user_id = ?
                        ''', (user_id,)
                        )
                    )
                )
                
                logger.debug(f"User Deleted")

                return True
        
        except DatabaseError:
            raise        
        except Exception as e:
            logger.error(f"Failed to delete user: {e}")
            return False


    async def get_user_sessions(self, user_id: UUID) -> List[Dict[str, Any]]:
        """Get active sessions for user"""
        try:
            current_time = int(datetime.now(UTC).timestamp())
            
            async with self.pool.get_connection() as conn:
                rows = await async_bridge.run_in_db_thread(
                    lambda: conn.execute('''
                        SELECT session_id, created_at, expires_at, ip_address, user_agent
                        FROM sessions
                        WHERE user_id = ? AND expires_at > ?
                        ORDER BY created_at DESC
                    ''', (user_id, current_time)
                    ).fetchall()
                )
                
                return [
                    {
                        "session_id": UUID(row['session_id']),
                        "created_at": datetime.fromtimestamp(row['created_at'], UTC).isoformat(),
                        "expires_at": datetime.fromtimestamp(row['expires_at'], UTC).isoformat(),
                        "ip_address": row['ip_address'],
                        "user_agent": row['user_agent']
                    }
                    for row in rows
                ]
                
        except Exception as e:
            logger.error(f"Failed to get user sessions: {e}")
            return []


    async def revoke_user_sessions(self, user_id: UUID) -> int:
        """
        Revoke all active sessions for a user (logout from all devices)
        """
        try:
            async with self.pool.get_connection() as conn:
                cursor = await sql_cb.execute(
                    async_bridge.run_in_db_thread(
                        lambda: conn.execute('''
                            DELETE FROM sessions 
                            WHERE user_id = ?
                        ''', (user_id,)
                        )
                    )
                )
                
                revoked_count = cursor.rowcount
                
                if revoked_count:
                    logger.info(f"Revoked {revoked_count} sessions for user {user_id}")
                
                return revoked_count
        
        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to revoke user sessions: {e}")
            return 0


    async def store_audit_event(
        self,
        event_type: str,
        severity: str,
        user_id: Optional[UUID],
        email: Optional[str],
        ip_address: Optional[str],
        user_agent: Optional[str],
        timestamp: datetime,
        details: Dict[str, Any],
        success: bool,
        error_message: Optional[str]
    ):
        """Store audit event in database"""
        
        # timestamp recieved from audit logger 
        # is in UTC datetime format
        timestamp = int(timestamp.timestamp())

        try:
            async with self.pool.get_connection() as conn:
                await sql_cb.execute(
                    async_bridge.run_in_db_thread(
                        lambda:  conn.execute('''
                            INSERT INTO audit_log 
                            (event_type, severity, user_id, email, ip_address, user_agent, 
                             timestamp, details, success, error_message)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ''', (event_type, severity, user_id, email, ip_address, user_agent,
                            timestamp, json.dumps(details), success, error_message)
                            )
                        )
                    )
        
        except DatabaseError:
            raise         
        except Exception as e:
            logger.error(f"Failed to store audit event: {e}")


    async def get_audit_events(
        self,
        user_id: Optional[UUID] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        event_types: Optional[List[str]] = None,
        severity: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Query audit events with filters"""
        
        # DONT query with 'utc' in strtime if time is already in UTC 
        # as it converts the time value to UTC thinking it is locl time 
        # resulting in wrong offset (UTC -> (assume local) -> UTC), general rule:
            # Unix timestamps: Use 'unixepoch' alone
            # Local time strings: Use 'utc' alone
            # Never combine them for Unix timestamps
        # Add 'Z' - "Zulu time" to marks time stamp UTC as a metadata for parsers 
        # on how to interpret time, important for correct conversion to local time
        # JavaScript: Converts UTC -> browser local time
        try:
            # "WHERE" 1=1 a dummy item to start the WHERE clause 
            # so that "AND" in dynamic filters becomes always valid
            # because "WHERE" already exists
            # It always evaluates to true (doesn't filter anything)
            query = '''
                SELECT event_type, severity, user_id, email,
                       ip_address, user_agent,
                       -- strftime('%Y-%m-%dT%H:%M:%SZ', timestamp, 'unixepoch') as timestamp,
                       timestamp,
                       details, success, error_message
                FROM audit_log
                WHERE 1=1
            '''
            params = []
            
            if user_id:
                query += f' AND user_id = ?'
                params.append(user_id)
            
            if start_date:
                # Convert incoming datetime to Unix timestamp for comparison
                # Assume UTC as default time zone
                query += f' AND timestamp >= ?'
                params.append(int(start_date.timestamp()))
            
            if end_date:
                query += f' AND timestamp <= ?'
                params.append(int(end_date.timestamp()))
            
            if event_types:
                # The number of '?' matches the number of items 
                # in event_types (e.g., '?, ?, ?')
                placeholders = ', '.join(['?' for _ in event_types])
                query += f' AND event_type IN ({placeholders})'
                params.extend(event_types)

            if severity:
                query += f' AND severity = ?'
                params.append(severity)
            
            query += f' ORDER BY timestamp DESC LIMIT ?'
            params.append(limit)

            async with self.pool.get_connection() as conn:
                rows = await async_bridge.run_in_db_thread(
                    lambda: conn.execute(query, params).fetchall()
                )

                return [
                    {
                        "event_type": row['event_type'],
                        "severity": row['severity'],
                        "user_id": row['user_id'], # STR
                        "email": row['email'],
                        "ip_address": row['ip_address'],
                        "user_agent": row['user_agent'],
                        # Its better to convert at application level than query
                        # to maintain proper control and segregation of duties
                        "timestamp": datetime.fromtimestamp(row['timestamp'], UTC).isoformat(),
                        "details": json.loads(row['details']), # for proper display at frontend
                        "success": row['success'],
                        "error_message": row['error_message']
                    }

                    for row in rows
                ]
                
        except Exception as e:
            logger.error(f"Failed to query audit events: {e}")
            return []


    async def get_minimal_audit_events(
        self,
        user_id: UUID,
        start_date: datetime,
        limit: int = 1000
    ) -> List[Dict[str, Any]]:
        """
        Get raw activity events for aggregation
        Returns minimal data needed for chart stats
        """
        try:
            query = '''
                SELECT 
                    event_type,
                    timestamp,
                    details,
                    success
                FROM audit_log
                WHERE user_id = ?
                  AND timestamp >= ?
                ORDER BY timestamp DESC
                LIMIT ?
            '''
            
            params = [user_id, int(start_date.timestamp()), limit]
            
            async with self.pool.get_connection() as conn:
                rows = await async_bridge.run_in_db_thread(
                    lambda: conn.execute(query, params).fetchall()
                )
                
                return [
                    {
                        "event_type": row['event_type'],
                        "timestamp": datetime.fromtimestamp(row['timestamp'], UTC), # datetime for extraction
                        "details": json.loads(row['details']) if row['details'] else {},
                        "success": row['success']
                    }
                    for row in rows
                ]
                
        except Exception as e:
            logger.error(f"Failed to get user activity events: {e}")
            return []


    async def get_recent_audit_activities(
        self,
        user_id: UUID,
        limit: int = 20
    ) -> List[Dict[str, Any]]:
        """Get recent activities separately (lighter query)"""
        
        try:
            query = '''
                SELECT event_type, timestamp, details, success
                FROM audit_log
                WHERE user_id = ?
                ORDER BY timestamp DESC
                LIMIT ?
            '''
            
            params = [user_id, limit]
            
            async with self.pool.get_connection() as conn:
                rows = await async_bridge.run_in_db_thread(
                    lambda: conn.execute(query, params).fetchall()
                )
                
                return [
                    {
                        "type": row['event_type'],
                        "timestamp": datetime.fromtimestamp(row['timestamp'], UTC).isoformat(),
                        "details": json.loads(row['details']),
                        "success": row['success']
                    }
                    for row in rows
                ]
                
        except Exception as e:
            logger.error(f"Failed to get recent activities: {e}")
            return []


    async def get_failed_logins(
        self,
        start_date: datetime,
        threshold: int = 3
    ) -> List[Dict[str, Any]]:
        """Get users/IPs with multiple failed login attempts"""

        # convert to Unix for comparison
        start_date = int(start_date.timestamp())

        try:
            async with self.pool.get_connection() as conn:
                rows =  await async_bridge.run_in_db_thread(
                    lambda: conn.execute('''
                        SELECT 
                            email,
                            ip_address,
                            COUNT(*) as attempt_count,
                            MAX(timestamp) as last_attempt
                        FROM audit_log
                        WHERE event_type = 'login_failed'
                          AND timestamp >= ?
                        GROUP BY email, ip_address
                        HAVING COUNT(*) >= ?
                        ORDER BY attempt_count DESC
                    ''', (start_date, threshold)
                    ).fetchall()
                )
                
                return [
                    {
                        "email": row['email'],
                        "ip_address": row['ip_address'],
                        "attempt_count": row['attempt_count'],
                        "last_attempt": datetime.fromtimestamp(row['last_attempt'], UTC).isoformat()
                    }
                    for row in rows
                ]
                
        except Exception as e:
            logger.error(f"Failed to query failed logins: {e}")
            return []


    async def get_audit_summary(
        self,
        start_date: datetime
    ) -> Dict[str, Any]:
        """Get summary of audit events"""

        # convert to Unix for comparison
        start_date = int(start_date.timestamp())

        try:
            async with self.pool.get_connection() as conn:
                summary = await async_bridge.run_in_db_thread(
                    lambda: conn.execute('''
                        SELECT 
                            COUNT(*) FILTER (WHERE event_type = 'login_success') as successful_logins,
                            COUNT(*) FILTER (WHERE event_type = 'login_failed') as failed_logins,
                            COUNT(*) FILTER (WHERE event_type = 'password_changed') as password_changes,
                            COUNT(*) FILTER (WHERE severity = 'critical') as critical_events,
                            COUNT(*) FILTER (WHERE severity = 'warning') as warning_events,
                            COUNT(DISTINCT user_id) as unique_users,
                            COUNT(DISTINCT ip_address) as unique_ips
                        FROM audit_log
                        WHERE timestamp >= ?
                    ''', (start_date,)
                    ).fetchone()
                )
                
                return dict(summary) if summary else {}
                
        except Exception as e:
            logger.error(f"Failed to get audit summary: {e}")
            return {}


    async def store_password_reset_token(
        self,
        token_hash: str,
        user_id: UUID,
        expires_at: datetime,
        ip_address: Optional[str] = None
    ):
        """Store password reset token"""

        # convert to Unix
        expires_at = int(expires_at.timestamp())

        try:
            async with self.pool.get_connection() as conn:
                await sql_cb.execute(
                    async_bridge.run_in_db_thread(
                        lambda: conn.execute('''
                            INSERT INTO password_reset_tokens 
                            (token_hash, user_id, expires_at, ip_address)
                            VALUES (?, ?, ?, ?)
                        ''', (token_hash, user_id, expires_at, ip_address)
                        )
                    )
                )
        
        except DatabaseError:
            raise         
        except Exception as e:
            logger.error(f"Failed to store password reset token: {e}")
            raise DatabaseError(f"Database error: {e}")


    async def get_password_reset_token(
        self,
        token_hash: str
    ) -> Optional[Dict[str, Any]]:
        """Get password reset token by hash"""
        try:
            async with self.pool.get_connection() as conn:
                row = await async_bridge.run_in_db_thread(
                    lambda: conn.execute('''
                        SELECT token_hash, user_id, created_at, expires_at, used, used_at, ip_address
                        FROM password_reset_tokens
                        WHERE token_hash = ?
                    ''', (token_hash,)
                    ).fetchone()
                )
                
                if row:
                    return {
                        'token_hash': row['token_hash'],
                        'user_id': UUID(row['user_id']),
                        "created_at": datetime.fromtimestamp(row['created_at'], UTC), # datetime object for dynamic usage
                        "expires_at": datetime.fromtimestamp(row['expires_at'], UTC),
                        'used': row['used'],
                        'used_at': datetime.fromtimestamp(row['used_at'], UTC).isoformat() if row['used_at'] else None,
                        'ip_address': row['ip_address']
                    }

                return None
                
        except Exception as e:
            logger.error(f"Failed to get password reset token: {e}")
            return None


    async def mark_reset_token_used(self, token_hash: str):
        """Mark password reset token as used"""
        try:
            current_time = int(datetime.now(UTC).timestamp())

            async with self.pool.get_connection() as conn:
                await sql_cb.execute(
                    async_bridge.run_in_db_thread(
                        lambda: conn.execute('''
                            UPDATE password_reset_tokens
                            SET used = 1, used_at = ?
                            WHERE token_hash = ?
                        ''', (current_time, token_hash)
                        )
                    )
                )

        except DatabaseError:
            raise        
        except Exception as e:
            logger.error(f"Failed to mark token as used: {e}")
            raise DatabaseError(f"Database error: {e}")


    async def count_password_reset_requests(
        self,
        user_id: UUID,
        since: datetime
    ) -> int:
        """Count password reset requests for user since given time"""

        # convert to Unix for comparison
        since = int(since.timestamp())

        try:
            async with self.pool.get_connection() as conn:
                count = await async_bridge.run_in_db_thread(
                    lambda: conn.execute('''
                        SELECT COUNT(*)
                        FROM password_reset_tokens
                        WHERE user_id = ? AND created_at >= ?
                    ''', (user_id, since)
                    ).fetchone()[0]
                )
                
                return count or 0
                
        except Exception as e:
            logger.error(f"Failed to count reset requests: {e}")
            return 0


    async def delete_password_reset_token(self, token_hash: str) -> bool: # Not Used
        """
        Delete password reset token
        
        Args:
            token: Reset token
        
        Returns:
            bool: Success status
        """
        try:
            async with self.pool.get_connection() as conn:
                await sql_cb.execute(
                    async_bridge.run_in_db_thread(
                        lambda: conn.execute('''
                            DELETE FROM password_reset_tokens
                            WHERE token_hash = ?
                        ''', (token_hash,)
                        )
                    )
                )
                
                logger.debug(f"Deleted reset tokens")

                return True
        
        except DatabaseError:
            raise        
        except Exception as e:
            logger.error(f"Failed to delete reset tokens: {e}")
            return False


    async def delete_expired_reset_tokens(self) -> int:
        """
        Delete expired password reset tokens
        similat to cleanup_expired_password_resets but
        uses current time
        """
        try:
            current_time = int(datetime.now(UTC).timestamp())

            async with self.pool.get_connection() as conn:
                cursor = await sql_cb.execute(
                    async_bridge.run_in_db_thread(
                        lambda: conn.execute('''
                            DELETE FROM password_reset_tokens
                            WHERE expires_at < ?
                        ''', (current_time,)
                        )
                    )
                )
                
                deleted = cursor.rowcount
                logger.debug(f"Deleted {deleted} expired reset tokens")

                return deleted
        
        except DatabaseError:
            raise        
        except Exception as e:
            logger.error(f"Failed to delete expired tokens: {e}")
            return 0


    async def revoke_password_reset_tokens(self, user_id: UUID):
        """Revoke all password reset tokens for user"""
        try:
            current_time = int(datetime.now(UTC).timestamp())

            async with self.pool.get_connection() as conn:
                await sql_cb.execute(
                    async_bridge.run_in_db_thread(
                        lambda: conn.execute('''
                            UPDATE password_reset_tokens
                            SET used = 1, used_at = ?
                            WHERE user_id = ? AND used = 0
                        ''', (current_time, user_id)
                        )
                    )
                )
                
        except DatabaseError:
            raise      
        except Exception as e:
            logger.error(f"Failed to revoke reset tokens: {e}")
            raise DatabaseError(f"Database error: {e}")


    async def create_refresh_token(
        self, 
        user_id: UUID,
        expires_days: int = 30,
        session_id: Optional[UUID] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
        ) -> str:
        """
        Create refresh token with 30-day expiry
        
        Args:
            user_id: User ID
            session_id: Optional linked session
            ip_address: Request IP
            user_agent: Request user agent
            
        Returns:
            Refresh token (plain text, only returned once)
        """
        try:
            # Generate secure token
            token, token_hash = self.hasher.generate_token(32)
            token_id = self.hasher.generate_id()

            # 30 day expiry for refresh tokens
            expires_at = int((datetime.now(UTC) + timedelta(days=expires_days)).timestamp())
            
            async with self.pool.get_connection() as conn:
                await sql_cb.execute(
                    async_bridge.run_in_db_thread(
                        lambda: conn.execute('''
                            INSERT INTO refresh_tokens 
                            (token_id, token_hash, user_id, session_id, expires_at, ip_address, user_agent)
                            VALUES (?, ?, ?, ?, ?, ?, ?)
                        ''', (token_id, token_hash, user_id, session_id, expires_at, ip_address, user_agent)
                        )
                    )
                )
            
            logger.debug(f"Refresh token created for user {user_id}")

            return token
            
        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to create refresh token: {e}")
            raise DatabaseError(f"Database error: {e}")


    async def verify_refresh_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Validate refresh token and return session data
        
        Args:
            token: Refresh token to verify
            
        Returns:
            Dict with user_id and session info if valid, None otherwise
        """
        try:
            token_hash = self.hasher.hash(token)
            current_time = int(datetime.now(UTC).timestamp())
            
            async with self.pool.get_connection() as conn:
                row = await async_bridge.run_in_db_thread(
                    lambda: conn.execute('''
                        SELECT rt.user_id, rt.session_id, rt.expires_at, rt.revoked,
                               u.email, u.role, u.is_active
                        FROM refresh_tokens rt
                        JOIN users u ON rt.user_id = u.user_id
                        WHERE rt.token_hash = ? 
                        AND rt.expires_at > ?
                        AND rt.revoked = 0
                        AND u.is_active = 1
                    ''', (token_hash, current_time)
                    ).fetchone()
                )
            
            if not row:
                logger.info("Refresh token not found or expired")

                return None
            
            return {
                'user_id': UUID(row['user_id']), # row[0]
                'session_id': UUID(row['session_id']), # row[1]
                'expires_at': datetime.fromtimestamp(row['expires_at'], UTC).isoformat(), # row[2]
                'email': row['email'], # row[4]
                'role': row['role'] # row[5]
            }
            
        except Exception as e:
            logger.error(f"Failed to verify refresh token: {e}")
            raise DatabaseError(f"Database error: {e}")


    async def revoke_refresh_token(self, token: str) -> bool:
        """Revoke a refresh token"""
        try:
            token_hash = self.hasher.hash(token)
            revoked_at = int(datetime.now(UTC).timestamp())
   
            async with self.pool.get_connection() as conn:
                await sql_cb.execute(
                    async_bridge.run_in_db_thread(
                        lambda: conn.execute('''
                            UPDATE refresh_tokens 
                            SET revoked = 1, revoked_at = ?
                            WHERE token_hash = ?
                        ''', (revoked_at, token_hash)
                        )
                    )
                )

            logger.debug("Refresh token revoked")

            return True
        
        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to revoke refresh token: {e}")
            return False


    async def rotate_refresh_token(
        self,
        old_token: str,
        user_id: UUID,
        expires_days: int = 30,
        session_id: Optional[UUID] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Optional[str]:
        """
        Atomically revoke old refresh token and create new one.
        
        This implements secure token rotation:
        1. Verify old token is valid
        2. Revoke old token
        3. Create new token
        
        All in a single transaction to prevent race conditions.
        
        Args:
            old_token: Current refresh token to rotate
            user_id: User ID (for verification)
            session_id: Optional session to link to
            ip_address: Request IP
            user_agent: Request user agent
            
        Returns:
            New refresh token if successful, None if old token invalid
        """
        try:
            old_token_hash = self.hasher.hash(old_token)
            new_token, new_token_hash = self.hasher.generate_token(32)
            token_id = self.hasher.generate_id()
            
            timestamp = datetime.now(UTC)
            current_time = int(timestamp.timestamp())
            expires_at = int((timestamp + timedelta(days=expires_days)).timestamp())
            
            async with self.pool.get_connection() as conn:
                # SQLite doesn't have great transaction support, so we do our best
                await sql_cb.execute(
                    async_bridge.run_in_db_thread(
                        lambda: self._rotate_token_transaction(
                            conn, old_token_hash, user_id, current_time,
                            token_id, new_token_hash, session_id, expires_at,
                            ip_address, user_agent
                        )
                    )
                )
            
            logger.debug(f"Refresh token rotated for user {user_id}")

            return new_token
            
        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to rotate refresh token: {e}")
            return None


    def _rotate_token_transaction(
        self,
        conn: sqlite3.Connection,
        old_token_hash: str,
        user_id: UUID,
        current_time: int,
        token_id: UUID,
        new_token_hash: str,
        session_id: Optional[UUID],
        expires_at: int,
        ip_address: Optional[str],
        user_agent: Optional[str]
    ) -> bool:
        """Transaction logic for token rotation"""
        
        # 1. Verify and revoke old token
        result = conn.execute('''
            UPDATE refresh_tokens 
            SET revoked = 1, revoked_at = ?
            WHERE token_hash = ? 
              AND user_id = ?
              AND expires_at > ?
              AND revoked = 0
        ''', (current_time, old_token_hash, user_id, current_time))
        
        if result.rowcount == 0:
            # Old token invalid/expired/already used
            logger.warning(f"Failed to revoke old refresh token for user {user_id}")
            raise ValueError("Invalid refresh token")
        
        # 2. Create new token
        conn.execute('''
            INSERT INTO refresh_tokens 
            (token_id, token_hash, user_id, session_id, expires_at, ip_address, user_agent)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (token_id, new_token_hash, user_id, session_id, expires_at, ip_address, user_agent))
        
        return True


    async def revoke_user_refresh_tokens(self, user_id: UUID) -> int:
        """Revoke all refresh tokens for a user (used on logout)"""
        try:
            revoked_at = int(datetime.now(UTC).timestamp())
            
            async with self.pool.get_connection() as conn:
                cursor = await sql_cb.execute(
                    async_bridge.run_in_db_thread(
                        lambda: conn.execute('''
                            UPDATE refresh_tokens 
                            SET revoked = 1, revoked_at = ?
                            WHERE user_id = ? AND revoked = 0
                        ''', (revoked_at, user_id)
                        )
                    )
                )
                
                revoked_count = cursor.rowcount
            
            logger.debug(f"Revoked {revoked_count} refresh tokens for user {user_id}")

            return revoked_count
        
        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to revoke user refresh tokens: {e}")
            return 0


    async def cleanup_expired_refresh_tokens(self, days: int = 30) -> int:
        """Clean up expired refresh tokens"""
        try:
            # 30-day retention (balance security vs performance)
            cutoff_time = int((datetime.now(UTC) - timedelta(days=days)).timestamp())
            
            async with self.pool.get_connection() as conn:
                cursor = await sql_cb.execute(
                    async_bridge.run_in_db_thread(
                        lambda: conn.execute('''
                            DELETE FROM refresh_tokens 
                            WHERE expires_at < ? OR (revoked = 1 AND revoked_at < ?)
                        ''', (cutoff_time, cutoff_time)
                        )
                    )
                )
                
                deleted_count = cursor.rowcount
            
            logger.debug(f"Cleaned up {deleted_count} expired refresh tokens")

            return deleted_count
          
        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to cleanup refresh tokens: {e}")
            return 0


    async def get_session_info(self, user_id: UUID) -> Optional[Dict[str, Any]]:
        """
        Get session information for a user
        
        Returns:
            Dict with session details if exists, None otherwise
        """
        try:
            async with self.pool.get_connection() as conn:
                row = await async_bridge.run_in_db_thread(    
                    lambda: conn.execute('''
                        SELECT session_id, expires_at, ip_address, user_agent, created_at
                        FROM sessions
                        WHERE user_id = ?
                        ORDER BY created_at DESC
                        LIMIT 1
                    ''', (user_id,)
                    ).fetchone() # TODO: what about multiple sessions
                )
                
            if row:
                return {
                    'session_id': UUID(row['session_id']),
                    'expires_at': datetime.fromtimestamp(row['expires_at'], UTC), # datetime object
                    'ip_address': row['ip_address'],
                    'user_agent': row['user_agent'],
                    'created_at': datetime.fromtimestamp(row['created_at'], UTC)
                }
            
            return None

        except Exception as e:
            logger.error(f"Failed to get session info: {e}")
            return None


    async def store_mfa_secret(
        self, 
        user_id: UUID, 
        secret: str, 
        backup_codes: List[str], 
        method: str = "totp"
        ) -> bool:
        """
        Store MFA secret for user
        
        Args:
            user_id: User ID
            secret: TOTP secret (encrypted in production!)
            backup_codes: List of backup codes
            method: MFA method (totp, sms, email)
            
        Returns:
            True if successful
        """
        try:
            # ENCRYPT the TOTP secret
            encrypted_secret = mfa_crypto.encrypt_secret(secret)

            # Hash backup codes, treat like passwords - one-way hash 
            # for one-time use, never need to decrypt
            hashed_backup_codes = [hash_password(code) for code in backup_codes]
            backup_codes_json = json.dumps(hashed_backup_codes) # TODO: Same location as secret
        
            created_at = int(datetime.now(UTC).timestamp())
            
            async with self.pool.get_connection() as conn:
                # Upsert pattern for SQLite
                await sql_cb.execute(
                    async_bridge.run_in_db_thread(
                        lambda: conn.execute('''
                            INSERT INTO mfa_secrets (user_id, method, secret, backup_codes, created_at)
                            VALUES (?, ?, ?, ?, ?)
                            ON CONFLICT(user_id) DO UPDATE SET
                                method = excluded.method,
                                secret = excluded.secret,
                                backup_codes = excluded.backup_codes,
                                created_at = excluded.created_at,
                                verified_at = NULL
                        ''', (user_id, method, encrypted_secret, backup_codes_json, created_at)
                        )
                    )
                )
                
            logger.info(f"MFA secret stored for user {user_id}")

            return True
        
        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to store MFA secret: {e}")
            return False


    async def get_mfa_data(self, user_id: UUID) -> Optional[Dict[str, Any]]:
        """
        Get MFA data for verification
        
        Returns:
            Dict with secret and backup codes if exists
        """
        try:
            async with self.pool.get_connection() as conn:
                row = await async_bridge.run_in_db_thread(
                    lambda: conn.execute('''
                        SELECT method, secret, backup_codes, verified_at, last_used
                        FROM mfa_secrets
                        WHERE user_id = ?
                    ''', (user_id,)
                    ).fetchone()
                )
            
            if not row:
                return None
            
            # Decrypt secret
            decrypted_secret = mfa_crypto.decrypt_secret(row[1])

            backup_codes = json.loads(row[2]) if row[2] else []
            
            return {
                'method': row[0],
                'secret': decrypted_secret,  # Decrypted!
                'backup_codes': backup_codes,
                'verified_at': datetime.fromtimestamp(row[3], UTC).isoformat() if row[3] else None,
                'last_used': datetime.fromtimestamp(row[4], UTC).isoformat() if row[4] else None # backup codes
            }
            
        except Exception as e:
            logger.error(f"Failed to get MFA secret: {e}")
            return None


    async def enable_mfa(self, user_id: UUID) -> bool:
        """Activate MFA after successful verification"""
        try:
            async with self.pool.get_connection() as conn:
                await sql_cb.execute(
                    async_bridge.run_in_db_thread(
                        lambda: conn.execute('''
                            UPDATE users 
                            SET mfa_enabled = 1
                            WHERE user_id = ?
                        ''', (user_id,)
                        )
                    )
                )
                
            logger.info(f"MFA enabled for user {user_id}")
            
            return True
        
        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to enable MFA: {e}")
            return False


    async def check_mfa(self, user_id: UUID) -> bool:
        """Fast check if mfa enabled or not"""
        try:
            async with self.pool.get_connection() as conn:
                row = await async_bridge.run_in_db_thread(
                    lambda: conn.execute('''
                        SELECT 1
                        FROM users
                        WHERE user_id = ? AND mfa_enabled = 1
                        LIMIT 1
                    ''', (user_id,)
                    ).fetchone()
                )
            
            if not row:
                logger.info(f"MFA not enabled for user {user_id}")
                return False
                
            return True
        
        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to check MFA: {e}")
            return False


    async def disable_mfa(self, user_id: UUID) -> bool:
        """Delete MFA configuration"""
        try:
            async with self.pool.get_connection() as conn:
                # Single query: delete mfa data + update status
                result = await sql_cb.execute(
                    async_bridge.run_in_db_thread(
                        lambda: self._disable_mfa_op(conn, user_id)
                    )
                )
                
            logger.info(f"MFA disabled for user {user_id}")
            
            return result
       
        except DatabaseError:
            raise   
        except Exception as e:
            logger.error(f"Failed to disabled MFA: {e}")
            return False

    def _disable_mfa_op(self, conn: sqlite3.Connection, user_id: UUID) -> bool:
        """Transaction logic for disabling MFA"""
        
        # 1. Delete mfa data
        conn.execute('''
            DELETE FROM mfa_secrets WHERE user_id = ?
            ''', (user_id,)
        )
        
        # 2. Update status
        conn.execute('''
            UPDATE users 
            SET mfa_enabled = 0
            WHERE user_id = ?
        ''', (user_id,)
        )
        
        return True


    async def remove_backup_code(self, user_id: UUID, used_code: str) -> bool:
        """Remove backup code"""
        try:
            async with self.pool.get_connection() as conn:
                # Single query: fetch + check + rebuild in one transaction
                result = await sql_cb.execute(
                    async_bridge.run_in_db_thread(
                        lambda: self._remove_backup_code_op(conn, user_id, used_code)
                    )
                )
                
                return result
            
        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to remove backup code: {e}")
            return False


    def _remove_backup_code_op(self, conn: sqlite3.Connection, user_id: UUID, used_code: str) -> bool:
        """Transaction logic for backup code removal"""

        # 1. Fetch ONLY backup codes (not entire MFA data)
        row = conn.execute('''
            SELECT backup_codes FROM mfa_secrets WHERE user_id = ?
        ''', (user_id,)
        ).fetchone()
        
        if not row:
            return False
        
        # 2. Parse and check
        backup_codes = json.loads(row[0]) if row[0] else []
        
        if used_code not in backup_codes:
            return False
        
        # 3. Remove and update
        backup_codes.remove(used_code)
        backup_codes_json = json.dumps(backup_codes)
        last_used = int(datetime.now(UTC).timestamp())
        
        conn.execute('''
            UPDATE mfa_secrets 
            SET backup_codes = ?, last_used = ?
            WHERE user_id = ?
        ''', (backup_codes_json, last_used, user_id))
        
        return True


    async def update_mfa_verification(self, user_id: UUID) -> bool:
        """Update MFA last used timestamp"""
        try:
            verified_at = int(datetime.now(UTC).timestamp())
            
            async with self.pool.get_connection() as conn:
                await sql_cb.execute(
                    async_bridge.run_in_db_thread(
                        lambda: conn.execute('''
                            UPDATE mfa_secrets 
                            SET verified_at = ?
                            WHERE user_id = ?
                        ''', (verified_at, user_id)
                        )
                    )
                )
            
            return True
            
        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to update MFA last used: {e}")
            return False


    async def cleanup_expired_sessions(self) -> int:
        """Clean up expired sessions"""
        try:
            current_time = int(datetime.now(UTC).timestamp())
            
            async with self.pool.get_connection() as conn:
                cursor = await sql_cb.execute(
                    async_bridge.run_in_db_thread(
                        lambda:  conn.execute('''
                            DELETE FROM sessions 
                            WHERE expires_at < ?
                        ''', (current_time,)
                        )
                    )
                )
                
                deleted_count = cursor.rowcount
            
            logger.debug(f"Cleaned up {deleted_count} expired sessions")
            
            return deleted_count
           
        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to cleanup sessions: {e}")
            return 0


    async def cleanup_expired_password_resets(self, days: int = 7) -> int:
        """Clean up old password reset tokens"""
        try:
            # 7-day retention (security sensitive)
            cutoff_time = int((datetime.now(UTC) - timedelta(days=days)).timestamp())
            
            async with self.pool.get_connection() as conn:
                cursor = await sql_cb.execute(
                    async_bridge.run_in_db_thread(
                        lambda:  conn.execute('''
                            DELETE FROM password_reset_tokens 
                            WHERE expires_at < ? OR (used = 1 AND used_at < ?)
                        ''', (cutoff_time, cutoff_time)
                        )
                    )
                )
        
                deleted_count = cursor.rowcount
            
            logger.debug(f"Cleaned up {deleted_count} password reset tokens")
            
            return deleted_count
        
        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to cleanup password resets: {e}")
            return 0
    

    async def cleanup_expired(self) -> int:
        """Clean up expired sessions and API keys"""
        try:
            current_time = int(datetime.now(UTC).timestamp())
            
            async with self.pool.get_connection() as conn:
                total = await sql_cb.execute( 
                    async_bridge.run_in_db_thread(
                        lambda: self._cleanup_expired_op(conn, current_time)
                    )
                )

                if total > 0:
                    logger.info(f"Cleaned up {total} expired auth records")
                
                return total

        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to cleanup: {e}")
            # return 0
            raise DatabaseError(f"Unexpected database cleanup error: {e}")
    

    def _cleanup_expired_op(self, conn: sqlite3.Connection, current_time: int) -> int:
        """Sync cleanup operation"""

        # Delete expired sessions
        conn.execute('DELETE FROM sessions WHERE expires_at < ?', (current_time,))
        sessions_deleted = conn.total_changes
        
        # Deactivate expired keys
        conn.execute('UPDATE api_keys SET is_active = 0 WHERE expires_at < ? AND is_active = 1', (current_time,))
        keys_updated = conn.total_changes - sessions_deleted # total_changes is cumulative so need to remove prior changes
        
        return sessions_deleted + keys_updated
            

    async def health_check(self) -> Dict[str, Any]:
        """Health check"""
        try:
            async with self.pool.get_connection() as conn:
                stats = await async_bridge.run_in_db_thread(
                    lambda: self._get_stats_op(conn)
                    )
                
                return {
                    'status': 'healthy',
                    'database_type': 'SQLite',
                    **stats
                }
            
        except Exception as e:
            logger.error(f"Auth health check failed: {e}")
            return {'status': 'unhealthy', 'error': str(e)}
            

    def _get_stats_op(self, conn: sqlite3.Connection) -> Dict[str, Any]:
        """Get stats operation"""
        current_time = int(datetime.now(UTC).timestamp())
        
        user_count = conn.execute('SELECT COUNT(*) FROM users WHERE is_active = 1').fetchone()[0]
        active_keys = conn.execute('SELECT COUNT(*) FROM api_keys WHERE is_active = 1 AND expires_at > ?', (current_time,)).fetchone()[0]
        active_sessions = conn.execute('SELECT COUNT(*) FROM sessions WHERE expires_at > ?', (current_time,)).fetchone()[0]
        
        return {
            'active_users': user_count,
            'active_api_keys': active_keys,
            'active_sessions': active_sessions
        }
    

    async def close(self):
        """Cleanup"""
        try:
            if self.pool:
                await self.pool.close()
            self._initialized = False
            # logger.debug("SQLite Auth manager closed")
        except Exception as e:
            logger.error(f"Error closing Auth store: {e}")
            raise DatabaseError(f"Unexpected database closing error: {e}")