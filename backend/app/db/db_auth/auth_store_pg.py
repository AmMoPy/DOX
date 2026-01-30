import asyncpg
import asyncio
import json
import logging
from uuid import UUID
from typing import Optional, Dict, List, Any
from datetime import datetime, timedelta, UTC
from app.auth.hash_service import TokenHasher
from app.auth.pwd_mngr.pwd_utils import hash_password
from app.auth.mfa_crypto import mfa_encryption as mfa_crypto
from app.db.utils_db.pg_pool_mngr import pg_pool
from app.db.utils_db.circuit_breaker import pg_cb, DatabaseError

logger = logging.getLogger(__name__)


class PostgreSQLAuthStore:
    """Authentication store for PostgreSQL"""
    
    def __init__(self, hasher: TokenHasher):
        self.hasher = hasher
        self._lock = asyncio.Lock()
        self._initialized = False
        self.COMPONENT_NAME = "auth_store"
        self.SCHEMA_VERSION = "1.0"
    

    async def initialize(self):
        """Initialize auth tables"""
        async with self._lock:
            if self._initialized:
                logger.debug("PostgreSQL Auth store already initialized")
                return
            
            try:
                logger.debug("Initializing PostgreSQL Auth Store...")
                
                # Register with shared pool (creates pool if needed)
                await pg_pool.initialize(self.COMPONENT_NAME, self.SCHEMA_VERSION)
                
                # Setup own schema
                async with pg_pool.get_connection() as conn:
                    await pg_cb.execute(
                        lambda: self._setup_schema(conn)
                    )

                self._initialized = True
                logger.debug("PostgreSQL Auth Store initialized")
                
            except Exception as e:
                logger.error(f"Failed to initialize auth store: {e}")
                raise DatabaseError(f"Auth database error: {e}")
    

    async def _setup_schema(self, conn: asyncpg.Connection):
        """Setup authentication tables"""
        
        # Users table
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                user_id UUID PRIMARY KEY DEFAULT gen_random_uuid(), -- default is just for fallback, uuids are generated and passed before insertion
                email TEXT UNIQUE NOT NULL, -- implicit index exists because of UNIQUE constraint
                password_hash TEXT,  -- For local auth
                role TEXT NOT NULL CHECK (role IN ('admin', 'user')),
                auth_method TEXT DEFAULT 'local' CHECK (auth_method IN ('local', 'oidc', 'saml')),
                mfa_enabled BOOLEAN DEFAULT FALSE,
                sso_provider TEXT,
                sso_id TEXT,
                sso_attributes JSONB DEFAULT '{}',  -- Store SSO claims
                created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE,
                account_locked_until TIMESTAMPTZ,  -- For failed login protection
                failed_login_attempts INTEGER DEFAULT 0,
                metadata JSONB DEFAULT '{}'
            )
        ''')
        
        # API Keys table
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS api_keys (
                key_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                key_hash TEXT UNIQUE NOT NULL,
                user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
                name TEXT NOT NULL,
                scopes TEXT[] DEFAULT ARRAY['search', 'ask'],
                created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMPTZ NOT NULL,
                last_used TIMESTAMPTZ,
                is_active BOOLEAN DEFAULT TRUE
            )
        ''')
        
        # Sessions table (for SSO tokens)
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                session_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
                token_hash TEXT UNIQUE NOT NULL,
                created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMPTZ NOT NULL,
                ip_address TEXT,
                user_agent TEXT,
                mfa_verified BOOLEAN DEFAULT TRUE
            )
        ''')

        # Refresh tokens table
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS refresh_tokens (
                token_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                token_hash VARCHAR(64) UNIQUE NOT NULL,
                user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
                session_id UUID REFERENCES sessions(session_id) ON DELETE CASCADE,
                created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMPTZ NOT NULL,
                revoked BOOLEAN DEFAULT FALSE,
                revoked_at TIMESTAMPTZ,
                ip_address INET,
                user_agent TEXT
            )
          ''')

        # MFA secrets table
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS mfa_secrets (
                user_id UUID PRIMARY KEY REFERENCES users(user_id) ON DELETE CASCADE,
                method VARCHAR(20) NOT NULL DEFAULT 'totp' CHECK (method IN ('totp', 'sms', 'email')),
                secret TEXT NOT NULL,  -- Encrypt this in production!
                backup_codes JSONB NOT NULL DEFAULT '[]'::jsonb, -- Explicit cast (for clarity), python returns as empty list
                created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                verified_at TIMESTAMPTZ,
                last_used TIMESTAMPTZ
            )
        ''')

        # password reset tokens table
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS password_reset_tokens (
                id SERIAL PRIMARY KEY,
                token_hash TEXT UNIQUE NOT NULL,
                user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
                created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMPTZ NOT NULL,
                used BOOLEAN DEFAULT FALSE,
                used_at TIMESTAMPTZ,
                ip_address TEXT,

                forced_by_admin BOOLEAN DEFAULT FALSE,

                CONSTRAINT valid_expiry CHECK (expires_at > created_at)
            )
        ''')

        # Audit log table
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS audit_log (
                id BIGSERIAL PRIMARY KEY, -- Use BIGSERIAL for long-term logs
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                user_id UUID,
                email TEXT,
                ip_address TEXT,
                user_agent TEXT,
                timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                details JSONB DEFAULT '{}', -- String literal, implicit cast (PostgreSQL infers), python returns as empty dict, null allowed
                success BOOLEAN DEFAULT TRUE,
                error_message TEXT,
                FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE SET NULL -- DON'T CASCADE, logs are needed for investigations!
            )
        ''')    
        
        # Indexes - CONCURRENTLY doesn't block reads/writes
        indexes = [
            # 'CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_email ON users(email)',
            'CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_sso ON users(sso_provider, sso_id)',

            'CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_active ON users(is_active) WHERE is_active', # partial index, good for active user queries
            # 'CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_mfa_enabled ON users(mfa_enabled) WHERE mfa_enabled', # Only useful if <10% users have MFA
            'CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_mfa_enabled ON users(user_id) WHERE mfa_enabled AND is_active',

            'CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_api_keys_user ON api_keys(user_id)',
            'CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_api_keys_active ON api_keys(is_active, expires_at)',
            
            'CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_sessions_user ON sessions(user_id)',
            'CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_sessions_expires ON sessions(expires_at)',

            'CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_user ON audit_log(user_id)',
            'CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp DESC)',
            'CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_event_type ON audit_log(event_type)',
            'CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_severity ON audit_log(severity)',
            'CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_email ON audit_log(email)',
            'CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_ip ON audit_log(ip_address)',

            'CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_reset_token_hash ON password_reset_tokens(token_hash)',
            'CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_reset_user ON password_reset_tokens(user_id)',
            'CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_reset_expires ON password_reset_tokens(expires_at)',
            'CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_reset_used ON password_reset_tokens(used)',

            'CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens(user_id)',
            'CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_refresh_tokens_hash ON refresh_tokens(token_hash)',
            'CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_refresh_tokens_expires ON refresh_tokens(expires_at)',
            'CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_refresh_tokens_revoked ON refresh_tokens(revoked) WHERE NOT revoked',
            
            'CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_mfa_secrets_user ON mfa_secrets(user_id)',
        ]
        
        for index in indexes:
            try:
                await conn.execute(index)
                logger.debug(f"Index creation success")
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
        user_id: Optional[UUID] = None
        ) -> Dict[str, Any]:
        """Create new user with password support"""
        try:
            if user_id:
                from app.val.file_val import text_validator
                user_id = text_validator.validate_user_id(user_id)
            else:
                user_id = self.hasher.generate_id()
            
            async with pg_pool.get_connection() as conn:
                await pg_cb.execute(
                    lambda: conn.execute('''
                        INSERT INTO users 
                        (user_id, email, role, password_hash, auth_method, mfa_enabled, sso_id)
                        VALUES ($1, $2, $3, $4, $5, $6, $7)
                    ''', user_id, email, role, password_hash, auth_method, mfa_enabled, sso_id
                    )
                )
            
            logger.info(f"Created user: {email} ({role}, {auth_method})")

            return {
                'user_id': user_id,
                'email': email,
                'role': role,
                'auth_method': auth_method
            }
            
        except DatabaseError:
            raise
        except asyncpg.UniqueViolationError:
            raise ValueError(f"User with email {email} already exists")
        except Exception as e:
            logger.error(f"Failed to create user: {e}")
            raise DatabaseError(f"Database error: {e}")
    

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

            async with pg_pool.get_connection() as conn:
                row = await conn.fetchrow(f'''
                    SELECT {', '.join(fields)}
                    FROM users 
                    -- WHERE email = $1 AND is_active = TRUE
                    WHERE email = $1
                ''', email
                )
                
                if row:
                    return {
                        "user_id": row['user_id'],
                        "email": row['email'],
                        "role": row['role'],
                        "sso_provider": row['sso_provider'],
                        "sso_id": row['sso_id'],
                        "created_at": row['created_at'].isoformat(),
                        "last_login": row['last_login'].isoformat(),
                        "account_locked_until": row['account_locked_until'] if row['account_locked_until'] else None, # datetime object
                        "is_active": row['is_active'],
                        "auth_method": row['auth_method'],
                        "mfa_enabled": row['mfa_enabled'],
                        "password_hash": row['password_hash'] if include_pass else None,
                    }
                    
                return None
                
        except Exception as e:
            logger.error(f"Failed to get user: {e}")
            raise DatabaseError(f"Database error: {e}")
    

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

            async with pg_pool.get_connection() as conn:
                row = await conn.fetchrow(f'''   
                    SELECT {', '.join(fields)}
                    FROM users 
                    -- WHERE user_id = $1 AND is_active = TRUE
                    WHERE user_id = $1
                ''', user_id
                )

                if row:
                    # return dict(row)
                    return {
                        "user_id": row['user_id'],
                        "email": row['email'],
                        "role": row['role'],
                        "sso_provider": row['sso_provider'],
                        "sso_id": row['sso_id'],
                        "created_at": row['created_at'].isoformat(),
                        "last_login": row['last_login'].isoformat(),
                        "account_locked_until": row['account_locked_until'] if row['account_locked_until'] else None,
                        "is_active": row['is_active'],
                        "auth_method": row['auth_method'],
                        "mfa_enabled": row['mfa_enabled'],
                        "password_hash": row['password_hash'] if include_pass else None,
                    }

                return None
                
        except Exception as e:
            logger.error(f"Failed to get user: {e}")
            raise DatabaseError(f"Database error: {e}")
    

    async def create_api_key(
        self, 
        user_id: UUID, 
        name: str,
        scopes: List[str], 
        expires_days: int = 30
        ) -> Dict[str, Any]:
        """Create API key for user"""
        try:
            # Generate key            
            raw_key, key_hash = self.hasher.generate_token(32)
            key_id = self.hasher.generate_id()

            expires_at = datetime.now(UTC) + timedelta(days=expires_days)
            
            async with pg_pool.get_connection() as conn:
                await pg_cb.execute(
                    lambda: conn.execute('''
                        INSERT INTO api_keys (key_id, key_hash, user_id, name, scopes, expires_at)
                        VALUES ($1, $2, $3, $4, $5, $6)
                    ''', key_id, key_hash, user_id, name, scopes, expires_at
                    )
                )
            
            logger.info(f"Created API key '{name}' for user {user_id}")
            
            return {
                'key_id': key_id,
                'key': raw_key,  # Only returned once!
                'name': name,
                'scopes': scopes,
                'expires_at': expires_at.isoformat()
            }

        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to create API key: {e}")
            raise DatabaseError(f"Database error: {e}")
    

    async def verify_api_key(self, raw_key: str) -> Optional[Dict[str, Any]]:
        """Verify API key and return user info"""
        try:
            key_hash = self.hasher.hash(raw_key)
            
            async with pg_pool.get_connection() as conn:
                row = await conn.fetchrow('''
                    SELECT 
                        ak.key_id, ak.user_id, ak.scopes, ak.expires_at,
                        u.email, u.role, u.mfa_enabled, u.auth_method,
                        u.is_active as user_active
                    FROM api_keys ak
                    JOIN users u ON ak.user_id = u.user_id
                    WHERE ak.key_hash = $1 
                      AND ak.is_active = TRUE
                      AND ak.expires_at > CURRENT_TIMESTAMP
                      AND u.is_active = TRUE
                ''', key_hash
                )
                
                if row:
                    # Update last_used
                    await pg_cb.execute(
                        lambda: conn.execute('''
                            UPDATE api_keys 
                            SET last_used = CURRENT_TIMESTAMP 
                            WHERE key_hash = $1
                        ''', key_hash
                        )
                    )
                    
                    # materialize manually for proper datetime handling
                    return {
                        'key_id': row['key_id'],
                        'user_id': row['user_id'],
                        'scopes': row['scopes'],  # Already a list in PostgreSQL
                        'expires_at': row['expires_at'].isoformat(),
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
            return None


    async def revoke_api_key(self, key_id: UUID, user_id: UUID):
        """Revoke API key"""
        try:
            async with pg_pool.get_connection() as conn:
                await pg_cb.execute(
                    lambda: conn.execute('''
                        UPDATE api_keys 
                        SET is_active = FALSE 
                        WHERE key_id = $1 AND user_id = $2
                    ''', key_id, user_id
                    )
                )
            
            logger.info(f"Revoked API key {key_id}")
        
        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to revoke API key: {e}")
            raise DatabaseError(f"Database error: {e}")
  

    async def list_user_api_keys(self, user_id: UUID) -> List[Dict[str, Any]]:
        """List user's API keys (without the actual key)"""
        try:
            async with pg_pool.get_connection() as conn:
                rows = await conn.fetch('''
                    SELECT key_id, name, scopes, created_at, expires_at, last_used, is_active
                    FROM api_keys
                    WHERE user_id = $1
                    ORDER BY created_at DESC
                ''', user_id
                )
                
                return [
                    {
                        'key_id': row['key_id'],
                        'name': row['name'],
                        'scopes': row['scopes'],  # Already a list in PostgreSQL
                        'created_at': row['created_at'].isoformat(),
                        'expires_at': row['expires_at'].isoformat(),
                        'last_used': row['last_used'].isoformat() if row['last_used'] else None,
                        'is_active': row['is_active']
                    }
                    for row in rows
                ]
                
        except Exception as e:
            logger.error(f"Failed to list API keys: {e}")
            raise DatabaseError(f"Database error: {e}")


    async def create_session(
        self, 
        user_id: UUID, 
        timedelta: timedelta, # let callers decide
        mfa_verified: bool = True,
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
            expires_at = datetime.now(UTC) + timedelta
            
            async with pg_pool.get_connection() as conn:
                await pg_cb.execute(
                    lambda: conn.execute('''
                        INSERT INTO sessions 
                        (session_id, user_id, token_hash, expires_at, ip_address, user_agent, mfa_verified)
                        VALUES ($1, $2, $3, $4, $5, $6, $7)
                    ''', session_id, user_id, token_hash, expires_at, ip_address, user_agent, mfa_verified
                    )
                )
            
                return {
                    'access_token': raw_token,
                    'session_id': session_id,
                    'expires_at': expires_at.isoformat()
                }

        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to create session: {e}")
            raise DatabaseError(f"Database error: {e}")
    

    async def verify_session(self, raw_token: str) -> Optional[Dict[str, Any]]:
        """Verify session token"""
        try:
            token_hash = self.hasher.hash(raw_token)
            
            async with pg_pool.get_connection() as conn:
                row = await conn.fetchrow('''
                    SELECT 
                        s.session_id, s.user_id, s.expires_at, s.mfa_verified,
                        u.email, u.role, u.is_active, u.auth_method, 
                        u.mfa_enabled
                    FROM sessions s
                    JOIN users u ON s.user_id = u.user_id
                    WHERE s.token_hash = $1 
                      AND s.expires_at > CURRENT_TIMESTAMP
                      AND u.is_active = TRUE
                ''', token_hash
                )
                
                if row:
                    return {
                        'session_id': row['session_id'],
                        'user_id': row['user_id'],
                        'expires_at': row['expires_at'], # datetime object for dynamic use comparison/conversion
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
            return None
            

    async def revoke_session(self, session_id: UUID) -> int:
        """Revoke specific session"""
        try:
            async with pg_pool.get_connection() as conn:
                deleted = await pg_cb.execute(
                    lambda: conn.execute('''
                        WITH deleted AS (
                            DELETE FROM sessions 
                            WHERE session_id = $1
                            RETURNING session_id
                        )
                        SELECT COUNT(*) FROM deleted

                    ''', session_id
                    )
                )   
            
            if deleted:
                logger.info(f"Session revoked: {session_id}")
                
                return deleted
        
        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to revoke session: {e}")
            return 0

    async def increment_failed_login(self, user_id: UUID) -> int:
        """Increment failed login counter and return new count"""
        try:
            async with pg_pool.get_connection() as conn:
                result = await pg_cb.execute(
                    lambda: conn.fetchrow('''
                        UPDATE users 
                        SET failed_login_attempts = failed_login_attempts + 1
                        WHERE user_id = $1
                        RETURNING failed_login_attempts
                    ''', user_id
                    )
                )
                
                return result['failed_login_attempts'] if result else 0

        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to increment failed login: {e}")
            raise DatabaseError(f"Database error: {e}")


    async def lock_account(self, user_id: UUID, locked_until: datetime):
        """Lock user account until specified time"""
        try:
            async with pg_pool.get_connection() as conn:
                await pg_cb.execute( 
                    lambda: conn.execute('''
                        UPDATE users 
                        SET account_locked_until = $1
                        WHERE user_id = $2
                    ''', locked_until, user_id
                    )
                )
                
                logger.info(f"User Account Locked")

                return True

        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to lock account: {e}")
            raise DatabaseError(f"Database error: {e}")


    async def reset_failed_login(self, user_id: UUID):
        """Reset failed login attempts"""
        try:
            async with pg_pool.get_connection() as conn:
                await pg_cb.execute( 
                    lambda: conn.execute('''
                        UPDATE users 
                        SET failed_login_attempts = 0, account_locked_until = NULL
                        WHERE user_id = $1
                    ''', user_id
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
            async with pg_pool.get_connection() as conn:
                await pg_cb.execute( 
                    lambda: conn.execute('''
                        UPDATE users 
                        SET last_login = CURRENT_TIMESTAMP
                        WHERE user_id = $1
                    ''', user_id
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
    
        WARNING: This method bypasses old password validation!
        Don't expose this in public API - Ensure callers
        validate old password/reset tokens beforehand.
        
        Direct usage from endpoints is a SECURITY RISK.
        
        Args:
            user_id: User whose password to update
            password_hash: Pre-hashed password (bcrypt hash)
        """
        try:
            async with pg_pool.get_connection() as conn:
                await pg_cb.execute( 
                    lambda: conn.execute('''
                        UPDATE users 
                        SET password_hash = $1
                        WHERE user_id = $2
                    ''', password_hash, user_id
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
            param_count = 0 # for building $ placeholders
            
            if role:
                param_count += 1
                query += f' AND role = ${param_count}' # $1
                params.append(role) 
            
            if auth_method:
                param_count += 1
                query += f' AND auth_method = ${param_count}' # $2
                params.append(auth_method)
            
            if is_active is not None:
                param_count += 1
                query += f' AND is_active = ${param_count}' # $3 ...
                params.append(is_active)
            
            if search:
                param_count += 1
                query += f' AND email ILIKE ${param_count}'
                params.append(f'%{search}%')
            
            query += f' ORDER BY created_at DESC LIMIT ${param_count + 1} OFFSET ${param_count + 2}'
            params.extend([limit, skip])
            
            async with pg_pool.get_connection() as conn:
                rows = await conn.fetch(query, *params)

                return [
                    {
                        "user_id": row['user_id'],
                        "email": row['email'],
                        "role": row['role'],
                        "auth_method": row['auth_method'],
                        "is_active": row['is_active'],
                        "created_at": row['created_at'].isoformat(),
                        "last_login": row['last_login'].isoformat(),
                        "failed_login_attempts": row['failed_login_attempts'],
                        "account_locked_until": row['account_locked_until'].isoformat() if row['account_locked_until'] else None,
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
            param_count = 0
            
            if role:
                param_count += 1
                query += f' AND role = ${param_count}'
                params.append(role)
            
            if auth_method:
                param_count += 1
                query += f' AND auth_method = ${param_count}'
                params.append(auth_method)
            
            if is_active is not None:
                param_count += 1
                query += f' AND is_active = ${param_count}'
                params.append(is_active)
            
            if search:
                param_count += 1
                query += f' AND email ILIKE ${param_count}'
                params.append(f'%{search}%')
            
            async with pg_pool.get_connection() as conn:
                count = await conn.fetchval(query, *params)

                return count or 0
                
        except Exception as e:
            logger.error(f"Failed to count users: {e}")
            return 0


    async def get_user_stats(self) -> Dict[str, Any]:
        """Get user statistics"""
        try:
            async with pg_pool.get_connection() as conn:
                stats = await conn.fetchrow('''
                    SELECT 
                        COUNT(*) as total_users,
                        COUNT(*) FILTER (WHERE is_active = TRUE) as active_users,
                        COUNT(*) FILTER (WHERE is_active = FALSE) as inactive_users,
                        COUNT(*) FILTER (WHERE role = 'admin') as admin_count,
                        COUNT(*) FILTER (WHERE role = 'user') as user_count,
                        COUNT(*) FILTER (WHERE auth_method = 'local') as local_auth_count,
                        COUNT(*) FILTER (WHERE auth_method = 'oidc') as oidc_auth_count,
                        COUNT(*) FILTER (WHERE auth_method = 'saml') as saml_auth_count,
                        COUNT(*) FILTER (WHERE account_locked_until > CURRENT_TIMESTAMP) as locked_accounts,
                        COUNT(*) FILTER (WHERE created_at > CURRENT_TIMESTAMP - INTERVAL '7 days') as recent_signups_7d,
                        COUNT(*) FILTER (WHERE last_login > CURRENT_TIMESTAMP - INTERVAL '24 hours') as recent_logins_24h
                    FROM users
                ''')
                
                if not stats:
                    return {}
                
                return {
                    "total_users": stats['total_users'],
                    "active_users": stats['active_users'],
                    "inactive_users": stats['inactive_users'],
                    "by_role": {
                        "admin": stats['admin_count'],
                        "user": stats['user_count']
                    },
                    "by_auth_method": {
                        "local": stats['local_auth_count'],
                        "oidc": stats['oidc_auth_count'],
                        "saml": stats['saml_auth_count']
                    },
                    "locked_accounts": stats['locked_accounts'],
                    "recent_signups_7d": stats['recent_signups_7d'],
                    "recent_logins_24h": stats['recent_logins_24h']
                }
                
        except Exception as e:
            logger.error(f"Failed to get user stats: {e}")
            return {}


    async def update_user_role(self, user_id: UUID, role: str):
        """Update user role"""
        try:
            async with pg_pool.get_connection() as conn:
                await pg_cb.execute(
                    lambda: conn.execute('''
                        UPDATE users 
                        SET role = $1
                        WHERE user_id = $2
                    ''', role, user_id
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
            async with pg_pool.get_connection() as conn:
                await pg_cb.execute(
                    lambda: conn.execute('''
                        UPDATE users 
                        SET is_active = $1
                        WHERE user_id = $2
                    ''', is_active, user_id
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
            async with pg_pool.get_connection() as conn:
                await pg_cb.execute(
                    lambda: conn.execute('''
                        DELETE FROM users
                        WHERE user_id = $1
                    ''', user_id
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
            async with pg_pool.get_connection() as conn:
                rows = await conn.fetch('''
                    SELECT session_id, created_at, expires_at, ip_address, user_agent
                    FROM sessions
                    WHERE user_id = $1 AND expires_at > CURRENT_TIMESTAMP
                    ORDER BY created_at DESC
                ''', user_id
                )
                
                return [
                    {
                        "session_id": row['session_id'],
                        "created_at": row['created_at'].isoformat(),
                        "expires_at": row['expires_at'].isoformat(),
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
            async with pg_pool.get_connection() as conn:
                deleted = await pg_cb.execute(
                    lambda: conn.execute('''
                        WITH deleted AS (
                            DELETE FROM sessions 
                            WHERE user_id = $1
                            RETURNING session_id
                        )
                        SELECT COUNT(*) FROM deleted

                    ''', user_id
                    )
                )   
            
            if deleted:
                logger.info(f"Revoked {deleted} sessions for user {user_id}")
                
                return deleted
        
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
        try:
            async with pg_pool.get_connection() as conn:
                await pg_cb.execute(
                    lambda:  conn.execute('''
                        INSERT INTO audit_log 
                        (event_type, severity, user_id, email, ip_address, user_agent, 
                         timestamp, details, success, error_message)
                        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                    ''', event_type, severity, user_id, email, ip_address, user_agent,
                        timestamp, json.dumps(details), success, error_message
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
        try:
            query = '''
                SELECT event_type, severity, user_id, email,
                       ip_address, user_agent,
                       timestamp,
                       details, success, error_message
                FROM audit_log
                WHERE 1=1
            '''
            params = []
            param_count = 0
            
            if user_id:
                param_count += 1
                query += f' AND user_id = ${param_count}'
                params.append(user_id)
            
            if start_date:
                param_count += 1
                query += f' AND timestamp >= ${param_count}'
                params.append(start_date)
            
            if end_date:
                param_count += 1
                query += f' AND timestamp <= ${param_count}'
                params.append(end_date)
            
            if event_types:
                param_count += 1
                query += f' AND event_type = ANY(${param_count})'
                params.append(event_types)

            if severity:
                param_count += 1
                query += f' AND severity = ${param_count}'
                params.append(severity)
            
            query += f' ORDER BY timestamp DESC LIMIT ${param_count + 1}'
            params.append(limit)
            
            async with pg_pool.get_connection() as conn:
                rows = await conn.fetch(query, *params)

                return [
                    {
                        "event_type": row['event_type'],
                        "severity": row['severity'],
                        "user_id": str(row['user_id']), # UUID -> STR
                        "email": row['email'],
                        "ip_address": row['ip_address'],
                        "user_agent": row['user_agent'],
                        "timestamp": row['timestamp'].isoformat(),
                        "details": json.loads(row['details']),
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
                WHERE user_id = $1
                  AND timestamp >= $2
                ORDER BY timestamp DESC
                LIMIT $3
            '''
            
            params = [user_id, start_date, limit]
            
            async with pg_pool.get_connection() as conn:
                rows = await conn.fetch(query, *params)
    
                return [
                    {
                        "event_type": row['event_type'],
                        "timestamp": row['timestamp'], # already datetime
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
                WHERE user_id = $1
                ORDER BY timestamp DESC
                LIMIT $2
            '''
            
            params = [user_id, limit]
            
            async with pg_pool.get_connection() as conn:
                rows = await conn.fetch(query, *params)
                
                return [
                    {
                        "type": row['event_type'],
                        "timestamp": row['timestamp'].isoformat(),
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
        try:
            async with pg_pool.get_connection() as conn:
                rows = await conn.fetch('''
                    SELECT 
                        email,
                        ip_address,
                        COUNT(*) as attempt_count,
                        MAX(timestamp) as last_attempt
                    FROM audit_log
                    WHERE event_type = 'login_failed'
                      AND timestamp >= $1
                    GROUP BY email, ip_address
                    HAVING COUNT(*) >= $2
                    ORDER BY attempt_count DESC
                ''', start_date, threshold
                )

                return [
                    {
                        "email": row['email'],
                        "ip_address": row['ip_address'],
                        "attempt_count": row['attempt_count'],
                        "last_attempt": row['last_attempt'].isoformat()
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
        try:
            async with pg_pool.get_connection() as conn:
                summary = await conn.fetchrow('''
                    SELECT 
                        COUNT(*) FILTER (WHERE event_type = 'login_success') as successful_logins,
                        COUNT(*) FILTER (WHERE event_type = 'login_failed') as failed_logins,
                        COUNT(*) FILTER (WHERE event_type = 'password_changed') as password_changes,
                        COUNT(*) FILTER (WHERE severity = 'critical') as critical_events,
                        COUNT(*) FILTER (WHERE severity = 'warning') as warning_events,
                        COUNT(DISTINCT user_id) as unique_users,
                        COUNT(DISTINCT ip_address) as unique_ips
                    FROM audit_log
                    WHERE timestamp >= $1
                ''', start_date
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
        try:
            async with pg_pool.get_connection() as conn:
                await pg_cb.execute(
                    lambda: conn.execute('''
                        INSERT INTO password_reset_tokens 
                        (token_hash, user_id, expires_at, ip_address)
                        VALUES ($1, $2, $3, $4)
                    ''', token_hash, user_id, expires_at, ip_address
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
            async with pg_pool.get_connection() as conn:
                row = await conn.fetchrow('''
                    SELECT token_hash, user_id, created_at, expires_at, used, used_at, ip_address
                    FROM password_reset_tokens
                    WHERE token_hash = $1
                ''', token_hash
                )
                
                if row:
                    return {
                        'token_hash': row['token_hash'],
                        'user_id': row['user_id'],
                        'created_at': row['created_at'],
                        'expires_at': row['expires_at'],
                        'used': row['used'],
                        'used_at': row['used_at'].isoformat() if row['used_at'] else None,
                        'ip_address': row['ip_address']
                    }
                
                return None
                
        except Exception as e:
            logger.error(f"Failed to get password reset token: {e}")
            return None


    async def mark_reset_token_used(self, token_hash: str):
        """Mark password reset token as used"""
        try:
            async with pg_pool.get_connection() as conn:
                await pg_cb.execute(
                    lambda: conn.execute('''
                        UPDATE password_reset_tokens
                        SET used = TRUE, used_at = CURRENT_TIMESTAMP
                        WHERE token_hash = $1
                    ''', token_hash
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
        try:
            async with pg_pool.get_connection() as conn:
                count = await conn.fetchval('''
                    SELECT COUNT(*)
                    FROM password_reset_tokens
                    WHERE user_id = $1 AND created_at >= $2
                ''', user_id, since
                )
                
                return count or 0
                
        except Exception as e:
            logger.error(f"Failed to count reset requests: {e}")
            return 0


    async def delete_password_reset_token(self, token_hash: str) -> bool:
        """
        Delete password reset token
        
        Args:
            token: Reset token
        
        Returns:
            bool: Success status
        """
        try:    
            async with pg_pool.get_connection() as conn:
                await pg_cb.execute(
                    lambda: conn.execute('''
                        DELETE FROM password_reset_tokens
                        WHERE token_hash = $1
                    ''', token_hash
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
            async with pg_pool.get_connection() as conn:
                deleted = await pg_cb.execute(
                    lambda: conn.execute('''
                        WITH deleted AS (
                            DELETE FROM password_reset_tokens 
                            WHERE expires_at < CURRENT_TIMESTAMP
                            RETURNING id
                        )
                        SELECT COUNT(*) FROM deleted
                    '''
                    )
                )
                
                logger.debug(f"Deleted {deleted} expired reset tokens")

                return deleted or 0
        
        except DatabaseError:
            raise        
        except Exception as e:
            logger.error(f"Failed to delete expired reset tokens: {e}")
            return 0


    async def revoke_password_reset_tokens(self, user_id: UUID):
        """Revoke all password reset tokens for user"""
        try:
            async with pg_pool.get_connection() as conn:
                await pg_cb.execute(
                    lambda: conn.execute('''
                        UPDATE password_reset_tokens
                        SET used = TRUE, used_at = CURRENT_TIMESTAMP
                        WHERE user_id = $1 AND used = FALSE
                    ''', user_id
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
        """Create refresh token (PostgreSQL version)"""
        try:
            token, token_hash = self.hasher.generate_token(32)
            
            async with pg_pool.get_connection() as conn:
                await pg_cb.execute(
                    lambda: conn.execute('''
                        INSERT INTO refresh_tokens 
                        (token_hash, user_id, session_id, expires_at, ip_address, user_agent)
                        VALUES ($1, $2, $3, CURRENT_TIMESTAMP + (INTERVAL '1 day' * $4), $5, $6)
                    ''', token_hash, user_id, session_id, expires_days, ip_address, user_agent
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
        """Verify refresh token (PostgreSQL version)"""
        try:
            token_hash = self.hasher.hash(token)
            
            async with pg_pool.get_connection() as conn:
                row = await conn.fetchrow('''
                    SELECT rt.user_id, rt.session_id, rt.expires_at, rt.revoked,
                           u.email, u.role, u.is_active
                    FROM refresh_tokens rt
                    JOIN users u ON rt.user_id = u.user_id
                    WHERE rt.token_hash = $1 
                    AND rt.expires_at > CURRENT_TIMESTAMP
                    AND rt.revoked = FALSE
                    AND u.is_active = TRUE
                ''', token_hash
                )
            
            if not row:
                return None
            
            return {
                'user_id': str(row['user_id']),
                'session_id': str(row['session_id']) if row['session_id'] else None,
                'expires_at': row['expires_at'].isoformat(),
                'email': row['email'],
                'role': row['role']
            }
            
        except Exception as e:
            logger.error(f"Failed to verify refresh token: {e}")
            return None


    async def revoke_refresh_token(self, token: str) -> bool:
        """Revoke refresh token (PostgreSQL version)"""
        try:
            token_hash = self.hasher.hash(token)
            
            async with pg_pool.get_connection() as conn:
                result = await pg_cb.execute(
                    lambda: conn.execute('''
                        UPDATE refresh_tokens 
                        SET revoked = TRUE, revoked_at = CURRENT_TIMESTAMP
                        WHERE token_hash = $1
                    ''', token_hash
                    )
                )
            
            return result != "UPDATE 0"
        
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
            new_token, new_token_hash = self.hasher.generate_token()
            
            async with pg_pool.get_connection() as conn:
                await pg_cb.execute(
                    # circuit breaker inside transaction can leave transaction open on
                    # failure so execute queries inside transaction, wrap transaction in CB
                    lambda: self._rotate_token_transaction(
                        conn, old_token_hash, user_id, new_token_hash,
                        expires_days, session_id, ip_address, user_agent
                    )
                )
            logger.debug(f"Refresh token rotated for user {user_id}")

            return new_token

        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to rotate refresh token: {e}")
            return None


    async def _rotate_token_transaction(
        self,
        conn: asyncpg.Connection,
        old_token_hash: str,
        user_id: UUID,
        new_token_hash: str,
        expires_days: int,
        session_id: UUID,
        ip_address: str,
        user_agent: str
    ) -> bool:
        """Transaction logic for token rotation"""
        async with conn.transaction():# Use transaction for atomicity
            # 1. Verify and revoke old token in one query (atomic)
            result = await conn.execute('''
                UPDATE refresh_tokens 
                SET revoked = TRUE, revoked_at = CURRENT_TIMESTAMP
                WHERE token_hash = $1 
                  AND user_id = $2
                  AND expires_at > CURRENT_TIMESTAMP
                  AND revoked = FALSE
                RETURNING user_id
            ''', old_token_hash, user_id
            )
            
            if result == "UPDATE 0":
                # Old token invalid/expired/already used
                logger.warning(f"Failed to revoke old refresh token for user {user_id}")
                raise ValueError("Invalid refresh token")
            
            # 2. Create new token
            await conn.execute('''
                INSERT INTO refresh_tokens
                (token_hash, user_id, session_id, expires_at, ip_address, user_agent)
                -- VALUES ($1, $2, $3, $4, $5, $6)
                VALUES ($1, $2, $3, CURRENT_TIMESTAMP + (INTERVAL '1 day' * $4), $5, $6)
            ''', new_token_hash, user_id, session_id, expires_days, ip_address, user_agent
            )
            
            return True


    async def revoke_user_refresh_tokens(self, user_id: UUID) -> int:
        """Revoke all user refresh tokens (PostgreSQL version)"""
        try:
            async with pg_pool.get_connection() as conn:
                result = await pg_cb.execute(
                    lambda: conn.execute('''
                        UPDATE refresh_tokens 
                        SET revoked = TRUE, revoked_at = CURRENT_TIMESTAMP
                        WHERE user_id = $1 AND revoked = FALSE
                    ''', user_id
                    )
                )
            
            # Extract count from result "UPDATE N"
            revoked_count = int(result.split()[-1]) if result else 0
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
            cutoff_date = datetime.now(UTC) - timedelta(days=days)
            
            async with pg_pool.get_connection() as conn:
                deleted_count = await pg_cb.execute(
                    # Use CTE with RETURNING to get count directly
                    lambda: conn.fetchval('''
                        WITH deleted AS (
                            DELETE FROM refresh_tokens 
                            WHERE expires_at < $1 OR (revoked = TRUE AND revoked_at < $2)
                            RETURNING token_id
                        )
                        SELECT COUNT(*) FROM deleted
                    ''', cutoff_date, cutoff_date
                    )
                )
                            
            logger.debug(f"Cleaned up {deleted_count} expired refresh tokens")

            return deleted_count or 0
          
        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to cleanup refresh tokens: {e}")
            return 0


    async def get_session_info(self, user_id: UUID) -> Optional[Dict[str, Any]]:
        """Get session info"""
        try:
            async with pg_pool.get_connection() as conn:
                row = await conn.fetchrow('''
                    SELECT session_id, expires_at, ip_address, user_agent, created_at
                    FROM sessions
                    WHERE user_id = $1
                    ORDER BY created_at DESC
                    LIMIT 1
                ''', user_id
                )
            
            if not row:
                return None
            
            return {
                'session_id': str(row['session_id']),
                'expires_at': row['expires_at'],
                'ip_address': str(row['ip_address']) if row['ip_address'] else None,
                'user_agent': row['user_agent'],
                'created_at': row['created_at']
            }
            
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
        """Store MFA secret"""
        try:
            # ENCRYPT the TOTP secret
            encrypted_secret = mfa_crypto.encrypt_secret(secret)

            hashed_backup_codes = [hash_password(code) for code in backup_codes]
            backup_codes_json = json.dumps(hashed_backup_codes)

            async with pg_pool.get_connection() as conn:
                await pg_cb.execute(
                    lambda:  conn.execute('''
                        INSERT INTO mfa_secrets (user_id, method, secret, backup_codes)
                        VALUES ($1, $2, $3, $4)
                        ON CONFLICT (user_id) DO UPDATE SET
                            method = EXCLUDED.method,
                            secret = EXCLUDED.secret,
                            backup_codes = EXCLUDED.backup_codes,
                            created_at = CURRENT_TIMESTAMP,
                            verified_at = NULL
                    ''', user_id, method, encrypted_secret, backup_codes_json
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
        """Get MFA data for verification"""
        try:
            async with pg_pool.get_connection() as conn:
                row = await conn.fetchrow('''
                    SELECT method, secret, backup_codes, verified_at, last_used
                    FROM mfa_secrets
                    WHERE user_id = $1
                ''', user_id
                )
            
            if not row:
                return None
            
            # Decrypt secret
            decrypted_secret = mfa_crypto.decrypt_secret(row['secret'])
            backup_codes = json.loads(row['backup_codes']) if row['backup_codes'] else []

            return {
                'method': row['method'],
                'secret': decrypted_secret,
                'backup_codes': backup_codes,
                'verified_at': row['verified_at'].isoformat() if row['verified_at'] else None,
                'last_used': row['last_used'].isoformat() if row['last_used'] else None
            }
            
        except Exception as e:
            logger.error(f"Failed to get MFA secret: {e}")
            return None


    async def enable_mfa(self, user_id: UUID) -> bool:
        """Enable MFA (PostgreSQL version)"""
        try:
            async with pg_pool.get_connection() as conn:
                 await pg_cb.execute(
                    lambda: conn.execute('''
                        UPDATE users 
                        SET mfa_enabled = TRUE
                        WHERE user_id = $1
                    ''', user_id
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
            async with pg_pool.get_connection() as conn:
                row = await conn.fetchrow('''
                    SELECT 1
                    FROM users
                    WHERE user_id = $1 AND mfa_enabled = TRUE
                    LIMIT 1
                ''', user_id
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
        """Disable MFA"""
        try:
            async with pg_pool.get_connection() as conn:
                async with conn.transaction():
                    result = await pg_cb.execute(
                        lambda: self._disable_mfa_op(conn, user_id)
                    )
            
            logger.info(f"MFA disabled for user {user_id}")
            
            return result
        
        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to delete MFA secret: {e}")
            return False

    async def _disable_mfa_op(self, conn: asyncpg.Connection, user_id: UUID) -> bool:
        """Transaction logic for disabling MFA"""

        # 1. Delete mfa data
        await conn.execute('''
            DELETE FROM mfa_secrets WHERE user_id = $1
            ''', user_id
        )
        
        # 2. Update status
        await conn.execute('''
            UPDATE users 
            SET mfa_enabled = FALSE
            WHERE user_id = $1
        ''', user_id
        )
        
        return True

    async def remove_backup_code(self, user_id: UUID, used_code: str) -> bool:
        """Remove backup code """
        try:
            async with pg_pool.get_connection() as conn:
                # PostgreSQL JSONB operations
                result = await pg_cb.execute(
                    lambda: conn.execute('''
                        UPDATE mfa_secrets 
                        SET backup_codes = backup_codes - $2,
                            last_used = CURRENT_TIMESTAMP
                        WHERE user_id = $1
                        AND backup_codes ? $2
                        RETURNING user_id
                    ''', user_id, used_code
                    )
                )
            
            return result != "UPDATE 0"
        
        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to remove backup code: {e}")
            return False


    async def update_mfa_verification(self, user_id: UUID) -> bool:
        """Update MFA last used (PostgreSQL version)"""
        try:
            async with pg_pool.get_connection() as conn:
                await pg_cb.execute(
                    lambda: conn.execute('''
                        UPDATE mfa_secrets 
                        SET verified_at = CURRENT_TIMESTAMP
                        WHERE user_id = $1
                    ''', user_id
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
            async with pg_pool.get_connection() as conn:
                count = await pg_cb.execute(
                    lambda: conn.fetchval('''
                        WITH deleted AS (
                            DELETE FROM sessions 
                            WHERE expires_at < CURRENT_TIMESTAMP
                            RETURNING session_id
                        )
                        SELECT COUNT(*) FROM deleted
                    '''
                    )
                )
            
            logger.debug(f"Cleaned up {count} expired sessions")
            
            return count or 0
          
        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to cleanup sessions: {e}")
            return 0


    async def cleanup_expired_password_resets(self, days: int = 7) -> int:
        """Clean up old password reset tokens"""
        try:
            # 7-day retention (security sensitive)
            cutoff_date = datetime.now(UTC) - timedelta(days=days)
            
            async with pg_pool.get_connection() as conn:
                count = await pg_cb.execute(
                    lambda: conn.fetchval('''
                        WITH deleted AS (
                            DELETE FROM password_reset_tokens 
                            WHERE expires_at < $1 OR (used = TRUE AND used_at < $1)
                            RETURNING id
                        )
                        SELECT COUNT(*) FROM deleted
                    ''', cutoff_date
                    )
                )
            
            logger.debug(f"Cleaned up {count} password reset tokens")
            
            return count or 0
            
        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to cleanup password resets: {e}")
            return 0

    
    async def cleanup_expired(self) -> int:
        """Clean up expired sessions and API keys"""
        try:
            async with pg_pool.get_connection() as conn:
                # Count first
                sessions_count = await conn.fetchval(
                    'SELECT COUNT(*) FROM sessions WHERE expires_at < CURRENT_TIMESTAMP'
                )

                keys_count = await conn.fetchval(
                    'SELECT COUNT(*) FROM api_keys WHERE expires_at < CURRENT_TIMESTAMP AND is_active = TRUE'
                )

                # Then delete
                await pg_cb.execute(
                    conn.execute('DELETE FROM sessions WHERE expires_at < CURRENT_TIMESTAMP')
                    )
                await pg_cb.execute(
                    conn.execute(
                    'UPDATE api_keys SET is_active = FALSE WHERE expires_at < CURRENT_TIMESTAMP AND is_active = TRUE')
                    )
                
                total = (sessions_count or 0) + (keys_count or 0)

                if total > 0:
                    logger.info(f"Cleaned up {total} expired auth records")
                
                return total
            
        except DatabaseError:
            raise 
        except Exception as e:
            logger.error(f"Failed to cleanup expired: {e}")
            return 0

    
    async def health_check(self) -> Dict[str, Any]:
        """Health check"""
        try:
            async with pg_pool.get_connection() as conn:
                user_count = await conn.fetchval('SELECT COUNT(*) FROM users WHERE is_active = TRUE')
                active_keys = await conn.fetchval('SELECT COUNT(*) FROM api_keys WHERE is_active = TRUE AND expires_at > CURRENT_TIMESTAMP')
                active_sessions = await conn.fetchval('SELECT COUNT(*) FROM sessions WHERE expires_at > CURRENT_TIMESTAMP')
            
            return {
                'status': 'healthy',
                'database_type': 'PostgreSQL',
                'active_users': user_count,
                'active_api_keys': active_keys,
                'active_sessions': active_sessions
            }
            
        except Exception as e:
            logger.error(f"Auth health check failed: {e}")
            return {'status': 'unhealthy', 'error': str(e)}

    
    async def close(self):
        """Cleanup"""
        async with self._lock:
            if self._initialized:
                try:
                    # Close connection pool gracefully
                    await pg_pool.unregister_component(self.COMPONENT_NAME)
                    self._initialized = False
                    # logger.debug("Auth store closed successfully")

                except Exception as e:
                    logger.error(f"Error closing Auth store: {e}")
                    raise DatabaseError(f"Unexpected database closing error: {e}")