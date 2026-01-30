import logging
import asyncio
import secrets
from uuid import UUID
from datetime import timedelta
from typing import Optional, Dict, Any

from app.auth.sec_prov.base import (
    AuthenticationProvider, AuthMethod, UserIdentity, 
    AuthenticationRequest, InvalidCredentialsError, AccountLockedError
)
from app.auth.pwd_mngr.pwd_utils import (
    hash_password, verify_password, validate_password_strength,
    AccountLockoutManager
)
from app.auth.compliance.sec_audit_log import audit_logger


logger = logging.getLogger(__name__)


class LocalAuthProvider(AuthenticationProvider):
    """
    Local username/password authentication provider
    """
    
    def __init__(self, auth_store):
        """
        Initialize with auth store dependency.
        
        Args:
            auth_store: SQLiteAuthStore or PostgreSQLAuthStore instance
        """
        self.auth_store = auth_store
        self._provider_name = "Local Authentication"
    

    @property
    def auth_method(self) -> AuthMethod:
        return AuthMethod.LOCAL
    

    @property
    def provider_name(self) -> str:
        return self._provider_name
    

    async def authenticate(self, request: AuthenticationRequest) -> Optional[UserIdentity]:
        """Authenticate user"""

        if not request.username or not request.password:

            # audit log
            await audit_logger.log_event(
                event_type="login_failed",
                success=False,
                ip_address=request.ip_address,
                details={"reason": "missing_credentials"}
            )

            raise InvalidCredentialsError("Username and password required")
        
        try:
            # Get user from database
            user_data = await self.auth_store.get_user_by_email(request.username, True)
            
            if not user_data:
                logger.warning(f"Login attempt for non-existent user: {request.username}")

                # audit log
                await audit_logger.log_event(
                    event_type="login_failed",
                    success=False,
                    ip_address=request.ip_address,
                    details={"reason": "non_existing_user"}
                )

                raise InvalidCredentialsError("user doesn't exist")

            # Check status
            if not user_data["is_active"]:
                logger.warning(f"Login attempt for deactivated user: {request.username}")

                # audit log
                await audit_logger.log_event(
                    event_type="login_failed",
                    success=False,
                    ip_address=request.ip_address,
                    details={"reason": "deactivated_user"}
                )

                raise InvalidCredentialsError("deactivated user")
            
            # Check if account is locked
            locked_until = user_data.get('account_locked_until')
            if AccountLockoutManager.is_account_locked(locked_until):
                logger.warning(f"Login attempt for locked account: {request.username}")

                # audit log
                await audit_logger.log_event(
                    event_type="login_failed",
                    user_id=user_data['user_id'],
                    email=user_data['email'],
                    success=False,
                    ip_address=request.ip_address,
                    details={"reason": "account_locked"}
                )

                raise AccountLockedError(
                    f"Account locked until {locked_until.strftime('%Y-%m-%d %H:%M:%S UTC')}"
                )
            
            # Verify password
            password_hash = user_data.get('password_hash')
            if not password_hash:
                logger.error(f"User {request.username} has no password hash (SSO user?)")

                # audit log
                await audit_logger.log_event(
                    event_type="login_failed",
                    user_id=user_data['user_id'],
                    email=user_data['email'],
                    success=False,
                    ip_address=request.ip_address,
                    details={"reason": "invalid_auth_method"}
                )

                raise InvalidCredentialsError("Invalid auth method")
            
            password_valid = verify_password(request.password, password_hash)
            
            if not password_valid:
                # Handle failed login
                await self._handle_failed_login(user_data['user_id'], request)

                # audit log
                await audit_logger.log_event(
                    event_type="login_failed",
                    user_id=user_data['user_id'],
                    email=user_data['email'],
                    success=False,
                    ip_address=request.ip_address,
                    details={"reason": "invalid_credentials"}
                ) 

                raise InvalidCredentialsError("Invalid credentials")
            
            # Successful login - reset failed attempts
            await self._handle_successful_login(user_data['user_id'], request)
            
            # Return user identity
            return UserIdentity(
                user_id=user_data['user_id'],
                email=user_data['email'],
                role=user_data['role'],
                auth_method=AuthMethod.LOCAL,
                mfa_enabled=user_data['mfa_enabled'],
                auth_provider="local",
                scopes=self._get_default_scopes(user_data['role'])
            )
            
        except (InvalidCredentialsError, AccountLockedError):
            raise
        except Exception as e:
            logger.error(f"Authentication error for {request.username}: {e}")
            raise InvalidCredentialsError("Authentication failed")
        finally:
            # Add small random delay (50-150ms) to prevent timing analysis
            # and user enumeration via login timing. Executes in all paths
            await asyncio.sleep(0.05 + (secrets.randbelow(100) / 1000))
    

    async def get_user_by_id(self, user_id: UUID) -> Optional[UserIdentity]:
        """Get user identity by ID"""
        try:
            user_data = await self.auth_store.get_user_by_id(user_id)
            
            if not user_data:
                return None
            
            return self._user_data_to_identity(user_data)
            
        except Exception as e:
            logger.error(f"Error getting user by ID {user_id}: {e}")
            return None
    

    async def get_user_by_email(self, email: str) -> Optional[UserIdentity]:
        """Get user identity by email"""
        try:
            user_data = await self.auth_store.get_user_by_email(email)
            
            if not user_data:
                return None
            
            return self._user_data_to_identity(user_data)
            
        except Exception as e:
            logger.error(f"Error getting user by email {email}: {e}")
            return None
    

    async def create_user(self, identity: UserIdentity, password: str = None, **kwargs) -> UserIdentity:
        """
        Create new local user with password.
        
        Args:
            identity: User identity information
            password: Plain text password (will be hashed)
            **kwargs: Additional parameters
            
        Returns:
            Created UserIdentity
        """
        if not password:
            raise ValueError("Password required for local user creation")
        
        # Validate password strength
        is_valid, message = validate_password_strength(password)
        if not is_valid:
            raise ValueError(f"Password validation failed: {message}")
        
        # Hash password
        password_hash = hash_password(password)
        
        try:
            # Create user in database
            user_data = await self.auth_store.create_user(
                email=identity.email,
                role=identity.role,
                auth_method=identity.auth_method,
                mfa_enabled=identity.mfa_enabled,
                password_hash=password_hash,
                sso_id=identity.sso_id,
                user_id=identity.user_id
            )
            
            logger.info(f"Created local user: {identity.email}")
            
            return UserIdentity(
                user_id=user_data['user_id'],
                email=user_data['email'],
                role=user_data['role'],
                auth_method=AuthMethod.LOCAL,
                mfa_enabled=False,
                auth_provider="local",
                scopes=self._get_default_scopes(user_data['role'])
            )
            
        except Exception as e:
            logger.error(f"Failed to create user {identity.email}: {e}")
            raise
    

    async def supports_password_change(self) -> bool:
        """Local auth supports password changes"""
        return True
    

    async def change_password(self, user_id: UUID, old_password: str, new_password: str) -> bool:
        """
        Change user password.
  
        Args:
            user_id: User whose password to change
            old_password: Current password for verification
            new_password: New password to set
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Get user data
            user_data = await self.auth_store.get_user_by_id(user_id, True)
            if not user_data:
                logger.error(f"Password change failed: user {user_id} not found")
                return False
            
            # Verify old password
            password_hash = user_data.get('password_hash')
            if not password_hash or not verify_password(old_password, password_hash):
                logger.warning(f"Password change failed: invalid old password for {user_id}")
                return False
            
            # Validate new password strength
            is_valid, message = validate_password_strength(new_password)
            if not is_valid:
                logger.warning(f"Password change failed: {message}")
                return False
            
            # Hash new password
            new_password_hash = hash_password(new_password)
            
            # Update in database
            await self.auth_store.update_password_hash(user_id, new_password_hash)
            
            logger.info(f"Password changed successfully for user {user_id}")
            return True
            
        except Exception as e:
            logger.error(f"Password change error for {user_id}: {e}")
            return False


    async def create_session(
        self,
        user_id: UUID,
        timedelta: timedelta,
        mfa_verified: bool = True,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Dict[str, str]:
        """
        Create session token for user
        
        Returns:
            Dict with 'access_token', 'session_id', 'expires_at'
        """
        try:
            return await self.auth_store.create_session(
                user_id=user_id,
                timedelta=timedelta,
                mfa_verified=mfa_verified,
                ip_address=ip_address,
                user_agent=user_agent
            )
            
        except Exception as e:
            logger.error(f"Failed to create session: {e}")
            raise


    async def verify_session(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify session token"""
        try:
            return await self.auth_store.verify_session(token)
        except Exception as e:
            logger.error(f"Failed to verify session: {e}")
            return None


    async def revoke_session(self, session_id: UUID) -> bool:
        """
        revoke single session 
            
        Returns:
            True if successful
        """
        try:
            await self.auth_store.revoke_session(session_id)
            logger.info(f"Session revoked: {session_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to revoke session: {e}")
            return False


    async def get_session_info(self, user_id: UUID) -> Optional[Dict[str, Any]]:
        """Get session information for user"""
        try:
            return await self.auth_store.get_session_info(user_id)
        except Exception as e:
            logger.error(f"Failed to get session info: {e}")
            return None


    async def create_refresh_token(
        self,
        user_id: UUID,
        expires_days: int = 30,
        session_id: Optional[UUID] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> str:
        """
        Create refresh token
        
        Returns:
            Refresh token (plain text)
        """
        try:
            return await self.auth_store.create_refresh_token(
                user_id=user_id,
                expires_days=expires_days,
                session_id=session_id,
                ip_address=ip_address,
                user_agent=user_agent
            )

        except Exception as e:
            logger.error(f"Failed to create refresh token: {e}")
            raise


    async def verify_refresh_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify refresh token and return session data"""
        try:
            return await self.auth_store.verify_refresh_token(token)
        except Exception as e:
            logger.error(f"Failed to verify refresh token: {e}")
            return None


    async def revoke_refresh_token(self, token: str) -> bool:
        """Revoke a refresh token"""
        try:
            return await self.auth_store.revoke_refresh_token(token)
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
        Atomically revoke old token and create new one
        
        Returns:
            New refresh token if successful, None if old token invalid
        """
        try:
            return await self.auth_store.rotate_refresh_token(
                old_token=old_token,
                user_id=user_id,
                expires_days=expires_days,
                session_id=session_id,
                ip_address=ip_address,
                user_agent=user_agent
            )

        except Exception as e:
            logger.error(f"Failed to rotate refresh token: {e}")
            return None


    async def check_mfa(self, user_id: UUID) -> bool:
        """Check if MFA is enabled for a specific user"""
        try:
            return await self.auth_store.check_mfa(user_id)
        except Exception as e:
            logger.error(f"Failed to check MFA: {e}")
            return None


    async def store_mfa_secret(
        self,
        user_id: UUID,
        secret: str,
        backup_codes: list[str],
        method: str = "totp"
    ) -> bool:
        """Store MFA secret for user"""
        try:
            return await self.auth_store.store_mfa_secret(
                user_id=user_id,
                secret=secret,
                backup_codes=backup_codes,
                method=method
            )

        except Exception as e:
            logger.error(f"Failed to store MFA secret: {e}")
            return False


    async def get_mfa_data(self, user_id: UUID) -> Optional[Dict[str, Any]]:
        """Get MFA secret for verification"""
        try:
            return await self.auth_store.get_mfa_data(user_id)
        except Exception as e:
            logger.error(f"Failed to get MFA secret: {e}")
            return None


    async def enable_mfa(self, user_id: UUID) -> bool:
        """Activate MFA after successful verification"""
        try:
            return await self.auth_store.enable_mfa(user_id)
        except Exception as e:
            logger.error(f"Failed to enable MFA: {e}")
            return False


    async def disable_mfa(self, user_id: UUID) -> bool:
        """Delete MFA configuration"""
        try:
            return await self.auth_store.disable_mfa(user_id)
        except Exception as e:
            logger.error(f"Failed to delete MFA secret: {e}")
            return False


    async def update_user_attributes(self, user_id: UUID, attributes: Dict[str, Any]) -> bool:
        """Update user attributes (limited for local auth)"""
        try:
            # For local auth, we only allow updating basic attributes
            # Not SSO-specific fields
            allowed_updates = {}
            
            if 'role' in attributes:
                allowed_updates['role'] = attributes['role']
            
            if not allowed_updates:
                return True
            
            # TODO: add this method to auth stores
            logger.info(f"User attribute update for {user_id}: {allowed_updates}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to update user attributes: {e}")
            return False
    

    async def delete_user(self, user_id: UUID) -> bool:
        """Permanently delete user account"""
        try:
            await self.auth_store.delete_user(user_id)
            logger.info(f"User deleted: {user_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to delete user: {e}")
            return False


    async def update_user_status(self, user_id: UUID, is_active: bool) -> bool:
        """
        Enable or disable user account.
        
        Args:
            user_id: User to update
            is_active: True to enable, False to disable
            
        Returns:
            True if successful
        """
        try:
            await self.auth_store.update_user_status(user_id, is_active)
            logger.info(f"User status updated: {user_id} active={is_active}")
            return True
        except Exception as e:
            logger.error(f"Failed to update user status: {e}")
            return False


    async def update_user_role(self, user_id: UUID, new_role: str) -> bool:
        """
        Update user role.
        
        Args:
            user_id: User to update
            new_role: New role ('admin' or 'user')
            
        Returns:
            True if successful
        """
        try:
            if new_role not in ('admin', 'user'):
                raise ValueError(f"Invalid role: {new_role}")
            
            await self.auth_store.update_user_role(user_id, new_role)
            logger.info(f"User role updated: {user_id} → {new_role}")
            return True
        except Exception as e:
            logger.error(f"Failed to update user role: {e}")
            return False


    async def logout(self, user_id: UUID) -> bool:
        """Logout user - revoke active sessions"""
        try:
            # Revoke all active sessions for this user
            sessions_revoked = await self.auth_store.revoke_user_sessions(user_id)
            
            # Revoke refresh tokens
            tokens_revoked = await self.auth_store.revoke_user_refresh_tokens(user_id)
            
            logger.info(
                f"User logout: {user_id}"
                f"({sessions_revoked} sessions, {tokens_revoked} refresh tokens revoked)"
                )
            
            return True
            
        except Exception as e:
            logger.error(f"Logout failed for {user_id}: {e}")
            return False


    async def health_check(self) -> Dict[str, Any]:
        """Check local auth provider health"""
        try:
            # Check if auth_store is responsive
            health = await self.auth_store.health_check_async()
            
            return {
                "provider": self.provider_name,
                "auth_method": self.auth_method.value,
                "status": health.get("status", "unknown"),
                "database_type": health.get("database_type"),
                "active_users": health.get("active_users", 0)
            }
            
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return {
                "provider": self.provider_name,
                "auth_method": self.auth_method.value,
                "status": "unhealthy",
                "error": str(e)
            }
    
    # Helper methods
    
    async def _handle_failed_login(self, user_id: UUID, request: AuthenticationRequest):
        """Track failed login attempt and lock account if needed"""
        try:
            # This requires adding methods to auth stores
            failed_attempts = await self.auth_store.increment_failed_login(user_id)
            
            if AccountLockoutManager.should_lock_account(failed_attempts):
                locked_until = AccountLockoutManager.calculate_lockout_until()
                await self.auth_store.lock_account(user_id, locked_until)
                
                logger.warning(
                    f"Account locked: {user_id} after {failed_attempts} failed attempts "
                    f"until {locked_until.strftime('%Y-%m-%d %H:%M:%S UTC')}"
                )
            else:
                logger.warning(
                    f"Failed login attempt {failed_attempts} for user {user_id} "
                    f"from {request.ip_address}"
                )
                
        except Exception as e:
            logger.error(f"Error handling user authentication: {e}")
    

    async def _handle_successful_login(self, user_id: UUID, request: AuthenticationRequest):
        """Reset failed attempts and update last login"""
        try:
            await self.auth_store.reset_failed_login(user_id)
            await self.auth_store.update_last_login(user_id)
            
            logger.info(f"Successful authentication: {user_id} from {request.ip_address}")
            
        except Exception as e:
            logger.error(f"Error handling successful authentication: {e}")
    

    def _user_data_to_identity(self, user_data: Dict[str, Any]) -> UserIdentity:
        """Convert auth store user data to UserIdentity"""
        return UserIdentity(
            user_id=user_data['user_id'],
            email=user_data['email'],
            role=user_data['role'],
            auth_method=AuthMethod(user_data.get('auth_method', 'local')),
            mfa_enabled=user_data['mfa_enabled'],
            auth_provider=user_data.get('sso_provider', 'local'),
            sso_id=user_data.get('sso_id'),
            sso_attributes=user_data.get('sso_attributes', {}),
            scopes=self._get_default_scopes(user_data['role'])
        )
    

    def _get_default_scopes(self, role: str) -> list[str]:
        """Get default scopes based on user role"""
        if role == 'admin':
            return ['search', 'ask', 'upload', 'admin']
        else:
            return ['search', 'ask']