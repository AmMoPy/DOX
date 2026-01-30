import logging
from uuid import UUID
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta, UTC
from app.auth.sec_prov.base import (
    AuthenticationProvider, AuthMethod, UserIdentity, 
    AuthenticationRequest, AuthenticationError
)
from app.auth.sec_prov.local import LocalAuthProvider
from app.db.db_factory import auth_store
from app.config.setting import settings

logger = logging.getLogger(__name__)


class AuthenticationManager:
    """
    Central authentication manager that coordinates multiple auth providers.
    
    This manager:
    1. Routes authentication requests to appropriate providers
    2. Handles Just-In-Time (JIT) user provisioning for SSO
    3. Provides unified authentication interface for the application
    4. Supports configuration-driven provider selection
    """
    
    def __init__(self, default_auth_method: str = 'local'):
        """
        Initialize authentication manager.
        
        Args:
            default_auth_method: Default authentication method to use
        """
        self.default_auth_method = AuthMethod(default_auth_method)
        self._providers: Dict[AuthMethod, AuthenticationProvider] = {}
        self._initialized = False
        
        logger.info(f"Authentication manager initialized with default method: {default_auth_method}")
    

    def register_provider(self, provider: AuthenticationProvider):
        """
        Register an authentication provider.
        
        Args:
            provider: AuthenticationProvider instance
        """
        auth_method = provider.auth_method
        self._providers[auth_method] = provider
        
        logger.info(f"Registered authentication provider: {provider.provider_name} ({auth_method.value})")
    

    def get_provider(self, auth_method: Optional[AuthMethod] = None) -> Optional[AuthenticationProvider]:
        """
        Get authentication provider by method.
        
        Args:
            auth_method: Specific auth method, or None for default
            
        Returns:
            AuthenticationProvider if found, None otherwise
        """
        if auth_method is None:
            auth_method = self.default_auth_method
        
        return self._providers.get(auth_method)
    

    async def authenticate(
        self, 
        request: AuthenticationRequest,
        auth_method: Optional[AuthMethod] = None
        ) -> Optional[UserIdentity]:
        """
        Authenticate user with specified or default provider.
        
        Args:
            request: Authentication request
            auth_method: Specific auth method, or None for default
            
        Returns:
            UserIdentity if successful, None otherwise
            
        Raises:
            AuthenticationError: If authentication fails
        """
        provider = self.get_provider(auth_method)
        
        if not provider:
            method_name = auth_method.value if auth_method else self.default_auth_method.value
            logger.error(f"No provider registered for auth method: {method_name}")
            raise AuthenticationError(f"Authentication method not available: {method_name}")
        
        try:
            identity = await provider.authenticate(request)
            
            if identity:
                logger.info(
                    f"Authentication successful: {identity.email} "
                    f"via {provider.provider_name}"
                )
            
            return identity
        
        except AuthenticationError: # no provider
            raise
        except (InvalidCredentialsError, AccountLockedError): # local auth error
            raise
        except Exception as e: # generic
            logger.error(f"Unexpected authentication error: {e}")
            raise
    

    async def get_user_by_id(
        self,
        user_id: UUID,
        auth_method: Optional[AuthMethod] = None
        ) -> Optional[UserIdentity]:
        """
        Get user identity by ID.
        
        Tries default provider first, then falls back to other providers.
        """
        # Try specified or default provider first
        provider = self.get_provider(auth_method)
        if provider:
            identity = await provider.get_user_by_id(user_id)
            if identity:
                return identity
        
        # Fall back to trying all providers
        for provider in self._providers.values():
            try:
                identity = await provider.get_user_by_id(user_id)
                if identity:
                    return identity
            except Exception as e:
                logger.debug(f"Provider {provider.provider_name} failed to get user: {e}")
                continue
        
        return None
    

    async def get_user_by_email(
        self, 
        email: str,
        auth_method: Optional[AuthMethod] = None
        ) -> Optional[UserIdentity]:
        """
        Get user identity by email.
        
        Tries default provider first, then falls back to other providers.
        """
        # Try specified or default provider first
        provider = self.get_provider(auth_method)
        if provider:
            identity = await provider.get_user_by_email(email)
            if identity:
                return identity
        
        # Fall back to trying all providers
        for provider in self._providers.values():
            try:
                identity = await provider.get_user_by_email(email)
                if identity:
                    return identity
            except Exception as e:
                logger.debug(f"Provider {provider.provider_name} failed to get user: {e}")
                continue
        
        return None
    

    async def create_user(self, identity: UserIdentity, **kwargs) -> UserIdentity:
        """
        Create user with appropriate provider.
        
        Args:
            identity: User identity to create
            **kwargs: Provider-specific parameters (e.g., password for local auth)
            
        Returns:
            Created UserIdentity
        """
        provider = self.get_provider(identity.auth_method)
        
        if not provider:
            raise AuthenticationError(
                f"Cannot create user: no provider for auth method {identity.auth_method.value}"
            )
        
        return await provider.create_user(identity, **kwargs)
    

    async def get_or_create_user(self, identity: UserIdentity, **kwargs) -> UserIdentity:
        """
        Get existing user or create new one
        
        This is used for SSO scenarios where users are automatically
        created on first login.
        
        Args:
            identity: User identity from SSO provider
            **kwargs: Additional parameters for user creation
            
        Returns:
            UserIdentity (existing or newly created)
        """
        # Try to find existing user
        existing_user = None
        
        # First try by SSO ID if available
        if identity.sso_id:
            # TODO: add methodS to search by sso_id
            # For now, search by ID
            existing_user = await self.get_user_by_id(identity.user_id)
        
        # Try by email
        if not existing_user:
            existing_user = await self.get_user_by_email(identity.email)
        
        if existing_user:
            # Update SSO attributes if they've changed
            provider = self.get_provider(existing_user.auth_method)
            
            if provider and identity.sso_attributes:
                await provider.update_user_attributes(
                    existing_user.user_id, 
                    identity.sso_attributes
                )
            
            logger.info(f"Found existing user for SSO login: {identity.email}")

            return existing_user
        
        # Create new user
        logger.info(f"Creating new user: {identity.email}")
        
        return await self.create_user(identity, **kwargs)
    

    async def change_password(
        self,
        user_id: UUID,
        old_password: str, 
        new_password: str,
        auth_method: Optional[AuthMethod] = None
        ) -> bool:
        """
        Change user password (local auth only).
        
        Args:
            user_id: User whose password to change
            old_password: Current password
            new_password: New password
            
        Returns:
            True if successful, False otherwise
        """
        # Optional use other search method,
        # for now just use default
        provider = self.get_provider(auth_method)
        
        if not provider:
            method_name = auth_method.value if auth_method else self.default_auth_method.value
            logger.error(f"Password change failed: no provider for {method_name}")
            return False
        
        if not await provider.supports_password_change():
            logger.warning(
                f"Password change not supported for auth method: {method_name}"
            )
            return False
        
        return await provider.change_password(user_id, old_password, new_password)
    

    async def create_session(
        self,
        user_id: UUID,
        timedelta: timedelta,
        mfa_verified: bool = True,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        auth_method: Optional[AuthMethod] = None
        ) -> bool:
        """
        Create single session 
        
        Returns:
            Dict with session details
        """
        # Delegate to store
        provider = self.get_provider(auth_method)
        
        if not provider:
            method_name = auth_method.value if auth_method else self.default_auth_method.value
            raise AuthenticationError(f"No provider available for auth method: {method_name}")
        
        try:
            session_data = await provider.create_session(
                user_id=user_id,
                timedelta=timedelta,
                mfa_verified=mfa_verified,
                ip_address=ip_address,
                user_agent=user_agent
            )
        
            return session_data
                
        except Exception as e:
            logger.error(f"Failed to create session: {e}")
            raise AuthenticationError(
                f"Failed to create session: {e}"
            )

    async def create_session_with_refresh(
        self,
        user_id: UUID,
        timedelta: timedelta,
        expires_days: int = 30,
        mfa_verified: bool = True,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        auth_method: Optional[AuthMethod] = None
    ) -> Dict[str, str]:
        """
        Create both access token and refresh token
        
        Returns:
            Dict with access_token and refresh_token
        """
        provider = self.get_provider(auth_method)
        
        if not provider:
            method_name = auth_method.value if auth_method else self.default_auth_method.value
            logger.error(f"Session creation with refresh failed: no provider for {method_name}")
            raise AuthenticationError(
                f"Failed to create session with refresh: no provider for auth method {method_name}"
            )
        
        try:
            session_data = await provider.create_session(
                user_id=user_id,
                timedelta=timedelta,
                mfa_verified=mfa_verified,
                ip_address=ip_address,
                user_agent=user_agent
            )

            # Create refresh token
            # Session ID Linking for 
            # Refresh Tokens is good for:
            # Security: If access token is compromised, can revoke all linked refresh tokens
            # Audit: Track which refresh tokens belong to which sessions
            # User Management: "Logout from all devices" can revoke session + linked refresh tokens
            # Forensics: If suspicious activity detected, trace back to original login
            refresh_token = await provider.create_refresh_token(
                user_id=user_id,
                expires_days=expires_days,
                session_id=session_data['session_id'],
                ip_address=ip_address,
                user_agent=user_agent
            )
            
            return {
                # 'access_token': access_token,
                'access_token': session_data['access_token'],
                'refresh_token': refresh_token,
                "expires_in": timedelta.seconds,        # access_token expire hours in seconds
                "expires_at": session_data['expires_at']   # access_token expire UTC ISO 
            }
            
        except Exception as e:
            logger.error(f"Failed to create session with refresh: {e}")
            raise AuthenticationError(
                f"Failed to create session with refresh: {e}"
            )


    async def refresh_session(
        self,
        refresh_token: str,
        timedelta: timedelta,
        expires_days: int = 30,
        ip_address: Optional[str] = None,
        auth_method: Optional[AuthMethod] = None
    ) -> Optional[Dict[str, str]]:
        """
        Refresh access token using refresh token

        Implements secure token rotation:
        1. Verify refresh token
        2. Create new access token
        3. Atomically rotate refresh token (revoke old, create new)
        
        This prevents token reuse attacks
            
        Returns:
            Dict with new access_token and refresh_token, or None if invalid
        """
        provider = self.get_provider(auth_method)
        
        if not provider:
            method_name = auth_method.value if auth_method else self.default_auth_method.value
            logger.error(f"Session refresh failed: no provider for {method_name}")
            raise AuthenticationError(
                f"Cannot refresh session: no provider for auth method {method_name}"
            )
        
        try:
            # 1. Verify refresh token (read-only, can be cached)
            token_data = await provider.verify_refresh_token(refresh_token)
            
            if not token_data:
                logger.warning("Invalid or expired refresh token")
                return {}
            
            user_id = token_data['user_id']
            email = token_data['email']

            # 2. Create new access token
            session_data = await provider.create_session(
                user_id=user_id,
                timedelta=timedelta,
                ip_address=ip_address
            )
            
            # 3. Rotate refresh token (atomic revoke + create in one call)
            new_refresh_token = await provider.rotate_refresh_token(
                old_token=refresh_token,
                user_id=user_id,
                expires_days=expires_days,
                session_id=session_data['session_id'],
                ip_address=ip_address
            )
            
            if not new_refresh_token:
                # TODO: Race condition? token was used/revoked/stolen 
                # between steps 1 and 3, apply token family checks?
                logger.warning(f"Refresh token rotation failed for user {user_id}")
                return {
                    'user_id': user_id,
                    'email': email,
                }
            
            logger.info(f"Session refreshed successfully for user {user_id}")

            return {
                'user_id': user_id,
                'email': email,
                'access_token': session_data['access_token'],
                'refresh_token': new_refresh_token,
                "expires_in": timedelta.seconds,        # access_token expire hours in seconds
                "expires_at": session_data['expires_at']   # access_token expire UTC ISO
            }

        except Exception as e:
            logger.error(f"Failed to refresh session: {e}")
            return None
 

    async def verify_session(
        self, 
        token: str,
        auth_method: Optional[AuthMethod] = None
        ) -> bool:
        """
        verify single session 
        
        Returns:
            Dict with session details
        """
        # Delegate to store
        provider = self.get_provider(auth_method)
        
        if not provider:
            method_name = auth_method.value if auth_method else self.default_auth_method.value
            raise AuthenticationError(f"No provider available for auth method: {method_name}")
        
        try:
            session_data = await provider.verify_session(token)
        
            return session_data
                
        except:
            logger.error(f"Failed to verify session: {e}")
            raise AuthenticationError(
                f"Failed to verify session: {e}"
            )


    async def revoke_session(
        self, 
        # session_id: str,
        session_id: UUID,
        auth_method: Optional[AuthMethod] = None
        ) -> bool:
        """
        revoke single session 
        
        Returns:
            True if successful
        """
        # Delegate to store
        provider = self.get_provider(auth_method)
        
        if not provider:
            method_name = auth_method.value if auth_method else self.default_auth_method.value
            raise AuthenticationError(f"No provider available for auth method: {method_name}")
        
        success = await provider.revoke_session(session_id)
            
        if success:
            logger.info(f"Session revoked: {session_id}")
        
        return success


    async def lock_user_account(
        self,
        user_id: UUID,
        admin_user_id: UUID,
        auth_method: AuthMethod
    ) -> bool:
        """
        Permanently lock user account until admin unlocks
        
        Args:
            user_id: User to lock
            admin_user_id: Admin performing the action
            auth_method: User's authentication method
        
        Returns:
            True if successful
        
        Security:
        - Only local auth users can be locked
        - Admin cannot lock themselves
        - All sessions are revoked
        - Audit logged
        """
        provider = self.get_provider(auth_method)

        if not provider:
            method_name = auth_method.value if auth_method else self.default_auth_method.value
            raise AuthenticationError(
                f"No provider available for auth method: {method_name}"
            )
        
        try:
            # Prevent self-lock
            if user_id == admin_user_id:
                raise ValueError("Cannot lock your own account")
            
            # Only local auth users can be locked
            # SSO users are managed by identity provider
            if auth_method != AuthMethod.LOCAL:
                raise ValueError(
                    f"Cannot lock {auth_method.value} user. "
                    "SSO users must be disabled through identity provider."
                )
            
            # Lock indefinitely (far future date - year 2099)
            locked_until = datetime(2099, 12, 31, tzinfo=UTC)
            
            success = await provider.auth_store.lock_account(user_id, locked_until)
            
            if success:
                # Revoke all active sessions/tokens
                await provider.logout(user_id)
                
                logger.info(f"User {user_id} locked by admin {admin_user_id}. ")
                
            return success

        except ValueError:
            raise
        except Exception as e:
            logger.error(f"Failed to lock user account: {e}")
            return False


    async def unlock_user_account(
        self, 
        user_id: UUID,
        admin_user_id: UUID,
        auth_method: Optional[AuthMethod] = None
        ) -> bool:
        """
        Unlock user account with audit trail.
        
        Business Rules:
        - Only admins can unlock accounts
        - Cannot unlock non-existent users
        
        Args:
            user_id: User to unlock
            admin_user_id: Admin performing action
            
        Returns:
            True if successful
        """
        provider = self.get_provider(auth_method)

        if not provider:
            method_name = auth_method.value if auth_method else self.default_auth_method.value
            raise AuthenticationError(
                f"No provider available for auth method: {method_name}"
            )
        
        try:
            # Reset failed login attempts (unlocks account)
            await provider.auth_store.reset_failed_login(user_id)
            
            logger.info(f"Account unlocked: {user_id} by admin {admin_user_id}")

            return True

        except Exception as e:
            logger.error(f"Failed to unlock account: {e}")
            # return None
            raise AuthenticationError(f"Failed to unlock account: {e}")


    async def update_user_role(
        self,
        user_id: UUID,
        new_role: str,
        admin_user_id: UUID,
        auth_method: Optional[AuthMethod] = None
        ) -> bool:
        """
        Update user role with business rules.
        
        Business Rules:
        - Admins cannot demote themselves
        - Role must be 'admin' or 'user'
        
        Args:
            user_id: User to update
            new_role: New role ('admin' or 'user')
            admin_user_id: Admin performing the action
            
        Returns:
            True if successful
            
        Raises:
            ValueError: If business rule violated
            AuthenticationError: If user not found or provider unavailable
        """
        # Prevent demote self
        if user_id == admin_user_id and new_role != 'admin':
            raise ValueError("Cannot demote your own admin account")
        
        if new_role not in ('admin', 'user'):
            raise ValueError(f"Invalid role: {new_role}. Must be 'admin' or 'user'")
        
        # Delegate to provider
        provider = self.get_provider(auth_method)

        if not provider:
            method_name = auth_method.value if auth_method else self.default_auth_method.value
            raise AuthenticationError(
                f"No provider available for auth method: {method_name}"
            )
        
        success = await provider.update_user_role(user_id, new_role)
        
        if success:
            logger.info(f"User role updated: {user_id} → {new_role} by {admin_user_id}")
        
        return success


    async def update_user_status(
        self,
        user_id: UUID,
        is_active: bool,
        admin_user_id: UUID,
        auth_method: Optional[AuthMethod] = None
        ) -> bool:
        """
        Enable or disable user account with business rules.
        
        Business Rules:
        - Admins cannot disable themselves
        
        Args:
            user_id: User to update
            is_active: True to enable, False to disable
            admin_user_id: Admin performing the action
            
        Returns:
            True if successful
            
        Raises:
            ValueError: If business rule violated
            AuthenticationError: If user not found or provider unavailable
        """
        # Prevent disable self
        if user_id == admin_user_id and not is_active:
            raise ValueError("Cannot disable your own admin account")
        
        # Delegate to provider
        provider = self.get_provider(auth_method)

        if not provider:
            method_name = auth_method.value if auth_method else self.default_auth_method.value
            raise AuthenticationError(
                f"No provider available for auth method: {method_name}"
            )
        
        success = await provider.update_user_status(user_id, is_active)
        
        if success:
            action = "enabled" if is_active else "disabled"
            logger.info(f"User {action}: {user_id} by {admin_user_id}")
        
        return success


    async def delete_user(
        self,
        user_id: UUID,
        admin_user_id: UUID,
        auth_method: Optional[AuthMethod] = None
        ) -> bool:
        """Permanently delete user account"""
        
        if user_id == admin_user_id and not is_active:
            raise ValueError("Cannot delete your own admin account")
        
        # Delegate to provider
        provider = self.get_provider(auth_method)

        if not provider:
            method_name = auth_method.value if auth_method else self.default_auth_method.value
            raise AuthenticationError(
                f"No provider available for auth method: {method_name}"
            )
        
        success = await provider.delete_user(user_id)
        
        if success:
            logger.info(f"User deleted: {user_id} by {admin_user_id}")
        
        return success


    async def check_mfa(
        self, 
        user_id: UUID,
        auth_method: Optional[AuthMethod] = None
        ) -> bool:
        """
        check if MFA is enabled for a specific user

        Returns:
            True if successful
        """
        # Delegate to store
        provider = self.get_provider(auth_method)
        
        if not provider:
            method_name = auth_method.value if auth_method else self.default_auth_method.value
            raise AuthenticationError(f"No provider available for auth method: {method_name}")
        
        success = await provider.check_mfa(user_id)
        
        if success:
            logger.info(f"MFA cheked for user: {user_id}")
        
        return success


    async def setup_mfa(
        self,
        user_id: UUID,
        secret: str,
        backup_codes: List[str],
        method: str = "totp",
        auth_method: Optional[AuthMethod] = None
    ) -> bool:
        """
        Setup MFA for user.
        
        Business Rules:
        - Admins must enable MFA
        - Secret and codes are validated
        
        Args:
            user_id: User setting up MFA
            secret: TOTP secret (plain text, will be encrypted)
            backup_codes: List of backup codes (will be hashed)
            method: MFA method (totp, sms, email)
            auth_method: specific auth method, or None for default
            
        Returns:
            True if successful
        """
        # Delegate to store (which handles encryption/hashing)
        provider = self.get_provider(auth_method)

        if not provider:
            method_name = auth_method.value if auth_method else self.default_auth_method.value
            raise AuthenticationError(f"No provider available for auth method: {method_name}")
        
        success = await provider.store_mfa_secret(
            user_id=user_id,
            secret=secret,
            backup_codes=backup_codes,
            method=method
        )
        
        if success:
            logger.info(f"MFA setup completed for user: {user_id}")
        
        return success
    

    async def get_mfa_data(
        self,
        # user_id: str,
        user_id: UUID,
        auth_method: Optional[AuthMethod] = None
        ) -> Optional[Dict[str, str]]:
        """
        Get MFA secret for verification
        
        Returns:
            Dict with secret and backup codes if exists
        """
        # Delegate to store
        provider = self.get_provider(auth_method)
        
        if not provider:
            method_name = auth_method.value if auth_method else self.default_auth_method.value
            raise AuthenticationError(f"No provider available for auth method: {method_name}")
        
        mfa_data = await provider.get_mfa_data(user_id)
        
        if mfa_data:
            logger.info(f"MFA secret successfully fetched: {user_id}")
        
        return mfa_data


    async def enable_mfa(
        self,
        user_id: UUID,
        auth_method: Optional[AuthMethod] = None
        ) -> bool:
        """
        Activate MFA after successful verification
            
        Returns:
            True if successful
        """
        # Delegate to store
        provider = self.get_provider(auth_method)
        
        if not provider:
            method_name = auth_method.value if auth_method else self.default_auth_method.value
            raise AuthenticationError(f"No provider available for auth method: {method_name}")
        
        success = await provider.enable_mfa(user_id)
        
        if success:
            logger.info(f"MFA enabled successfully for user: {user_id}")
        
        return success


    async def disable_mfa(
        self, 
        # user_id: str,
        user_id: UUID,
        auth_method: Optional[AuthMethod] = None
        ) -> bool:
        """
        Disable MFA for user.
        
        Args:
            user_id: User to disable MFA for
            auth_method: Specific auth method, or None for default
            
        Returns:
            True if successful
        """
        # Delegate to store
        provider = self.get_provider(auth_method)
        
        if not provider:
            method_name = auth_method.value if auth_method else self.default_auth_method.value
            raise AuthenticationError(f"No provider available for auth method: {method_name}")
        
        success = await provider.disable_mfa(user_id)
        
        if success:
            logger.info(f"MFA disabled for user: {user_id}")
        
        return success


    async def logout(self, user_id: UUID) -> bool:
        """
        Logout user across all providers.
        
        Args:
            user_id: User to logout
            
        Returns:
            True if successful on any provider
        """
        success = False
        
        for provider in self._providers.values():
            try:
                if await provider.logout(user_id):
                    success = True
            except Exception as e:
                logger.error(f"Logout error for provider {provider.provider_name}: {e}")
        
        return success


    async def health_check(self) -> Dict[str, Any]:
        """
        Check health of all registered providers.
        
        Returns:
            Health status for each provider
        """
        health_status = {
            "default_auth_method": self.default_auth_method.value,
            "registered_providers": [],
            "provider_health": {}
        }
        
        for auth_method, provider in self._providers.items():
            health_status["registered_providers"].append({
                "auth_method": auth_method.value,
                "provider_name": provider.provider_name
            })
            
            try:
                provider_health = await provider.health_check()
                health_status["provider_health"][auth_method.value] = provider_health
            except Exception as e:
                logger.error(f"Health check failed for {provider.provider_name}: {e}")
                health_status["provider_health"][auth_method.value] = {
                    "status": "unhealthy",
                    "error": str(e)
                }
        
        # Overall status
        all_healthy = all(
            health.get("status") == "healthy" 
            for health in health_status["provider_health"].values()
        )
        
        health_status["overall_status"] = "healthy" if all_healthy else "degraded"
        
        return health_status
    

    def get_available_auth_methods(self) -> List[str]:
        """Get list of available authentication methods"""
        return [method.value for method in self._providers.keys()]
    
    
    def is_method_available(self, auth_method: str) -> bool:
        """Check if authentication method is available"""
        try:
            method_enum = AuthMethod(auth_method)
            return method_enum in self._providers
        except ValueError:
            return False


# factory pattern
def initialize_auth_manager(auth_store, default_method: str = 'local') -> AuthenticationManager:
    """
    Initialize global authentication manager with providers.
    
    Args:
        auth_store: Auth store instance (SQLite or PostgreSQL)
        default_method: Default authentication method
        
    Returns:
        Initialized AuthenticationManager
    """
    manager = AuthenticationManager(default_auth_method=default_method)
    
    # Register local auth provider
    local_provider = LocalAuthProvider(auth_store)
    manager.register_provider(local_provider)
    
    # TODO: Register SSO providers when implemented
    # if settings.OIDC_ENABLED:
    #     oidc_provider = OIDCAuthProvider(...)
    #     manager.register_provider(oidc_provider)
    
    auth_manager = manager

    logger.info("Authentication manager initialized")
    
    return manager


# Singelton instance
auth_mgr = initialize_auth_manager(
    auth_store=auth_store,
    default_method=settings.auth.DEFAULT_AUTH_METHOD
)