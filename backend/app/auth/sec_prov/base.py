"""
Authentication provider abstraction layer.

This interface allows the RAG system to support multiple authentication
methods (local, OIDC, SAML) without changing application code.
"""

from uuid import UUID
from enum import Enum
from dataclasses import dataclass
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any


class AuthMethod(str, Enum):
    """Supported authentication methods"""
    LOCAL = "local"
    OIDC = "oidc"
    SAML = "saml"
    API_KEY = "api_key"


@dataclass
class UserIdentity:
    """
    Protocol-agnostic user identity.
    
    This standardized format works with any authentication method,
    allowing seamless switching between local auth and SSO.
    """
    user_id: UUID
    email: str
    role: str  # 'admin' or 'user'
    auth_method: AuthMethod
    mfa_enabled: bool
    auth_provider: Optional[str] = None  # e.g., 'google', 'microsoft', 'okta'
    
    # SSO-specific fields
    sso_id: Optional[str] = None  # Unique ID from SSO provider
    sso_attributes: Dict[str, Any] = None  # Raw claims/attributes from SSO
    
    # Additional user attributes
    display_name: Optional[str] = None
    scopes: list[str] = None
    
    def __post_init__(self):
        if self.sso_attributes is None:
            self.sso_attributes = {}
        if self.scopes is None:
            self.scopes = []


@dataclass
class AuthenticationRequest:
    """Encapsulates authentication request data"""
    # For password-based auth
    username: Optional[str] = None
    password: Optional[str] = None
    
    # For token-based auth
    token: Optional[str] = None
    
    # For SSO callbacks
    sso_code: Optional[str] = None
    sso_state: Optional[str] = None
    
    # Request context
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None


class AuthenticationProvider(ABC):
    """
    Abstract base class for all authentication providers.
    
    This interface ensures consistent authentication behavior regardless
    of the underlying protocol (local passwords, OIDC, SAML).
    """
    
    @property
    @abstractmethod
    def auth_method(self) -> AuthMethod:
        """Return the authentication method this provider handles"""
        pass
    
    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Return human-readable provider name"""
        pass
    
    @abstractmethod
    async def authenticate(self, request: AuthenticationRequest) -> Optional[UserIdentity]:
        """
        Authenticate user and return identity if successful.
        
        Args:
            request: Authentication request with credentials
            
        Returns:
            UserIdentity if authentication successful, None otherwise
        """
        pass
    
    @abstractmethod
    async def get_user_by_id(self, user_id: UUID) -> Optional[UserIdentity]:
        """
        Retrieve user identity by user ID.
        
        Args:
            user_id: Unique user identifier
            
        Returns:
            UserIdentity if found, None otherwise
        """
        pass
    
    @abstractmethod
    async def get_user_by_email(self, email: str) -> Optional[UserIdentity]:
        """
        Retrieve user identity by email.
        
        Args:
            email: User email address
            
        Returns:
            UserIdentity if found, None otherwise
        """
        pass
    
    @abstractmethod
    async def create_user(self, identity: UserIdentity, **kwargs) -> UserIdentity:
        """
        Create new user (for local auth or JIT provisioning).
        
        Args:
            identity: User identity to create
            **kwargs: Additional provider-specific parameters
            
        Returns:
            Created UserIdentity
        """
        pass
    
    @abstractmethod
    async def update_user_attributes(self, user_id: UUID, attributes: Dict[str, Any]) -> bool:
        """
        Update user attributes (for SSO attribute sync).
        
        Args:
            user_id: User to update
            attributes: New attributes to set
            
        Returns:
            True if successful, False otherwise
        """
        pass
    
    @abstractmethod
    async def logout(self, user_id: UUID) -> bool:
        """
        Logout user (revoke sessions/tokens).
        
        Args:
            user_id: User to logout
            
        Returns:
            True if successful, False otherwise
        """
        pass
    
    @abstractmethod
    async def health_check(self) -> Dict[str, Any]:
        """
        Check provider health and availability.
        
        Returns:
            Health status dictionary
        """
        pass
    
    async def supports_password_change(self) -> bool:
        """Whether this provider supports password changes"""
        return False
    
    async def change_password(self, user_id: UUID, old_password: str, new_password: str) -> bool:
        """
        Change user password (local auth only).
        
        Args:
            user_id: User whose password to change
            old_password: Current password for verification
            new_password: New password to set
            
        Returns:
            True if successful, False otherwise
        """
        raise NotImplementedError("Password change not supported by this provider")


class AuthenticationError(Exception):
    """Base exception for authentication errors"""
    pass


class InvalidCredentialsError(AuthenticationError):
    """Raised when credentials are invalid"""
    pass


class AccountLockedError(AuthenticationError):
    """Raised when account is locked due to failed attempts"""
    pass


class ProviderNotConfiguredError(AuthenticationError):
    """Raised when SSO provider is not properly configured"""
    pass


class ProviderUnavailableError(AuthenticationError):
    """Raised when SSO provider is temporarily unavailable"""
    pass