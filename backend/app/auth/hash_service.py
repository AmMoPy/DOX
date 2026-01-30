import hashlib
import secrets
import logging
from uuid import uuid4, UUID
from typing import Tuple, Protocol
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)

# Protocl vs ABC
# TokenHasher(ABC) - Abstract Base Class that requires:
# Subclass inheritance
# Explicit @abstractmethod decorators
# Runtime enforcement (can't instantiate without implementing all methods)
# TokenHasher(Protocol) - Structural Typing that allows:
# Any class with matching methods (duck typing)
# No inheritance required
# Static type checking only (mypy)
# More flexible
# Protocl provides type safety while allowing maximum flexibility.
class TokenHasher(Protocol):
    """Defines Interface for token hashing strategies"""
    
    def hash(value: str) -> str:
        """Hash a token/key for storage"""
        ...
    
    def generate_token(length: int = 32) -> Tuple[str, str]:
        """Generate random token and its hash"""
        ...
    
    def generate_id() -> UUID:
        """Generate random ID"""
        ...


class SHA256TokenHasher:
    """
    Centralized token and hash generation service using SHA-256

    Provides consistent hashing and token generation across the system
    All token/key/ID generation should go through this service

    Used for:
    - Session tokens
    - API keys
    - Refresh tokens
    - Password reset tokens
    
    NOT used for:
    - Passwords (uses bcrypt via PasswordHasher)
    - MFA secrets (uses Fernet via MFAEncryption)
    """
    
    def hash(self, value: str) -> str:
        """
        Hash a token/key for storage.
        
        Args:
            value: Raw token/key to hash
            
        Returns:
            SHA-256 hex digest
        """
        if not value:
            raise ValueError("Cannot hash empty value")
        
        return hashlib.sha256(value.encode()).hexdigest()
    

    def generate_token(self, length: int = 32, with_hash: bool = True) -> Tuple[str, str]:
        """
        Generate cryptographically secure random token.
        
        Args:
            length: Number of random bytes (default 32 = 43 char URL-safe string)
            
        Returns:
            (raw_token, hashed_token) tuple
            - raw_token: URL-safe base64 string (return to user ONCE)
            - hashed_token: SHA-256 hash (store in database)
        """
        raw_token = secrets.token_urlsafe(length) # CSPRNG

        if with_hash:
            # hash is a one-way function, cannot reverse 
            # a hash to reveal the original raw token
            hashed_token = self.hash(raw_token)
            
            return raw_token, hashed_token
        else:
            return raw_token


    def generate_id(self) -> UUID:
        """
        Generate random UUID for database primary keys.
        
        Better than using secretes:
            - Universal Uniqueness
            - Database Native Support (PostgreSQL)
            - Multi-Database Compatibility (SQLite (TEXT type))

        Returns:
            UUID - 128-bit identifiers (36 characters as a string)
        """
        return uuid4() # return raw CSPRNG uuid object, database drivers will handle conversion
    

    def verify_token(self, raw_token: str, stored_hash: str) -> bool:
        """
        Verify token against stored hash.
        
        Args:
            raw_token: Token to verify
            stored_hash: Hash from database
            
        Returns:
            True if token matches hash
        """
        if not raw_token or not stored_hash:
            return False
        
        try:
            computed_hash = self.hash(raw_token)
            # Use constant-time comparison to prevent timing attacks
            return secrets.compare_digest(computed_hash, stored_hash)
        except Exception as e:
            logger.error(f"Token verification error: {e}")
            return False


# Global instance (can be swapped with different hasher)
token_hasher: TokenHasher = SHA256TokenHasher()