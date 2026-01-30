import re
import bcrypt
import logging
from typing import Tuple, Optional
from datetime import datetime, timedelta, UTC
from app.config.setting import settings

logger = logging.getLogger(__name__)


class PasswordPolicy:
    """Password policy configuration and validation"""

    # O(n) string scans -> O(1) hash lookups
    SPECIAL_CHARS_SET = set(settings.sec.PASSWORD_SPECIAL_CHARS)
    
    # Pre-compile regex patterns for performance
    UPPERCASE_REGEX = re.compile(r'[A-Z]')
    LOWERCASE_REGEX = re.compile(r'[a-z]')
    DIGIT_REGEX = re.compile(r'\d')


    @classmethod
    def validate_password_strength(cls, password: str) -> Tuple[bool, str]:
        """
        Validate password against security policy.
        
        Returns:
            (is_valid, error_message)
        """
        if not password:
            return False, "Password cannot be empty"
        
        if len(password) < settings.sec.PASSWORD_MIN_LENGTH:
            return False, f"Password must be at least {settings.sec.PASSWORD_MIN_LENGTH} characters"
        
        if len(password) > settings.sec.PASSWORD_MAX_LENGTH:
            return False, f"Password must not exceed {settings.sec.PASSWORD_MAX_LENGTH} characters"
        
        # Check for common weak passwords
        if password.lower() in settings.sec.COMMON_PASSWORDS:
            return False, "Password is too common and easily guessable"
        
        # Check complexity requirements 
        if settings.sec.PASSWORD_REQUIRE_UPPERCASE and not cls.UPPERCASE_REGEX.search(password):
            return False, "Password must contain at least one uppercase letter"
        
        if settings.sec.PASSWORD_REQUIRE_LOWERCASE and not cls.LOWERCASE_REGEX.search(password):
            return False, "Password must contain at least one lowercase letter"
        
        if settings.sec.PASSWORD_REQUIRE_DIGIT and not cls.DIGIT_REGEX.search(password):
            return False, "Password must contain at least one digit"
        
        if settings.sec.PASSWORD_REQUIRE_SPECIAL and not any(c in cls.SPECIAL_CHARS_SET for c in password):
            return False, f"Password must contain at least one special character ({settings.sec.PASSWORD_SPECIAL_CHARS})"
        
        # Check for sequential characters (weak pattern)
        if cls._has_sequential_chars(password):
            return False, "Password contains sequential characters (e.g., 'abc', '123')"
        
        return True, "Password meets security requirements"
    

    @staticmethod
    def _has_sequential_chars(password: str, length: int = 3) -> bool:
        """Check for sequential characters like 'abc' or '123'"""
        password_lower = password.lower()
        
        for i in range(len(password_lower) - length + 1):
            substr = password_lower[i:i + length]
            
            # Check if all chars are sequential
            if all(ord(substr[j+1]) - ord(substr[j]) == 1 for j in range(length - 1)):
                return True
        
        return False


class PasswordHasher:
    """Secure password hashing using bcrypt"""

    @classmethod
    def hash_password(cls, password: str) -> str:
        """
        Hash password using bcrypt.
        
        Args:
            password: Plain text password
            
        Returns:
            Hashed password string
        """
        if not password:
            raise ValueError("Password cannot be empty")
        
        # Convert to bytes and hash
        password_bytes = password.encode('utf-8')
        salt = bcrypt.gensalt(rounds=settings.sec.BCRYPT_ROUNDS)
        hashed = bcrypt.hashpw(password_bytes, salt)
        
        # Return as string for database storage
        return hashed.decode('utf-8')
    

    @classmethod
    def verify_password(cls, password: str, password_hash: str) -> bool:
        """
        Verify password against stored hash.
        
        Args:
            password: Plain text password to verify
            password_hash: Stored bcrypt hash
            
        Returns:
            True if password matches, False otherwise
        """
        if not password or not password_hash:
            return False
        
        try:
            password_bytes = password.encode('utf-8')
            hash_bytes = password_hash.encode('utf-8')
            # bcrypt.checkpw performs a constant-time 
            # comparison of the hashed passwords making it
            # more resistant to timing attacks
            return bcrypt.checkpw(password_bytes, hash_bytes)
            
        except Exception as e:
            logger.error(f"Password verification error: {e}")
            return False


class AccountLockoutManager:
    """Manage account lockout after failed login attempts"""
    
    @classmethod
    def should_lock_account(cls, failed_attempts: int) -> bool:
        """Check if account should be locked"""
        return failed_attempts >= settings.sec.MAX_FAILED_ATTEMPTS
    

    @classmethod
    def calculate_lockout_until(cls) -> datetime:
        """Calculate when account lockout should expire"""
        return datetime.now(UTC) + timedelta(minutes=settings.sec.LOCKOUT_DURATION_MINUTES)
    

    @classmethod
    def is_account_locked(cls, locked_until: Optional[datetime]) -> bool:
        """Check if account is currently locked"""
        if not locked_until:
            return False

        return datetime.now(UTC).replace(microsecond=0) < locked_until
    
    @classmethod
    def should_reset_attempts(cls, last_failed_attempt: Optional[datetime]) -> bool:
        """Check if failed attempts should be reset"""
        if not last_failed_attempt:
            return False
        
        reset_time = last_failed_attempt + timedelta(minutes=settings.sec.RESET_ATTEMPTS_AFTER_MINUTES)
        
        return datetime.now(UTC).replace(microsecond=0) > reset_time


# Convenience functions for use in auth stores
def hash_password(password: str) -> str:
    """Hash a password securely"""
    return PasswordHasher.hash_password(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Verify password against hash"""
    return PasswordHasher.verify_password(password, password_hash)


def validate_password_strength(password: str) -> Tuple[bool, str]:
    """Validate password strength"""
    return PasswordPolicy.validate_password_strength(password)