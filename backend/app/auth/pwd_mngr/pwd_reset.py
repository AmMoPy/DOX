# import secrets
# import hashlib
import logging
from uuid import UUID
from typing import Optional, Tuple
from datetime import datetime, timedelta, UTC
from app.config.setting import settings
from app.db.db_factory import auth_store
from app.auth.auth_mngr import auth_mgr
from app.auth.compliance.sec_audit_log import audit_logger
from app.auth.hash_service import TokenHasher, token_hasher
from app.auth.pwd_mngr.pwd_utils import validate_password_strength, hash_password

logger = logging.getLogger(__name__)


class PasswordResetManager:
    """
    Manages password reset tokens and workflow.
    
    Security features:
    - Tokens are cryptographically random (32 bytes)
    - Stored as SHA-256 hashes (never plain text)
    - Time-limited (default 1 hour)
    - Single-use only
    - Rate limited per user
    - Full audit trail
    """
    
    def __init__(self, auth_store, audit_logger, hasher: TokenHasher):
        """
        Initialize password reset manager.
        
        Args:
            auth_store: Auth store for database operations
            audit_logger: Audit logger for security events
        """
        # Inject dependencies
        self.auth_store = auth_store
        self.audit_logger = audit_logger
        self.hasher = hasher
    

    def generate_reset_token(self, length: int) -> Tuple[str, str]:
        """
        Generate secure password reset token.
        
        Returns:
            (raw_token, token_hash) - Raw token for URL, hash for storage
        """
        # generate cryptographically secure random 
        # token and hash token for storage
        raw_token, token_hash = self.hasher.generate_token(length)
        
        return raw_token, token_hash
    

    async def request_password_reset(
        self,
        email: str,
        user_id: Optional[UUID] = None,
        admin: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_data: Optional[dict] = None
    ) -> Tuple[bool, str, Optional[str]]:
        """
        Request/Force password reset.
        
        Args:
            email: User's email address
            user_id: User's ID
            admin: Admin user email forcing the reset
            ip_address: Request source IP
            user_data: Full details of targeted user 
            
        Returns:
            (success, message, token_or_none)
            
        Security notes:
        - Always returns success even if user doesn't exist (prevent enumeration)
        - Rate limited per targeted user (if not forced)
        - Tokens expire after TOKEN_VALIDITY_HOURS
        """
        try:
            if not admin:
                if user_data is None:
                    # Try get user by email
                    # shouldn't reach here if
                    # caller do user validation
                    user_data = await self.auth_store.get_user_by_email(email)
                    
                    # IMPORTANT: Always return success to prevent email enumeration
                    # But only actually create token if user exists
                    if not user_data:
                        logger.warning(f"Password reset requested for non-existent email: {email}")
                        
                        # Log to audit
                        if self.audit_logger:
                            await self.audit_logger.log_event(
                                event_type="password_reset_failed",
                                email=email,
                                ip_address=ip_address,
                                success=False,
                                details={"reason": "user_not_found"}
                            )
                        
                        # Return success but no token (prevents enumeration)
                        return True, "Reset link has been sent to this email", None
                
                user_id = user_data['user_id']
                
                # Check if user is using local auth (SSO users can't reset password here)
                auth_method = user_data['auth_method']

                if auth_method != 'local':
                    logger.warning(
                        f"Password reset attempted for {auth_method} user: {email}"
                    )
                    
                    if self.audit_logger:
                        await self.audit_logger.log_event(
                            event_type="password_reset_failed",
                            user_id=user_id,
                            email=email,
                            ip_address=ip_address,
                            success=False,
                            details={"reason": "sso_user"}
                        )
                    
                    return True, "Reset link has been sent to this email", None
                
                # Check rate limiting
                can_request, reason = await self._check_rate_limit(user_id)
                
                if not can_request:
                    logger.warning(
                        f"Password reset rate limited for user {user_id}: {reason}"
                    )
                    
                    if self.audit_logger:
                        await self.audit_logger.log_event(
                            event_type="password_reset_failed",
                            user_id=user_id,
                            email=email,
                            ip_address=ip_address,
                            success=False,
                            details={"reason": "rate_limited"}
                        )
                    
                    # Still return success message (don't reveal rate limiting)
                    return True, "Reset link has been sent to this email", None
            
            # Generate reset token
            raw_token, token_hash = self.generate_reset_token(settings.auth.TOKEN_LENGTH)
            
            # Store token in database
            expires_at = datetime.now(UTC) + timedelta(hours=settings.auth.TOKEN_VALIDITY_HOURS)
            
            await self.auth_store.store_password_reset_token(
                token_hash=token_hash,
                user_id=user_id,
                expires_at=expires_at,
                ip_address=ip_address
            )
            
            # Log to audit
            if self.audit_logger:
                if admin: 
                    event_type = 'password_reset_forced'
                    details = {
                        "target_user_id": str(user_id),
                        "target_email": email,
                        "admin": admin
                    }
                else:
                    event_type = 'password_reset_requested'
                    details = {"source": 'user request'}

                await self.audit_logger.log_event(
                    event_type= event_type,
                    user_id=user_id, # None if not admin
                    email=email if not admin else admin,
                    ip_address=ip_address,
                    details=details
                )
            
            logger.info(f"Password reset token generated for user {user_id}")
            
            return True, "Reset link has been sent to this email", raw_token
            
        except Exception as e:
            logger.error(f"Password reset request failed: {e}")
            # Return generic success to prevent information leakage
            return True, "Reset link has been sent to this email", None
    

    async def verify_reset_token(
        self,
        raw_token: str
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Verify password reset token.
        
        Args:
            raw_token: Raw token from reset URL
            
        Returns:
            (valid, user_id_or_none, error_message_or_none)
        """
        try:
            # Hash the provided token
            token_hash = self.hasher.hash(raw_token)
            
            # Look up token in database
            token_data = await self.auth_store.get_password_reset_token(token_hash)
            
            if not token_data:
                logger.warning("Invalid password reset token attempted")
                return False, None, "Invalid or expired reset token"
            
            # Check if token has been used
            if token_data.get('used', False):
                logger.warning(
                    f"Used password reset token attempted for user {token_data.get('user_id')}"
                )
                return False, None, "This reset token has already been used"
            
            # Check if token has expired
            expires_at = token_data.get('expires_at') # datetime object
     
            if datetime.now(UTC).replace(microsecond=0) > expires_at:
                logger.warning(
                    f"Expired password reset token attempted for user {token_data.get('user_id')}"
                )
                # Clean up expired token
                await self.cleanup_expired_tokens() # TODO: currently collective shall be targeted clean?

                return False, None, "This reset token has expired"
            
            user_id = token_data.get('user_id')
            logger.info(f"Valid password reset token verified for user {user_id}")
            
            return True, user_id, "Token is valid"
            
        except Exception as e:
            logger.error(f"Token verification failed: {e}")
            return False, None, "Token verification failed"
    

    async def reset_password(
        self,
        email: str,
        raw_token: str,
        new_password: str,
        ip_address: Optional[str] = None
    ) -> Tuple[bool, str]:
        """
        Reset password using valid token
        
        Args:
            email: Requesting user's email
            raw_token: Raw reset token
            new_password: New password (will be validated and hashed)
            ip_address: Request source IP
            
        Returns:
            (success, message)
        
        TODO: Revisit DB hits
        """
        try:
            # Never trust - always verify:
            # Tokens can expire between verification and consumption
            # Tokens can be replayed
            # Users can leave forms open
            # Attackers can manipulate timing
            # TOCTOU (Time-of-Check-to-Time-of-Use) vulnerabilities
            # Attack scenario:
            # 1. Attacker requests password reset for victim@example.com
            # 2. Attacker intercepts/steals reset link (phishing, MITM, etc.)
            # 3. Attacker opens reset link → Endpoint (verify_reset_token) verifies token (valid)
            # 4. Attacker leaves form open for 2 hours
            # 5. Token expires (1 hour validity)
            # 6. Attacker submits new password → Endpoint (reset_password) accepts it (no check!)
            # 7. Account compromised!
            valid, user_id, error = await self.verify_reset_token(raw_token)
            
            if not valid:
                return False, error or "Invalid reset token"
            
            # Get user data
            user_data = await self.auth_store.get_user_by_email(email)

            if not user_data:
                logger.error(f"User {email} not found during password reset")
                
                await audit_logger.log_event(
                    event_type="password_reset_failed",
                    user_id=user_id,
                    email=email,
                    success=False,
                    ip_address=ip_address,
                    details={"reason": "User not found"}
                )

                return False, "User not found"
            
            # Validate new password
            is_valid, validation_message = validate_password_strength(new_password)

            user_id = user_data['user_id']

            if not is_valid:
                logger.warning(
                    f"Password reset failed validation for user {user_id}: {validation_message}"
                )

                await audit_logger.log_event(
                    event_type="password_reset_failed",
                    user_id=user_id,
                    email=email,
                    ip_address=ip_address,
                    success=False,
                    details={"reason": "Invalid new password"}
                )

                return False, validation_message
            
            # Hash new password
            password_hash = hash_password(new_password)
            
            # Update password in database
            await self.auth_store.update_password_hash(user_id, password_hash)
            
            # Mark token as used
            token_hash = self.hasher.hash(raw_token)

            await self.auth_store.delete_password_reset_token(token_hash) # delete better for security and to maintain correct rate limit count
            
            # Reset failed login attempts (fresh start with new password)
            await self.auth_store.reset_failed_login(user_id)

            # Optionally revoke all existing sessions for security
            await auth_mgr.logout(user_id)
            
            # Log to audit
            if self.audit_logger:
                await self.audit_logger.log_event(
                    event_type="password_reset_completed",
                    user_id=user_id,
                    email=email,
                    ip_address=ip_address,
                    success=True,
                    details={"method": "reset_token"}
                )
            
            logger.info(f"Password reset completed successfully for user {user_id}")
            
            return True, "Password reset successful"
            
        except Exception as e:
            logger.error(f"Password reset failed: {e}")
            return False, "Password reset failed. Please try again."
    

    async def _check_rate_limit(self, user_id: UUID) -> Tuple[bool, str]:
        """
        Check if user can request another password reset
        
        Returns:
            (can_request, reason)
        """
        try:
            # Get reset request count in last 24 hours
            since = datetime.now(UTC) - timedelta(days=1)
            count = await self.auth_store.count_password_reset_requests(
                user_id=user_id,
                since=since
            )
            
            if count >= settings.auth.MAX_RESET_REQUESTS_PER_DAY:
                return False, f"Too many reset requests (max {settings.auth.MAX_RESET_REQUESTS_PER_DAY}/day)"
            
            return True, "OK"
            
        except Exception as e:
            logger.error(f"Rate limit check failed: {e}")
            # Fail open for availability
            return True, "OK"
    

    async def cleanup_expired_tokens(self) -> int:
        """
        Clean up expired reset tokens
        
        Returns:
            Number of tokens deleted
        """
        try:
            deleted = await self.auth_store.delete_expired_reset_tokens()
            
            if deleted > 0:
                logger.info(f"Cleaned up {deleted} expired password reset tokens")
            
            return deleted
            
        except Exception as e:
            logger.error(f"Token cleanup failed: {e}")
            return 0
    

    async def revoke_user_tokens(self, user_id: UUID) -> bool:
        """
        Revoke all password reset tokens for a user.
        
        Useful when:
        - User requests cancellation
        - Admin intervention
        - Security incident
        
        Returns:
            True if successful
        """
        try:
            await self.auth_store.revoke_password_reset_tokens(user_id)
            logger.info(f"Revoked all password reset tokens for user {user_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to revoke tokens for user {user_id}: {e}")
            return False


# Global instance
pwd_reset_mngr = PasswordResetManager(auth_store, audit_logger, token_hasher)

# factory patter
def initialize_password_reset_manager(
    auth_store,
    hasher,
    audit_logger=None
) -> PasswordResetManager:
    """
    Initialize password reset manager.
    
    Call during application startup.
    """
    password_reset_manager = PasswordResetManager(auth_store, token_hasher, audit_logger)
    logger.info("Password reset manager initialized")
    return password_reset_manager