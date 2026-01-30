import io
import pyotp
import qrcode
import base64
import logging
from uuid import UUID
from typing import Optional
from datetime import datetime, timedelta, UTC
from collections import defaultdict
from fastapi import APIRouter, HTTPException, Depends, Query, Request, status, Response
from app.models.base_models import (
    User, UserCreate, LoginRequest, LoginResponse, APIKeyCreate, Flex,
    APIKeyResponse, PasswordChange, PasswordResetRequest, PasswordResetVerify, 
    PasswordResetConfirm, TokenRefreshRequest, TokenRefreshResponse, 
    SessionVerifyResponse, MFASetupRequest, MFASetupResponse, 
    MFAVerifyRequest, MFACompleteLoginRequest
    )
from app.config.setting import settings
from app.db.db_factory import auth_store
from app.val.file_val import text_validator
from app.core.rate_limiter import rate_limiter
from app.utils.email_services import email_service
from app.auth.sec_prov.base import (
    AuthenticationRequest, AuthenticationError, 
    InvalidCredentialsError, AccountLockedError,
    AuthMethod, UserIdentity
)
from app.auth.auth_mngr import auth_mgr
from app.auth.pwd_mngr.pwd_reset import pwd_reset_mngr
from app.auth.pwd_mngr.pwd_utils import verify_password
from app.auth.compliance.sec_audit_log import audit_logger
from app.auth.dependencies import get_current_user
from app.auth.mid_ware.csrf import CookieCSRFManager

logger = logging.getLogger(__name__)

# Shared Instances
router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=Flex, status_code=status.HTTP_201_CREATED)
async def register_user(user_data: UserCreate,  request: Request):
    """
    Register new user (always creates 'user' role).
    
    Security: 
     - Password strength, email validation, rate limiting, audit logging
     - Role is hardcoded to 'user' regardless of request body.
     - Generic messages on failed attempts regardless of reasons 
       (Let legitimate users puzzled and others fenced!)
    
    Note: user_data.role is ignored for security. Only admins can promote 
    users to admin via /admin/users/{id}/update-role
    """

    # Rate limiting by IP
    ip_address = request.client.host if request else "unknown"
    
    async with rate_limiter.limit(
        f"register_{ip_address}",
        request_metadata={
            'action': 'register',
            'endpoint': '/auth/register',
            'ip_address': ip_address,
            'user_agent': request.headers.get("User-Agent"),
            'email': user_data.email
        }
    ) as (allowed, reason):

        if not allowed:
            logger.warning(f"Registration rate limited: {ip_address}")
            raise HTTPException(status_code=429, detail="Too many registration attempts")

        try:
            # Input sanitization
            clean_email = text_validator.validate_text(user_data.email.lower(), "query")

            # Validate password for local auth
            if user_data.auth_method == 'local' and not user_data.password:
                
                # report failure
                await rate_limiter.report_operation_result(f"register_{ip_address}", success=False)

                raise HTTPException(
                    status_code=400,
                    detail="Password required"
                )

            # Audit suspicious behavior
            if user_data.role and user_data.role != 'user':
                await audit_logger.log_event(
                    event_type="suspicious_registration_attempt",
                    email=user_data.email,
                    success=False,
                    ip_address=ip_address,
                    details={
                        "attempted_role": user_data.role,
                        "reason": "privilege_escalation_attempt"
                    }
                )

                logger.warning(
                    f"Privilege escalation attempt: {user_data.email} "
                    f"tried to register as '{user_data.role}' from {ip_address}"
                    )
            
            # Create user identity
            identity = UserIdentity(
                user_id="",  # Will be generated
                email=user_data.email,
                role="user", # Force user role (ignore client input - if any)
                auth_method=AuthMethod(user_data.auth_method),
                mfa_enabled=user_data.mfa_enabled,
                sso_id=user_data.sso_id
            )
            
            # Create user through auth manager
            created_user = await auth_mgr.create_user(
                identity,
                password=user_data.password
            )

            # report success
            await rate_limiter.report_operation_result(f"register_{ip_address}", success=True)

            # Audit log
            await audit_logger.log_event(
                event_type="user_created",
                user_id=created_user.user_id,
                email=created_user.email,
                success=True,
                ip_address=ip_address,
                details={
                    "role": created_user.role,
                    "method": user_data.auth_method,
                    "requested_role": user_data.role
                }
            )
            
            logger.info(f"User registered: {created_user.email} ({created_user.role})")
            
            return {
                "message": "User created successfully",
                "user_id": created_user.user_id,
                "email": created_user.email,
                "role": created_user.role
            }
            
        except ValueError as e:
            # Password validation or duplicate email
            raise HTTPException(status_code=400, detail=str(e))
        except Exception as e:
            logger.error(f"Registration failed: {e}")
            raise HTTPException(
                status_code=500,
                detail="Registration failed"
            )


@router.post("/setup", response_model=Flex, include_in_schema=False) # Hide from docs
async def create_initial_admin(user_data: UserCreate, request: Request = None):
    """
    Create initial admin user (ONE-TIME USE).
    
    Security:
    - Only works if no admin exists
    - Disabled after first use
    - Not shown in API documentation

    Note: This endpoint should be disabled/removed in production
    """

    # Rate limit initial admin creation to prevent brute force
    ip_address = request.client.host if request else "unknown"

    async with rate_limiter.limit(
        f"admin_setup_{ip_address}",
        request_metadata={
            'action': 'admin_setup',
            'endpoint': '/admin/setup',
            'ip_address': ip_address
        }
    ) as (allowed, reason):
        if not allowed:
            raise HTTPException(status_code=429, detail="Too many setup attempts")

        # Check if admin creation is allowed
        if not settings.auth.ALLOW_ADMIN_CREATION:
            # report failure
            await rate_limiter.report_operation_result(f"admin_setup_{ip_address}", success=False)
            
            # log details
            logger.info("Admin creation is disabled.")
            
            # use generic message
            raise HTTPException(status_code=403, detail="Setup failed")

        # Check if any admin exists (call DB)
        try:
            users = await auth_store.list_users(role='admin', limit=1)

            if users:
                # Automatically disable further admin creation
                settings.auth.ALLOW_ADMIN_CREATION = False
                
                # report failure
                await rate_limiter.report_operation_result(f"admin_setup_{ip_address}", success=False)

                logger.info("Admin user already exists.")

                raise HTTPException(status_code=403, detail="Setup failed")

            # all checks failed, create admin
            identity = UserIdentity(
                user_id="",
                email=user_data.email,
                role='admin',
                auth_method=AuthMethod.LOCAL,
                mfa_enabled=user_data.mfa_enabled
            )
            
            created_user = await auth_mgr.create_user(
                identity,
                password=user_data.password
            )

            # Disable further admin creation
            settings.auth.ALLOW_ADMIN_CREATION = False

            # report success
            await rate_limiter.report_operation_result(f"admin_setup_{ip_address}", success=True)

            logger.info(f"Initial admin created via setup endpoint: {created_user.email}")
            
            return {
                "message": "Admin user created successfully",
                "user_id": created_user.user_id,
                "email": created_user.email,
                "note": "This endpoint should be disabled in production"
            }
        
        except HTTPException:
            raise
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        except Exception as e:
            logger.error(f"Admin setup failed: {e}")
            raise HTTPException(
                status_code=500,
                detail="Admin setup failed"
            )


@router.post("/login", response_model=LoginResponse)
async def login(
    response: Response,
    login_data: LoginRequest,
    request: Request = None
):
    """
    Login with httpOnly cookie-based authentication
    
    Security features:
    - Account lockout after 5 failed attempts
    - Failed login tracking
    - IP address logging
    - User agent tracking
    - MFA verification for enabled accounts
    - Main session tokens are hashed and stored in httpOnly cookies (not accessible to JavaScript)
    - CSRF token generated and returned
    - Automatic CSRF protection for subsequent requests
    
    Returns:
        If MFA disabled: User information and CSRF token
        If MFA enabled: Temporary token requiring MFA verification
    """

    # Rate limiting by IP
    ip_address = request.client.host if request else "unknown"
    user_agent = request.headers.get("User-Agent") if request else None

    # Input sanitization
    clean_username = text_validator.validate_text(login_data.email, "query")

    async with rate_limiter.limit(
        f"login_{ip_address}", 
        request_metadata={
            'action': 'login',
            'endpoint': '/auth/login',
            'ip_address': ip_address,
            'user_agent': user_agent,
            'username': clean_username
        }
    ) as (allowed, reason):

        if not allowed:

            await audit_logger.log_event(
                event_type="rate_limit_exceeded",
                email=clean_username,
                success=False,
                ip_address=ip_address,
                details={"reason": reason}
            )

            # Accept status code leakage for better UX and pattern detection
            raise HTTPException(status_code=429, detail="Busted")

        try:
            # Create authentication request
            auth_request = AuthenticationRequest(
                username=clean_username,
                password=login_data.password,
                ip_address=ip_address,
                user_agent=user_agent
            )
            
            # Authenticate user
            identity = await auth_mgr.authenticate(auth_request, AuthMethod.LOCAL)
            
            # Check if user has MFA enabled
            user_id = identity.user_id
            email = identity.email
            
            if identity.mfa_enabled:
                # Create temporary session (5 minutes) for MFA verification
                # restricted via path check in dependencies
                duration = timedelta(minutes=5)
                temp_session = await auth_mgr.create_session(
                    user_id=user_id,
                    timedelta=duration,
                    mfa_verified= False, # triggers MFA checkpoint
                    ip_address=ip_address,
                    user_agent=user_agent,
                    )

                # Set httpOnly cookies with CSRF token
                csrf_token = CookieCSRFManager.set_auth_cookies(
                    response=response,
                    access_token=temp_session['access_token'],
                    expires_in=duration.seconds # this only works for hours/minutes in timedelta, use .total_seconds() if passing days (real nasty bug!)
                )
                                
                # Report successful password verification
                await rate_limiter.report_operation_result(f"login_{ip_address}", success=True)
                
                logger.info(f"MFA required for login: {email}")
                
                # FastAPI handles JSON serialization 
                # status code 200 is default
                return LoginResponse(
                    mfa_required=True,
                    csrf_token=csrf_token,
                    expires_in=duration.seconds,
                    user={ # minimal details for UI, only return full when MFA verified 
                        "email": email
                    }
                )

            # No MFA - create both access and refresh tokens
            duration = timedelta(hours=8) # access token duration
            refresh_days = 30 # refresh token duration

            tokens = await auth_mgr.create_session_with_refresh(
                user_id=identity.user_id,
                timedelta=duration,
                expires_days=refresh_days,
                ip_address=ip_address,
                user_agent=user_agent
            )
 
            # Set httpOnly cookies with CSRF token
            csrf_token = CookieCSRFManager.set_auth_cookies(
                response=response,
                access_token=tokens['access_token'],
                expires_in=duration.seconds,
                refresh_token=tokens['refresh_token'],
                refresh_in=refresh_days * 24 * 3600
            )

            # report success
            await rate_limiter.report_operation_result(f"login_{ip_address}", success=True)

            # Audit log success
            await audit_logger.log_event(
                event_type="login_success",
                user_id=user_id,
                email=email,
                success=True,
                ip_address=ip_address,
                user_agent=user_agent
            )

            logger.info(f"Login successful: {email} from {ip_address}")

            return LoginResponse(
                mfa_required=False,
                csrf_token=csrf_token,
                expires_in=tokens['expires_in'],  # access_token expire hours in seconds
                user={
                    "user_id": str(user_id), # UUID -> STR
                    "email": email,
                    "role": identity.role,
                    "auth_method": identity.auth_method.value,
                    "mfa_enabled": identity.mfa_enabled
                }
            )
        
        # Still inside context manager. rate limits not released yet
        except InvalidCredentialsError as e: # Audit logged in local provider
            # report failure
            await rate_limiter.report_operation_result(f"login_{ip_address}", success=False)
            raise HTTPException(
                status_code=401,
                detail="Something fishy"
            )

        except AccountLockedError as e:
            # report failure
            await rate_limiter.report_operation_result(f"login_{ip_address}", success=False)
            raise HTTPException(
                status_code=403,
                detail="Nauty"
            )

        except AuthenticationError as e:
            logger.error(f"Authentication method not available: {e}")
            # report failure
            await rate_limiter.report_operation_result(f"login_{ip_address}", success=False)
            # audit log
            await audit_logger.log_event(
                event_type="login_failed",
                email=clean_username,
                success=False,
                ip_address=ip_address,
                user_agent=user_agent,
                details={"reason": "auth method not found"}
            )
            raise HTTPException(
                status_code=400, # keep it generic instead of 501
                detail="Unrecognized"
            )

        except Exception as e:
            logger.error(f"Login failed: {e}")
            # report failure
            await rate_limiter.report_operation_result(f"login_{ip_address}", success=False)
            # audit log
            await audit_logger.log_event(
                event_type="login_failed",
                email=clean_username,
                success=False,
                ip_address=ip_address,
                user_agent=user_agent,
                details={"reason": "unexpected login error"}
            )
            raise HTTPException(
                status_code=500,
                detail="Chill and retry!"
            )


@router.post("/logout", response_model=dict)
async def logout(
    response: Response,
    current_user: User = Depends(get_current_user),
    request: Request = None
    ):
    """Revokes all active sessions for the user"""
    try:
        success = await auth_mgr.logout(current_user.user_id)

        # Clear cookies
        CookieCSRFManager.clear_auth_cookies(response)
        
        if success:
            ip_address = request.client.host if request else "unknown"
            
            await audit_logger.log_event(
                event_type="logout",
                user_id=current_user.user_id,
                email=current_user.email,
                success=success,
                ip_address=ip_address
            )

            logger.info(f"User logged out: {current_user.email}")
            return {"message": "Logged out successfully"}
        else:
            logger.warning(f"Logout partially failed for: {current_user.email}")
            return {"message": "Logged out (some sessions may remain active)"}
            
    except Exception as e:
        logger.error(f"Logout error for {current_user.user_id}: {e}")
        # Don't fail logout on errors
        return {"message": "Logout completed with errors"}


@router.post("/refresh-token", response_model=TokenRefreshResponse)
async def refresh_token(
    response: Response,
    request: Request = None
):
    """
    Refresh access token
    """
    try:
        ip_address = request.client.host if request else "unknown"
        
        # Get refresh token from httpOnly cookie
        refresh_token = CookieCSRFManager.get_refresh_token(request)

        if not refresh_token:
            raise HTTPException(
                status_code=401,
                detail="Refresh token missing"
            )

        # Refresh session (includes token rotation)
        duration = timedelta(hours=8)
        refresh_days = 30

        tokens = await auth_mgr.refresh_session(
            refresh_token=refresh_token,
            timedelta=duration,
            expires_days=refresh_days,
            ip_address=ip_address
        )
        
        if not tokens.get('expires_in'): # either no user data or invalid new refresh token
            # Audit suspicious activity
            await audit_logger.log_event(
                event_type="token_refresh_failed",
                user_id=tokens.get('user_id', 'no user'),
                email=tokens.get('email', 'no user'),
                success=False,
                ip_address=ip_address,
                details={
                    "reason": "invalid_refresh_token"
                }
            )

            # Clear cookies on failed refresh
            CookieCSRFManager.clear_auth_cookies(response)

            raise HTTPException(status_code=401, detail="Invalid refresh token")
        
        # Audit successful refresh
        await audit_logger.log_event(
            event_type="token_refresh_success",
            user_id=tokens['user_id'],
            email=tokens['email'],
            success=True,
            ip_address=ip_address
        )

        # Set new cookies
        csrf_token = CookieCSRFManager.set_auth_cookies(
            response=response,
            access_token=tokens['access_token'],
            expires_in=duration.seconds,
            refresh_token=tokens['refresh_token'],
            refresh_in=refresh_days * 24 * 3600
        )

        return TokenRefreshResponse(
            csrf_token=csrf_token,
            expires_in=tokens['expires_in']  # access_token expire hours in seconds
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Token refresh failed: {e}")
        raise HTTPException(status_code=401, detail="Token refresh failed")


@router.get("/verify-session", response_model=SessionVerifyResponse)
async def verify_session(current_user: User = Depends(get_current_user)):
    """
    Check if session is still valid using user ID
    
    Returns session info without refreshing token
    """
    try:
        # Get session details
        session_info = await auth_store.get_session_info(current_user.user_id)
        
        if not session_info:
            raise HTTPException(status_code=401, detail="No sessions found")

        current_time = datetime.now(UTC).replace(microsecond=0)

        return SessionVerifyResponse(
            valid=True if session_info['expires_at'] > current_time else False,
            user_id=current_user.user_id,
            email=current_user.email,
            expires_at=session_info['expires_at'].isoformat()
        )

    except Exception as e:
        logger.error(f"Session verification failed: {e}")
        return SessionVerifyResponse(valid=False)


@router.post("/change-password", response_model=dict)
async def change_password(
    password_data: PasswordChange,
    current_user: User = Depends(get_current_user),
    request: Request = None
):
    """Change current user's password with audit logging"""

    # Rate limit by user ID
    ip_address = request.client.host if request else "unknown"

    async with rate_limiter.limit(
        current_user.user_id,
        request_metadata={
            'action': 'password_change',
            'endpoint': '/auth/change-password',
            'ip_address': ip_address,
            'user_agent': request.headers.get("User-Agent") if request else None
        }
    ) as (allowed, reason):

        if not allowed:
            raise HTTPException(status_code=429, detail=reason)
       
        try:       
            # Check if user is using local auth
            if current_user.auth_method != 'local':

                # report failure
                await rate_limiter.report_operation_result(current_user.user_id, success=False)

                raise HTTPException(
                    status_code=400,
                    detail=f"Password change not supported for {current_user.auth_method} authentication"
                )

            # Change password
            success = await auth_mgr.change_password(
                user_id=current_user.user_id,
                old_password=password_data.old_password,
                new_password=password_data.new_password
            )
            
            if not success:

                # report failure
                await rate_limiter.report_operation_result(current_user.user_id, success=False)

                await audit_logger.log_event(
                    event_type="password_change_failed",
                    user_id=current_user.user_id,
                    email=current_user.email,
                    success=False,
                    ip_address=ip_address
                )

                raise HTTPException(
                    status_code=400,
                    detail="Password change failed"
                )

            # report success
            await rate_limiter.report_operation_result(current_user.user_id, success=True)

            # Audit log success
            await audit_logger.log_event(
                event_type="password_changed",
                user_id=current_user.user_id,
                email=current_user.email,
                success=True,
                ip_address=ip_address
            )

            logger.info(f"Password changed for user: {current_user.email}")
            
            return {"message": "Password changed successfully"}
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Password change failed for {current_user.user_id}: {e}")
            raise HTTPException(
                status_code=500,
                detail="Password change failed."
            )


@router.post("/reset-password/request")
async def request_password_reset(
    request_data: PasswordResetRequest, 
    request: Request = None
    ):
    """Request password reset with rate limiting"""

    ip_address = request.client.host if request else "unknown"
    clean_email = text_validator.validate_text(request_data.email.lower(), "query")

    async with rate_limiter.limit(
        f"pwd_reset_{ip_address}",
        request_metadata={
            'action': 'password_reset',
            'endpoint': '/auth/reset-password/request',
            'ip_address': ip_address,
            'user_agent': request.headers.get("User-Agent") if request else None
        }
    ) as (allowed, reason):
        # hidden rate limit, always return same message even if rate limited
        # to prevent email enumeration
        if not allowed:
            return {"message": "Reset link has been sent to this email"}

        try:
            success, message, token = await pwd_reset_mngr.request_password_reset(
                email=clean_email,
                ip_address=ip_address
            )
            
            # Send email if token was generated
            if token:
                to_email = request_data.email
                
                email_sent = await email_service.send_password_reset_email(
                    to_email=to_email,
                    reset_token=token,
                    user_name=to_email.split('@')[0] 
                )
                
                if email_sent:
                    # report success
                    await rate_limiter.report_operation_result(f"pwd_reset_{ip_address}", success=True)
                else:
                    logger.error(f"Failed to send password reset email to {request_data.email}")
                    # report failure
                    await rate_limiter.report_operation_result(f"pwd_reset_{ip_address}", success=False)
            
            # Always return success (prevent email enumeration)
            return {"message": "Reset link has been sent to this email"}
            
        except Exception as e:
            logger.error(f"Password reset request failed: {e}")
            return {"message": "Reset link has been sent to this email"}


@router.post("/reset-password/verify")
async def verify_reset_token(
    verify_data: PasswordResetVerify,
    request: Request = None
    ):
    """
    Verify if a password reset token is valid
    
    Used by frontend to check token before showing reset form

    Important Note: this is just for UX and NOT A SECURITY FEATURE
    another validation is done before actual reset flow
    """
    try:
        # Verify token (non-consuming, for UX)
        valid, user_id, error = await pwd_reset_mngr.verify_reset_token(verify_data.token)
        
        if not valid:
            # report failure
            email = verify_data.email
            ip_address = request.client.host if request else "unknown"

            await rate_limiter.report_operation_result(email, success=False)

            await audit_logger.log_event(
                event_type="password_reset_failed",
                email=email,
                success=False,
                ip_address=ip_address,
                details={"reason": error}
            )

            raise HTTPException(
                status_code=400,
                detail="Invalid or expired reset token"
            )
        
        return {
            "valid": valid,
            "message": error
        }
        
    except Exception as e:
        logger.error(f"Token verification failed: {e}")
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired reset token"
        )


@router.post("/reset-password/confirm")
async def complete_password_reset(
    reset_data: PasswordResetConfirm,
    request: Request = None
):
    """Complete password reset using token"""
    email = reset_data.email
    ip_address = request.client.host if request else "unknown"
    
    async with rate_limiter.limit(
        email,
        request_metadata={
            'action': 'password_reset_confirm',
            'endpoint': '/auth/reset-password/confirm',
            'ip_address': ip_address
        }
    ) as (allowed, reason):
        if not allowed:
            raise HTTPException(status_code=429, detail="Too many attempts")

        try:
            # Complete the password reset
            success, message = await pwd_reset_mngr.reset_password(
                email=email,
                raw_token=reset_data.token,
                new_password=reset_data.new_password,
                ip_address=ip_address
            )
            
            if not success:
                # report failure
                await rate_limiter.report_operation_result(email, success=False)

                await audit_logger.log_event(
                    event_type="password_reset_failed",
                    email=email,
                    success=False,
                    ip_address=ip_address,
                    details={"reason": message}
                )

                raise HTTPException(status_code=400, detail=message)
            
            # report success
            await rate_limiter.report_operation_result(email, success=True)

            return {
                "message": "Password reset successfully. Please sign in with your new password."
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Password reset completion failed: {e}")
            raise HTTPException(
                status_code=500,
                detail="Password reset failed"
            )


@router.get("/mfa/{user_id}/status")
async def check_mfa_status(user_id: UUID):
    """Check if MFA is enabled"""
    try:
        return await auth_mgr.check_mfa(user_id)
 
    except Exception as e:
        logger.error(f"Failed to check MFA: {e}")
        raise HTTPException(status_code=500, detail="Failed to check MFA")


@router.post("/mfa/setup", response_model=MFASetupResponse)
async def setup_mfa(
    setup_request: MFASetupRequest,
    current_user: User = Depends(get_current_user),
    request: Request = None
):
    """Setup MFA (TOTP)"""
    try:
        # Only local auth users can setup MFA
        auth_method = AuthMethod(current_user.auth_method)

        if auth_method.value != 'local':
            raise HTTPException(
                status_code=400,
                detail=f"MFA not supported for {auth_method.value} authentication"
            )

        user_id = current_user.user_id
        user_email = current_user.email

        # Generate TOTP secret
        secret = pyotp.random_base32()
        
        # Create TOTP URI for QR code
        totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=user_email,
            issuer_name="DOX"
        )
        
        # Generate QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        img_buffer = io.BytesIO()
        img.save(img_buffer, format='PNG')
        img_buffer.seek(0)
        qr_code_base64 = base64.b64encode(img_buffer.getvalue()).decode()
        
        # Generate backup codes
        backup_codes = [pyotp.random_base32()[:8] for _ in range(10)] # each code has constrained length of 8
        
        # Store MFA secret
        success = await auth_mgr.setup_mfa(
            user_id=user_id,
            secret=secret,
            backup_codes=backup_codes,
            method="totp",
            auth_method = auth_method
        )

        if not success:
            raise HTTPException(status_code=500, detail="MFA setup failed")
        
        # Audit log
        await audit_logger.log_event(
            event_type="mfa_setup",
            user_id=user_id,
            email=user_email,
            success=True,
            ip_address=request.client.host if request else "unknown",
            details={"method": "totp"}
        )
        
        return MFASetupResponse(
            secret=secret,
            qr_code=f"data:image/png;base64,{qr_code_base64}",
            backup_codes=backup_codes
        )
    
    except AuthenticationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"MFA setup failed: {e}")
        raise HTTPException(status_code=500, detail="MFA setup failed")


@router.post("/mfa/verify")
async def verify_mfa(
    verify_request: MFAVerifyRequest,
    current_user: User = Depends(get_current_user),
    request: Request = None
):
    """Verify TOTP code and enable MFA during setup"""

    ip_address = request.client.host if request else "unknown"

    async with rate_limiter.limit(
        current_user.user_id,
        request_metadata={
            'action': 'mfa_verify',
            'endpoint': '/auth/mfa/verify',
            'ip_address': ip_address
        }
    ) as (allowed, reason):
        if not allowed:
            raise HTTPException(status_code=429, detail="Too many MFA attempts")

        try:
            user_id = current_user.user_id
            email = current_user.email

            # verify MFA code
            success, method, remaining_backup_codes = await _veriy_mfa_codes(
                user_id=user_id, 
                tracking_id=str(user_id), # UUID -> STR
                ip_address=ip_address,
                mfa_code=verify_request.code,
                email=email
            )

            # enable MFA
            enabled = await auth_mgr.enable_mfa(user_id)

            if success and enabled:
                # report success
                await rate_limiter.report_operation_result(user_id, success=True)

                # Audit log
                await audit_logger.log_event(
                    event_type="mfa_verified",
                    user_id=user_id,
                    email=email,
                    success=True,
                    ip_address=ip_address
                )
                
                return {
                    "message": "MFA verified successfully", 
                    "valid": True,
                    "method": method
                    }
            
        except HTTPException:
            raise


@router.post("/mfa/complete-login", response_model=LoginResponse)
async def complete_mfa_login(
    response: Response,
    request_data: MFACompleteLoginRequest,
    request: Request = None
):
    """
    Complete MFA login after password verification
    
    Security:
    - Verifies temporary session token
    - Validates MFA code (TOTP or backup code)
    - Creates full session with refresh token
    - Revokes temporary session
    
    Args:
        request_data:
            mfa_code: 6-digit TOTP code or backup code
            use_backup_code: True if using backup code instead of TOTP
            temp_token: Temporary session token from initial login (optional if not HTTPOnly)

    Returns:
        Full session tokens and user info
    """
    ip_address = request.client.host if request else "unknown"
    user_agent = request.headers.get("User-Agent") if request else None
    tracking_id = f"mfa_login_{ip_address}"
    
    # Rate limit MFA attempts
    async with rate_limiter.limit(
        tracking_id,
        request_metadata={
            'action': 'mfa_complete_login',
            'endpoint': '/auth/mfa/complete-login',
            'ip_address': ip_address,
            'user_agent': user_agent
        }
    ) as (allowed, reason):
        if not allowed:
            raise HTTPException(status_code=429, detail="Too many MFA attempts")

        try:
            # Input validation
            clean_code = text_validator.validate_text(request_data.mfa_code.strip(), "query")
            
            temp_token = CookieCSRFManager.get_session_token(request)

            if not temp_token:
                raise HTTPException(
                    status_code=401,
                    detail="Temporary access token missing"
                )

            # Verify temporary session
            temp_session = await auth_mgr.verify_session(temp_token)
            
            if not temp_session:                
                await rate_limiter.report_operation_result(tracking_id, success=False)
                
                await audit_logger.log_event(
                    event_type="mfa_login_failed",
                    success=False,
                    ip_address=ip_address,
                    details={"reason": "invalid_temp_session"}
                )

                # Clear cookies on failed verification
                CookieCSRFManager.clear_auth_cookies(response, True)
                
                raise HTTPException(
                    status_code=401,
                    detail="Invalid or expired MFA session. Please login again."
                )
            
            user_id = temp_session['user_id']
            email = temp_session['email']
            
            # verify MFA code
            success, method, remaining_backup_codes = await _veriy_mfa_codes(
                user_id=user_id, 
                tracking_id=tracking_id,
                ip_address=ip_address,
                mfa_code=clean_code,
                use_backup_code=request_data.use_backup_code,
                email=email
            )

            if success:   
                # Revoke temporary MFA session
                await auth_mgr.revoke_session(
                    session_id=temp_session['session_id']
                )

                # Create full session with refresh token
                duration = timedelta(hours=8) # access token duration
                refresh_days = 30 # refresh token duration

                tokens = await auth_mgr.create_session_with_refresh(
                    user_id=user_id,
                    timedelta=duration,
                    ip_address=ip_address,
                    user_agent=user_agent
                )
                
                # Set httpOnly cookies with CSRF token
                csrf_token = CookieCSRFManager.set_auth_cookies(
                    response=response,
                    access_token=tokens['access_token'],
                    expires_in=duration.seconds,
                    refresh_token=tokens['refresh_token'],
                    refresh_in=refresh_days * 24 * 3600
                )
                
                await rate_limiter.report_operation_result(user_id, success=True)
                
                # Audit log success
                await audit_logger.log_event(
                    event_type="mfa_login_success",
                    user_id=user_id,
                    email=email,
                    success=True,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    details={
                        "method": method,
                        "backup_codes_remaining": remaining_backup_codes,
                        "tracking_id": f"{csrf_token[:10]}_{user_id}"
                    }
                )
                
                logger.info(f"MFA login completed: {email} from {ip_address}")

                return LoginResponse(
                    mfa_required=False,
                    csrf_token=csrf_token,
                    expires_in=tokens['expires_in'],
                    user={
                        "user_id": str(user_id),
                        "email": email,
                        "role": temp_session['role'],
                        "auth_method": temp_session['auth_method'],
                        "mfa_enabled": temp_session['mfa_enabled']
                    }
                )
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"MFA login failed: {e}")
            raise HTTPException(
                status_code=500,
                detail="MFA login failed. Please try again."
            )

@router.delete("/mfa/disable")
async def disable_my_mfa(
    current_user: User = Depends(get_current_user),
    request: Request = None
):
    """Disable MFA for user"""

    try:
        user_id = current_user.user_id
        email = current_user.email
        auth_method = AuthMethod(current_user.auth_method)

        # Delete MFA configuration
        success = await auth_mgr.disable_mfa(
            user_id=user_id,
            auth_method = auth_method 
        )

        if not success:
            raise HTTPException(status_code=500, detail="MFA disable failed")
        
        # Audit log
        await audit_logger.log_event(
            event_type="mfa_disabled",
            user_id=user_id,
            email=email,
            success=True,
            ip_address=request.client.host if request else "unknown"
        )
        
        logger.info(f"MFA disabled: {email}")
        
        return {"message": "MFA disabled successfully"}
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except AuthenticationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"MFA disable failed: {e}")
        raise HTTPException(status_code=500, detail="MFA disable failed")


@router.post("/api-keys", response_model=APIKeyResponse)
async def create_api_key(
    key_data: APIKeyCreate,
    current_user: User = Depends(get_current_user),
    request: Request = None
):
    """Create API key for current user"""

    ip_address = request.client.host if request else "unknown"

    async with rate_limiter.limit(
        current_user.user_id,
        request_metadata={
            'action': 'api_key_create',
            'endpoint': '/auth/api-keys',
            'ip_address': ip_address
        }
    ) as (allowed, reason):
        if not allowed:
            raise HTTPException(status_code=429, detail=reason)

        try:
            # Validate key name
            clean_name = text_validator.validate_text(key_data.name, "title")

            key = await auth_store.create_api_key(
                user_id=current_user.user_id,
                name=clean_name,
                scopes=key_data.scopes,
                expires_days=key_data.expires_days # 30 days default
            )

            # Audit log
            await audit_logger.log_event(
                event_type="api_key_created",
                user_id=current_user.user_id,
                email=current_user.email,
                success=True,
                ip_address=ip_address,
                details={"key_name": clean_name, "scopes": key_data.scopes}
            )

            logger.info(
                f"API key created: {clean_name} for {current_user.email} "
            )

            # report success
            await rate_limiter.report_operation_result(current_user.user_id, success=True)
            
            return APIKeyResponse(**key)
            
        except Exception as e:
            logger.error(f"API key creation failed: {e}")
            raise HTTPException(status_code=500, detail="Failed to create API key")


@router.get("/api-keys")
async def list_my_api_keys(current_user: User = Depends(get_current_user)):
    """List current user's API keys (without actual key values)"""

    try:
        keys = await auth_store.list_user_api_keys(current_user.user_id)
        
        # Remove actual key values for security
        safe_keys = [
            {k: v for k, v in key.items() if k != 'key'}
            for key in keys
        ]

        return {"api_keys": safe_keys}
        
    except Exception as e:
        logger.error(f"Failed to list API keys: {e}")
        raise HTTPException(status_code=500, detail="Failed to list API keys")


@router.delete("/api-keys/{key_id}")
async def revoke_my_api_key(
    key_id: UUID,
    current_user: User = Depends(get_current_user),
    request: Request = None
):
    """Revoke API key"""

    try:
        await auth_store.revoke_api_key(key_id, current_user.user_id)
        
        # Audit log
        await audit_logger.log_event(
            event_type="api_key_revoked",
            user_id=current_user.user_id,
            email=current_user.email,
            success=True,
            ip_address=request.client.host if request else "unknown",
            details={"key_id": str(key_id)}
        )

        logger.info(f"API key revoked: {key_id} by {current_user.email}")
        
        return {"message": "API key revoked successfully"}
        
    except Exception as e:
        logger.error(f"Failed to revoke API key: {e}")
        raise HTTPException(status_code=500, detail="Failed to revoke API key")


@router.get("/my-activity-stats")
async def get_my_activity_stats(
    request: Request,
    hours: int = Query(168, ge=1, le=720),
    current_user: User = Depends(get_current_user)
):
    """
    Utilizing audit logs for tracking activity statistics 
    for current user with hourly and daily trends 
    Single DB query, multiple aggregations in Python
    """
    try:
        start_date = datetime.now(UTC) - timedelta(hours=hours)

        # single database query to get all events
        events = await audit_logger.get_mini_audit_history(
            user_id=current_user.user_id,
            start_date=start_date,
            limit=1000 # hard limit
        )
        
        # In-memory aggregation (fast for <1000 events)
        # TODO: offload to db?  
        hourly_stats = defaultdict(lambda: {
            'searches': 0, 'ai_queries': 0, 'uploads': 0, 'logins': 0, 'total': 0
        })
        daily_stats = defaultdict(lambda: {
            'searches': 0, 'ai_queries': 0, 'uploads': 0, 'logins': 0, 'total': 0
        })
        
        # Single pass through events - O(n) where n = events count
        recent_activities = []
        for idx, event in enumerate(events):
            timestamp = event['timestamp']
            event_type = event['event_type']
            
            # Generate keys for aggregation
            hour_key = timestamp.strftime('%Y-%m-%d %H:00:00')
            day_key = timestamp.strftime('%Y-%m-%d')
            
            # Increment hourly/daily stats
            # capturing all events regardless
            # of categorizatio
            hourly_stats[hour_key]['total'] += 1
            daily_stats[day_key]['total'] += 1

            if event_type == 'search':
                hourly_stats[hour_key]['searches'] += 1
                daily_stats[day_key]['searches'] += 1
            elif event_type == 'ai_query':
                hourly_stats[hour_key]['ai_queries'] += 1
                daily_stats[day_key]['ai_queries'] += 1
            elif event_type == 'upload_success':
                hourly_stats[hour_key]['uploads'] += 1
                daily_stats[day_key]['uploads'] += 1
            elif event_type == 'login_success':
                hourly_stats[hour_key]['logins'] += 1
                daily_stats[day_key]['logins'] += 1
            
            # Collect recent activities (first 20)
            if idx < 20:
                recent_activities.append({
                    "type": event_type,
                    # "timestamp": dt.isoformat(),
                    "timestamp": timestamp.isoformat(),
                    "details": event['details'],
                    "success": event['success']
                })
        
        # Build hourly data for line chart
        activities_by_hour = []
        total_hours = min(hours, 168)  # Cap at 7 days for hourly view
        
        for i in range(total_hours):
            dt = datetime.now(UTC) - timedelta(hours=i)
            period_key = dt.strftime('%Y-%m-%d %H:00:00')
            period_label = dt.strftime('%H:%M')
            
            stats = hourly_stats.get(period_key, {
                'searches': 0, 'ai_queries': 0, 'uploads': 0, 'total': 0
            })
            
            # filter: Only include if has activity
            # cleaner charts, less data transfer.
            if stats['total'] > 0:
                activities_by_hour.append({
                    "datetime": period_key,
                    "label": period_label,
                    "searches": stats['searches'],
                    "ai_queries": stats['ai_queries'],
                    "uploads": stats['uploads'],
                    "count": stats['total']
                })
        
        # Reverse to show oldest to newest
        activities_by_hour.reverse()
        
        # Build daily data for bar chart
        activities_by_day = []
        days = hours // 24 + 1
        
        for i in range(days - 1, -1, -1):
            dt = datetime.now(UTC) - timedelta(days=i)
            period_key = dt.strftime('%Y-%m-%d')
            period_label = dt.strftime('%a')
            
            stats = daily_stats.get(period_key, {
                'searches': 0, 'ai_queries': 0, 'uploads': 0, 'total': 0
            })
            
            # filter
            if stats['total'] > 0:
                activities_by_day.append({
                    "date": period_key,
                    "day": period_label,
                    "searches": stats['searches'],
                    "ai_queries": stats['ai_queries'],
                    "uploads": stats['uploads'],
                    "count": stats['total']
                })
        
        # Calculate totals
        total_searches = sum(s['searches'] for s in daily_stats.values())
        total_ai_queries = sum(s['ai_queries'] for s in daily_stats.values())
        total_uploads = sum(s['uploads'] for s in daily_stats.values())
        total_logins = sum(s['logins'] for s in daily_stats.values())
        # total_activities = len(events)
        total_activities = sum(s['total'] for s in daily_stats.values())

        return {
            "period_hours": hours,
            "total_searches": total_searches,
            "total_ai_queries": total_ai_queries,
            "total_uploads": total_uploads,
            "total_logins": total_logins,
            "total_activities": total_activities, # all including categorized
            "recent_activities": recent_activities,
            "activities_by_hour": activities_by_hour,
            "activities_by_day": activities_by_day,
            "user_id": str(current_user.user_id), # UUID -> STR
            "user_email": current_user.email,
            "timestamp": datetime.now(UTC).isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to get user activity stats: {e}")
        return {
            "period_hours": hours,
            "total_searches": 0,
            "total_ai_queries": 0,
            "total_uploads": 0,
            "total_logins": 0,
            "total_activities": 0,
            "recent_activities": [],
            "activities_by_hour": [],
            "activities_by_day": [],
            "user_id": str(current_user.user_id),
            "user_email": current_user.email,
            "timestamp": datetime.now(UTC).isoformat(),
            "error": "Failed to load activity stats"
        }


@router.get("/me", response_model=User)
async def get_current_user_info(current_user: User = Depends(get_current_user)):
    """Get current user information"""
    # return current_user
    return {
        'user_id':str(current_user.user_id), # UUID -> STR
        'email':current_user.email,
        'role':current_user.role,
        'auth_method':current_user.auth_method,
        'mfa_enabled':current_user.mfa_enabled,
        'scopes':current_user.scopes
    }


# Helper functions

async def _veriy_mfa_codes(
    user_id: UUID, 
    tracking_id: str,
    ip_address: str,
    mfa_code: str, 
    use_backup_code: bool = False, 
    email: Optional[str] = None
    ) -> bool:
    """"verify MFA codes and update database"""
    
    try:
        # get MFA secret
        mfa_data = await auth_mgr.get_mfa_data(user_id)
        
        if not mfa_data:
            # report failure
            await rate_limiter.report_operation_result(tracking_id, success=False)

            raise HTTPException(status_code=404, detail="MFA not configured")
        
        # trackers
        is_valid = False
        matched_backup_code = None
        remaining_backup_codes = None

        if use_backup_code:
            # Verify backup code
            backup_codes = mfa_data.get('backup_codes', [])
            
            if not backup_codes:
                raise HTTPException(
                    status_code=400,
                    detail="No backup codes available"
                )

            # update count
            remaining_backup_codes = len(backup_codes)

            # sequential with early exit (bcrypt comparison)
            # TODO: Still problematic, revisit
            for hashed_code in backup_codes:
                if verify_password(mfa_code, hashed_code):
                    is_valid = True
                    matched_backup_code = hashed_code
                    remaining_backup_codes -= 1
                    # Early exit creates timing side-channel
                    # But bcrypt is inherently slow, 
                    # so position leak is minor
                    break

        else:
            # Verify TOTP code (fast - no hashing)
            totp = pyotp.TOTP(mfa_data['secret'])
            is_valid = totp.verify(mfa_code, valid_window=3) # use wider window for testing/debuging, turn back to 1 or do NTP sync for proper security

        # log used method for tracking
        mfa_method = "backup_code" if use_backup_code else ("totp")

        if not is_valid:
            # report failure (both failed)
            await rate_limiter.report_operation_result(tracking_id, success=False)

            await audit_logger.log_event(
                event_type="mfa_verification_failed",
                user_id=tracking_id,
                email=email if email else None,
                success=False,
                ip_address=ip_address,
                details={
                    "reason": "invalid_code",
                    "method": mfa_method
                }
            )

            raise HTTPException(status_code=401, detail="Invalid MFA code")

        # Remove code + update timestamp (COMBINED)
        if matched_backup_code:
            await auth_store.remove_backup_code(user_id, matched_backup_code)
        else:
            # TOTP verified, just update timestamp
            await auth_store.update_mfa_verification(user_id)

        return True, mfa_method, remaining_backup_codes

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"MFA verification failed: {e}")
        raise HTTPException(status_code=500, detail="MFA verification failed")