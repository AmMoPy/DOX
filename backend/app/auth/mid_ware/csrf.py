import secrets
import logging
from typing import Optional, Callable
from fastapi import Request, HTTPException, status
from fastapi.responses import Response
from app.config.setting import settings
from app.auth.hash_service import TokenHasher, token_hasher
from app.auth.compliance.sec_audit_log import audit_logger

logger = logging.getLogger(__name__)

class CookieCSRFManager:
    """
    Manages httpOnly cookies and CSRF protection
    
    Security Features:
    - httpOnly cookies (prevents XSS token theft)
    - Secure flag (HTTPS only in production)
    - SameSite=Lax (CSRF protection)
    - Double Submit Cookie pattern for CSRF
    """
    
    # Cookie names
    SESSION_COOKIE = "session_token"
    REFRESH_COOKIE = "refresh_token"
    CSRF_COOKIE = "csrf_token"
    
    # Cookie configuration
    COOKIE_DOMAIN = settings.server.COOKIE_DOMAIN if hasattr(settings.server, 'COOKIE_DOMAIN') else None
    COOKIE_SECURE = settings.server.COOKIE_SECURE  # Ensure is set to "True" for HTTPS only in production
    # when a request is made to a specific domain, the browser automatically attaches all relevant cookies 
    # for that domain, regardless of which website the request originated from, unless SameSite=Strict is 
    # set, or the attack is a simple GET/HEAD ("safe" HTTP methods) request when SameSite=Lax is the default 
    # but not when state changing methods are used (POST/PUT/DELETE....).
    COOKIE_SAMESITE = "lax"  # Prevents CSRF while allowing normal navigation (balanced) while "Strict" is maximum security (no cookies from cross site)
    
    @classmethod
    def generate_csrf_token(cls, hasher:TokenHasher, **kwargs) -> str:
        """Generate cryptographically secure CSRF token"""
        return hasher.generate_token(**kwargs)
    
    @classmethod
    def set_auth_cookies(
        cls,
        response: Response,
        access_token: str,
        expires_in: int,
        refresh_token: Optional[str] = None,
        refresh_in: Optional[int] = None,
    ) -> str:
        """
        Set authentication cookies with security headers
        
        Args:
            response: FastAPI response object
            access_token: JWT access token
            refresh_token: JWT refresh token
            expires_in: Expiration time in seconds

        security features:
            - Primary session tokens are protected from 
            Cross-Site Scripting (XSS) attacks using httpOnly cookie
            - Requests are protected from Cross-Site Request Forgery (CSRF) 
            using CSRF token to be used in custom request header by frontend

            However, nothing is really "protected"! 
            
        """
        # Generate CSRF token and hash
        csrf_token, csrf_token_hash = cls.generate_csrf_token(token_hasher, length = 32)

        # Set access token (httpOnly, shorter expiry)
        response.set_cookie(
            key=cls.SESSION_COOKIE,
            value=access_token,
            max_age=expires_in,
            httponly=True,  # Prevents JavaScript access
            secure=cls.COOKIE_SECURE,  # HTTPS only in production
            samesite=cls.COOKIE_SAMESITE,
            domain=cls.COOKIE_DOMAIN,
            path="/"
        )
        
        # Set refresh token (httpOnly, longer expiry)
        if refresh_token:
            response.set_cookie(
                key=cls.REFRESH_COOKIE,
                value=refresh_token,
                max_age=refresh_in,
                httponly=True,
                secure=cls.COOKIE_SECURE,
                samesite=cls.COOKIE_SAMESITE,
                domain=cls.COOKIE_DOMAIN,
                path="/api/auth/refresh-token"  # Only sent to refresh endpoint "scope by path"
            )

        # using both hashed and raw token for request verification handles both standard CSRF attacks 
        # and provides significant mitigation if an XSS vulnerability exists elsewhere in the APP. This 
        # does not protect if an attacker has already compromised the APP entirely using same-site XSS. 
        # rather it changes what information the attacker can access and where they can use it. Minimizing 
        # the impact of potential minor data leaks, even if a full XSS compromise still bypasses the system.

        # The attacker can get the raw token via XSS, but they can only use the raw token in 
        # same-site requests (using XSS context), or they can use the hash in a cross-site request 
        # (using CSRF mechanism), but they cannot combine the two (the browser enforces the Rules).
        # He would have two options: A) abuse the XSS vulnerability directly (Same-Site Attack), reading
        # _raw cookie value via document.cookie (httponly=False) then use that raw value to set the 
        # X-CSRF-Token header using an AJAX request (RIP CSRF check!), XSS vulnerability defeats CSRF protection.
        # B) Tries a CSRF Attack (Cross-Site Attack): trick the browser into sending the HttpOnly: True cookie 
        # (the hash) BUT 1) cannot read hash or raw token via JavaScript. 2) cannot set the custom X-CSRF-Token header
        # without browser pre-flight checks (CORS) that would be blocked, so server's verification missing X-CSRF-Token 
        # custom header = blocked request...YAAY!

        # Store CSRF HASH in httpOnly cookie (server-side verification)
        response.set_cookie(
            key=cls.CSRF_COOKIE,
            value=csrf_token_hash,
            max_age=expires_in,
            httponly=True,  # lock
            secure=cls.COOKIE_SECURE,
            samesite=cls.COOKIE_SAMESITE,
            domain=cls.COOKIE_DOMAIN,
            path="/"
        )

        # Set raw CSRF token (NOT httpOnly - needs to be read by JavaScript for X-CSRF-Token header)
        response.set_cookie(
            key=f"{cls.CSRF_COOKIE}_raw", # ensure client reads correct key
            value=csrf_token,
            max_age=expires_in,
            httponly=False,  # JavaScript needs to read this
            secure=cls.COOKIE_SECURE,
            samesite=cls.COOKIE_SAMESITE,
            domain=cls.COOKIE_DOMAIN,
            path="/"
        )

        logger.info("Auth cookies set successfully")

        return csrf_token
    
    @classmethod
    def clear_auth_cookies(cls, response: Response, temp_session: bool = False) -> None:
        """Clear all authentication cookies"""
        if not temp_session:
            cookies = [cls.SESSION_COOKIE, cls.REFRESH_COOKIE, cls.CSRF_COOKIE]
        else:
            cookies = [cls.SESSION_COOKIE, cls.CSRF_COOKIE]
        
        for cookie_name in cookies:
            # When setting or deleting a cookie, the key, domain, 
            # and path must all align exactly with the original 
            # cookie intended to modify
            response.delete_cookie(
                key=cookie_name,
                path="/" if not cookie_name == "refresh_token" else "/api/auth/refresh-token",
                domain=cls.COOKIE_DOMAIN,
                secure=cls.COOKIE_SECURE,
                samesite=cls.COOKIE_SAMESITE
            )
        logger.info("Auth cookies cleared")
    
    @classmethod
    def get_session_token(cls, request: Request) -> Optional[str]:
        """Extract session token from httpOnly cookie"""
        return request.cookies.get(cls.SESSION_COOKIE)
    
    @classmethod
    def get_refresh_token(cls, request: Request) -> Optional[str]:
        """Extract refresh token from httpOnly cookie"""
        return request.cookies.get(cls.REFRESH_COOKIE)
    
    @classmethod
    async def validate_csrf_token(cls, request: Request) -> bool:
        """
        Validate CSRF token using Double Submit Cookie pattern
        
        Security: Compares hashed cookie value with header value.
        Attacker can't read cookies due to same-origin policy.
        
        Args:
            request: FastAPI request object
            
        Returns:
            True if CSRF token is valid
            
        Raises:
            HTTPException: If CSRF validation fails
        """
        # Skip CSRF for safe methods
        if request.method in ["GET", "HEAD", "OPTIONS"]:
            return True

        # Whitelist auth endpoints that don't have tokens yet to bypass CSRF midware 
        # Login/register endpoints use Basic Auth (credentials in header)
        # CSRF doesn't apply to credential-based auth (no ambient authority)
        # Once logged in, subsequent requests use CSRF
        CSRF_EXEMPT_PATHS = [
            "/api/auth/login",
            "/api/auth/register",
            "/api/auth/reset-password/request",
            "/api/auth/reset-password/verify",
            "/api/auth/reset-password/confirm",
            "/api/auth/mfa/complete-login",
            "/api/auth/refresh-token", # User's session expired -> CSRF token invalid, can't validate old CSRF token for a refresh operation
            "/api/auth/setup"  # Initial admin creation
        ]

        if any(request.url.path.startswith(path) for path in CSRF_EXEMPT_PATHS):
            return True  # SKIP CSRF for these
        
        # Skip CSRF in development for certain endpoints (optional)
        if settings.server.DEBUG and request.url.path.startswith("/docs"):
            return True
        
        # Get CSRF token from cookie
        csrf_cookie = request.cookies.get(cls.CSRF_COOKIE)
        
        # Get CSRF token from header
        csrf_header = request.headers.get("X-CSRF-Token")

        # Validate
        if not csrf_cookie:

            request_method = request.method
            request_url = request.url.path
            user_agent = request.headers.get("User-Agent")

            logger.warning(f"CSRF cookie missing for {request_method} {request_url}")

            # log suspicious pattern
            await audit_logger.log_event( # TODO: enrich
                event_type="csrf_missing",
                success=False,
                ip_address=request.client.host,
                details={
                    "method": request_method,
                    "url_path": request_url,
                    "user_agent": user_agent
                }
            )

            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="CSRF token missing"
            )
        
        if not csrf_header:
            logger.warning(f"CSRF header missing for {request.method} {request.url.path}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="CSRF token required in X-CSRF-Token header"
            )
    
        # Hash the header token and compare with cookie hash
        csrf_hash = token_hasher.hash(csrf_header)

        # if not secrets.compare_digest(csrf_cookie, csrf_header):
        if not secrets.compare_digest(csrf_cookie, csrf_hash): # hashed versions
            
            ip_address = request.client.host
            request_method = request.method
            request_url = request.url.path
            user_agent = request.headers.get("User-Agent")

            logger.warning(
                f"CSRF token mismatch from {ip_address} "
                f"for {request_method} {request_url}"
            )

            # log potential attack
            await audit_logger.log_event(
                event_type="csrf_mismatch",
                success=False,
                ip_address=ip_address,
                details={
                    "method": request_method,
                    "url_path": request_url,
                    "user_agent": user_agent
                }
            )

            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="CSRF token invalid"
            )
        
        return True


# Middleware for automatic CSRF validation
async def csrf_midware(request: Request, call_next: Callable) -> Response:
    """
    Global CSRF protection middleware
    
    Validates CSRF tokens for all state-changing requests
    """
    try:
        # Validate CSRF token
        await CookieCSRFManager.validate_csrf_token(request)
        
        # Process request
        # call_next: the middleware passes the current request 
        # object down the pipeline to the next piece of middleware 
        # or, eventually, to the final route handler.
        # ensure it is called before return response
        response = await call_next(request)
        return response
        
    except HTTPException as e:
        # Re-raise HTTPException for proper error handling
        raise
    except Exception as e:
        logger.error(f"CSRF middleware error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Security validation failed"
        )
