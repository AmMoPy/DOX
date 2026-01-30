import logging
from typing import Optional
from fastapi import Header, HTTPException, Depends, Request, Query, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from app.models.base_models import User
from app.db.db_factory import auth_store
from app.core.rate_limiter import rate_limiter
from app.auth.auth_mngr import auth_mgr
from app.auth.mid_ware.csrf import CookieCSRFManager
from app.auth.compliance.sec_audit_log import audit_logger

logger = logging.getLogger(__name__)

# Keep HTTPBearer for header based authentication (optional)
# 1. Read the Authorization header automatically
# 2. Parse it specifically for the Bearer <token> format
# 3. Return a structured object (HTTPAuthorizationCredentials) 
# containing the scheme ("Bearer") and the credentials (the raw token string)
security = HTTPBearer(auto_error=False)


async def get_current_user(
    request: Request, # No default needed, FastAPI auto-injects
    sse_token: Optional[str] = Query(None, description="Temporary SSE session token"),
    x_api_key: Optional[str] = Header(None),
    # authorization: Optional[str] = Header(None),
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> User:
    """
    Multi-auth dependency with priority, prefers httpOnly cookies 
    over Authorization header
    
    For SSE connections only, parse token from query parameter, 
    as EventSource API doesn't support custom headers, so token 
    must be in URL thus the need for exposing a "temp" token other
    than that of main session.

    Note: httpOnly was added at a later stage, this caller was kept 
    as is to support both legacy header-based and new cookie auth approache

    Authentication priority:
    1. SSE token (query param) - for EventSource connections
    2. Session cookie (httpOnly) - for web sessions
    3. API key (header) - for service-to-service
    4. Bearer token (header) - for legacy/mobile clients

    Args:
        sse_token: Read token directly from Query url (legacy) 
        X-API-Key header: API key for service-to-service
        authorization header: Bearer token for web sessions (deprecated)
        credentials: substitute for authorization param eliminating manual header parsing
    
    Raises:
        HTTPException: If authentication credentials invalid or expired
    """
    try:
        # priority for EventSource connections (explicitly requested via query param)
        # browser AUTOMATICALLY sends cookies (same-origin default behavior)
        # must be first as EventSource follows same-origin policy by default
        # this is to ensure that sse check triggers when same-origin policy is enforced 
        if sse_token:
            user_data = await auth_store.verify_session(sse_token)
            auth_source = "sse_token"

            # revoke temporary SSE session immediately after auth so if token
            # is stolen subsequent call to the stream endpoint using the same token
            # is declined as the SSE connection is already established after 
            # authentication. once the HTTP connection is open, it doesn't re-authenticate.
            # introduction of cookies eliminate the need for token in headers BUT I like current flow!
            if user_data:
                # revoke
                await auth_mgr.revoke_session(
                    session_id=user_data['session_id']
                )

                # Audit log usage for forensics
                await audit_logger.log_event(
                    event_type="sse_token_used",
                    user_id=user_data['user_id'],
                    email=user_data['email'],
                    success=True
                )
        # main check httpOnly cookie (most secure)
        # := walrus (python 3.8+) operator is an assignment expression, 
        # assigns a value to a variable and returns the value of that assignment
        # unlike = assignment operator that just binds a name to a value. 
        # Benefit arises where objects (token) are needed twice, 
        # first test if token exists then use again to verify session.
        elif token := CookieCSRFManager.get_session_token(request):
            # CSRF is validated by middleware for POST/PUT/DELETE
            # GET requests (like SSE) skip CSRF check
            user_data = await auth_store.verify_session(token)
            auth_source = "session_cookie"
        # fallback: check API key first  
        elif x_api_key:
            user_data = await auth_store.verify_api_key(x_api_key)
            auth_source = 'api_key'
        # check bearer headers (legacy)
        elif credentials and credentials.scheme == "Bearer":
            token = credentials.credentials
            user_data = await auth_store.verify_session(token)
            auth_source = "bearer"
        # elif authorization and authorization.startswith('Bearer '):
        #     token = authorization.replace('Bearer ', '')
        #     user_data = await auth_store.verify_session(token)
        else: # all checks failed, reject
            raise HTTPException(
                status_code=401,
                detail="No authentication credentials provided"
            )        

        # verification failed, reject
        if not user_data:
            logger.error(f"session validation failed for {request.method} {request.url.path} {auth_source} source")
            raise HTTPException(
                status_code=401,
                detail="Invalid or expired credentials"
            )
            
        # Only allow /auth/mfa/* endpoints for MFA-pending sessions when not using API keys
        elif not x_api_key and (user_data['mfa_enabled'] and not user_data['mfa_verified']):
            if not request.url.path.startswith('/api/auth/mfa/'):
                raise HTTPException(
                    status_code=403,
                    detail="MFA verification required"
                )

        # sucess
        user = User(
            user_id=user_data['user_id'], # UUID
            email=user_data['email'],
            role=user_data['role'],
            auth_method=user_data['auth_method'],
            mfa_enabled=user_data['mfa_enabled'],
            scopes=user_data.get('scopes', _get_default_scopes(user_data['role']))
        )

        # store in context for router-level dependencies
        request.state.current_user = user

        return user
   
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            f"Unexpected session validation error for {request.method} {request.url.path}: {e}",
            # exc_info=True  # Include stack trace
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Invalid or missing authentication credentials"
        )


async def get_current_user_optional(
    request: Request,
    sse_token: Optional[str] = Query(None),
    x_api_key: Optional[str] = Header(None),
    # authorization: Optional[str] = Header(None),
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> Optional[User]:
    """Optional authentication - returns None if not authenticated"""
    try:
        return await get_current_user(request, sse_token, x_api_key, credentials)
    except HTTPException:
        return None


async def require_admin(current_user: User = Depends(get_current_user)) -> User:
    """Require admin role"""
    if current_user.role != 'admin':

        user_id = current_user.user_id
        email = current_user.email

        # report failure
        await rate_limiter.report_operation_result(user_id, success=False)

        # log the imposter
        await audit_logger.log_event(
            event_type="unauthorized_access_attempt",
            user_id=user_id,
            email=email,
            success=False,
            details={
                "user_role": current_user.role,
                "auth_method": current_user.auth_method,
                "user_scope": current_user.scope,
                "imposter": "admin"
            }
        )

        logger.warning(
            f"Non-admin user attempted admin access: {current_user.email}"
        )

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required"
        )
    return current_user

 # "dependency factory" (or a "curried function"). 
 # It separates the generic authentication logic from 
 # the specific authorization logic required for a particular endpoint.
def require_scope(required_scope: str):
    """Require specific scope"""
    # This inner function is the actual FastAPI dependency
    def scope_checker(current_user: User = Depends(get_current_user)) -> User:
        if required_scope not in current_user.scopes and current_user.role != 'admin':
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Scope '{required_scope}' required"
            )
        return current_user
    # The outer function returns the dependency factory
    return scope_checker


# Helper functions

def _get_default_scopes(role: str) -> list[str]:
    """Get default scopes based on user role"""
    if role == 'admin':
        return ['search', 'ask', 'upload', 'admin']
    else:
        return ['search', 'ask']