import logging
from typing import Callable
from fastapi import Request, Response
from starlette.types import ASGIApp
from starlette.middleware.base import BaseHTTPMiddleware
from app.auth.hash_service import token_hasher


logger = logging.getLogger(__name__)


class CSPNonceMiddleware(BaseHTTPMiddleware):
    """
    Content Security Policy middleware with nonce generation.

    The Content Security Policy is a security contract established 
    when the INITIAL HTML document loads. Every single piece of 
    JavaScript code that runs on that page must adhere to the rules.

    Generates unique nonces for:
    - Inline scripts (including SolidJS event handlers)
    - Inline styles (including Tailwind utilities)
    
    The nonce (number used once) is:
    1. Generated per request (cryptographically random)
    2. Stored in request.state for template access
    3. Added to CSP header
    4. Injected into HTML
    """
    
    def __init__(self, app: ASGIApp, enable_hsts: bool = True):
        super().__init__(app)
        self.enable_hsts = enable_hsts
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Generate cryptographically secure nonce (16 bytes = 128 bits)
        # nonce provide a unique identifier for a specific request, its
        # primary function is to enhance security by preventing replay 
        # attacks (intercepting a valid request and resending it) and 
        # mitigating cross-site scripting (XSS) vulnerabilities.
        nonce = token_hasher.generate_token(16, False)
        
        # Store nonce in request state for template/HTML access
        request.state.csp_nonce = nonce
        
        # Process request to get the response object
        response = await call_next(request)
        
        # Only add CSP to HTML responses
        content_type = response.headers.get("content-type", "")
        # if "text/html" in content_type:
        # Build strict CSP with nonce
        csp_header = self._build_csp_header(nonce)
        
        # always apply the security headers to the response object immediately before 
        # returning it, regardless of content type unless excluding specific responses
        # from having headers. The CSP header itself defines policy for the browser 
        # rendering context. If the browser receives this header with an application/json 
        # response, it simply ignores the header's content because JSON isn't rendered HTML. 
        # It is harmless to send the CSP header with JSON
        response.headers["Content-Security-Policy"] = csp_header
        
        # # add CSP report-only for monitoring, logging what would have been blocked, 
        # # allowing analysis and refinement of security rules without user impact (optional)
        # response.headers["Content-Security-Policy-Report-Only"] = csp_header
    
        logger.debug(f"CSP nonce generated: {nonce[:8]}...")

        # HSTS
        if self.enable_hsts:
            # protect websites against man-in-the-middle attacks (protocol downgrade attacks and cookie hijacking)
            # When a browser receives this header from a website over a secure HTTPS connection, the browser records 
            # this instruction. From that moment on, the browser will automatically force all future connections 
            # to that site to use HTTPS, even if the user explicitly types http:// in the address bar or 
            # clicks on an http:// link. If the browser cannot establish a secure connection 
            # (e.g., the security certificate is invalid), HSTS instructs the browser to display a hard-fail 
            # error message that the user cannot bypass, preventing them from potentially accessing the site insecurely.
            # The preload directive solves the "first visit" problem. Browser vendors like Google, Mozilla, and Microsoft 
            # maintain a list of domains that have requested to be "preloaded" with HSTS built directly into their browser software.
            # If a domain is on the preload list, the browser knows before the first connection is even made that it must only connect via HTTPS.
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
        
        # Prevent MIME sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"
        # Prevent clickjacking
        response.headers["X-Frame-Options"] = "DENY" # 'frame-ancestors 'none'' in the CSP, XFO is redundant but harmless to keep
        # for legacy browsers, modern CSP largely replaces this but harmless to keep
        response.headers["X-XSS-Protection"] = "1; mode=block"
        # Referrer policy
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        # Permissions policy (disable dangerous features)
        response.headers["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=()"
        )

        # header obfuscation: security best practice to hide server tech
        if "Server" in response.headers:
            del response.headers["Server"]
        
        return response
    
    def _build_csp_header(self, nonce: str) -> str:
        """
        Build strict CSP header with nonce
        
        Security notes:
        - 'strict-dynamic' allows scripts loaded by nonce'd scripts
        - 'unsafe-inline' is fallback for old browsers (ignored if nonces present)
        - No 'unsafe-eval' (blocks dynamic code execution)
        """
        
        # CRITICAL: 'strict-dynamic' makes nonces propagate to dynamically loaded scripts
        # This is essential for SolidJS and modern frameworks
        directives = [
            "default-src 'self'",
            
            # Scripts: nonce + strict-dynamic for SolidJS
            f"script-src 'nonce-{nonce}' 'strict-dynamic' https: 'unsafe-inline'",
            # Note: 'unsafe-inline' is ignored when nonce is present (fallback only)
            
            # Styles: nonce for inline styles + Tailwind CDN (if using)
            f"style-src 'self' 'nonce-{nonce}'",
            # Note: Tailwind utilities need 'unsafe-inline' if not in JIT mode (Tailwind's modern build process - PostCSS configuration)
            
            # Workers (for SolidJS/Vite HMR in dev)
            "worker-src 'self' blob:",
            
            # Images
            "img-src 'self' data: blob: https://raw.githubusercontent.com",
            
            # Fonts
            "font-src 'self'",
            
            # AJAX/Fetch/WebSocket
            "connect-src 'self' https://ammopy.goatcounter.com",
            
            # Forms (only submit to same origin)
            "form-action 'self'",
            
            # Frames (prevent clickjacking)
            "frame-ancestors 'none'",
            
            # Base URI (prevent base tag injection)
            "base-uri 'self'",
            
            # Object/Embed (no Flash/plugins)
            "object-src 'none'",
        ]
        
        return "; ".join(directives)