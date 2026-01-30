import uvicorn
import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from app.api.web import router as nonce_router
from app.api.router import main_router as api_router
from app.config.setting import settings
from app.auth.mid_ware.csp import CSPNonceMiddleware
from app.auth.mid_ware.csrf import csrf_midware
from app.utils.app_utils import lifespan, enhanced_middleware

# Logging configuration
log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
logging.basicConfig(
    level=getattr(logging, settings.server.LOG_LEVEL),
    format=log_format
)

logger = logging.getLogger(__name__)

# Suppress noisy third-party loggers unless in debug mode
if not settings.server.DEBUG:
    logging.getLogger("chromadb").setLevel(logging.WARNING)
    logging.getLogger("sentence_transformers").setLevel(logging.WARNING)
    logging.getLogger("transformers").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)


# Create FastAPI app with lifespan manager
app = FastAPI(
    title="DOX",
    version="1.0.0",
    description="AI-powered RAG system",
    debug=settings.server.DEBUG,
    lifespan=lifespan
)


# middleware is executed from bottom to top when adding 
# them via app.add_middleware(). Execution flow:
# REQUEST:  Enhanced → CORS → CSP → CSRF → Router
# RESPONSE: Router → CSRF → CSP → CORS → Enhanced

# Enhanced middleware for exception handling and logging (first on the request, last on the response(runs last))
app.add_middleware(BaseHTTPMiddleware, dispatch=enhanced_middleware)


# CORS middleware (Runs second on request)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.server.CORS_ORIGINS, # white list, ensure they have no * 
    allow_credentials=True, # required to allow the browser to send cookies, critical for HTTPonly approach nice to have for authorization header.
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"], # ["*"] Acceptable for an API but better be explicit
    allow_headers=["Authorization", "Content-Type", "X-CSRF-Token"], # No stretching, be explicit as * tells any origin that they can send any HTTP header they want
    expose_headers=["X-Request-ID", "X-CSRF-Token"], # Expose CSRF token header
    max_age=600 # Cache preflight for 10 minutes
)


# CSP middleware (Runs third on request before CSRF, so nonce is available)
# IMPORTANT NOTE FOR FUTURE SELF (DEV MODE):
# using proxy in vite (back/front ends use different port) WILL SERVE INDEX.HTML
# STATICALLY WITHOUT TOUCHING FASTAPI MIDDLEWARE (AT INITIAL REQUEST) SO I WILL NOT 
# SEE THE CSP HEADERS IN DEV TOOLS (unless injected in VITE config, RIP 'nonce'!). 
# To ensure csp middleware work:
# A) curl -I -X GET http://localhost:port (backend URL), should see the csp header
# as curl CLI has no security restrictions like the Same-Origin Policy. It sees exactly what FastAPI sends. 
# B) inspect FETCH/XHR in network tab, all requests proxied through Vite should have the csp header set by the middleware.
app.add_middleware(
    CSPNonceMiddleware,
    enable_hsts=settings.server.ENABLE_HSTS
)


# CSRF protection middleware (Runs innermost before router)
# use BaseHTTPMiddleware wrapper for function-based middlewares
app.add_middleware(BaseHTTPMiddleware, dispatch=csrf_midware)


# Include routers (main routers)
app.include_router(api_router, prefix="/api", tags=["api"])


# the browser's INITIAL request to app url (e.g.: http://localhost:port/) will not
# include /api prefix, separate this router from main routers which uses the prefix 
# so it handled the request returning 200 OK text/html response with the nonce injected.
# NOTE VITE'S STATIC HTML SERVING (No Server-Side Processing in DEV), to truly test 
# CSP and nonce injection FastAPI must serves the initial index.html, either a production
# build or a hybrid dev setup (editing VITE hot module replacement (HMR) connections). Do
# quick test curl http://localhost:port | grep "nonce=" , should see tags having "nonce=Abc.."
app.include_router(nonce_router) # must be LAST - catch-all


if __name__ == "__main__":
    # Validate configuration before starting
    if not settings.models.get_configured_providers():
        logger.warning("No LLM providers configured! The AI features will not work.")
        logger.warning("Please configure at least one provider. See documentation for setup instructions.")
    
    logger.info(f"Starting server on {settings.server.HOST}:{settings.server.PORT}")
    logger.info(f"Provider preference: {settings.models.LLM_PROVIDER_PREFERENCE}")
    logger.info(f"Cache enabled: {settings.cache.ENABLE_QUERY_CACHE}")
    logger.info(f"Model warmup: {settings.server.ENABLE_MODEL_WARMUP}")
    
    uvicorn.run(
        "main:app",
        host=settings.server.HOST,
        port=settings.server.PORT,
        reload=settings.server.DEBUG,
        log_level=settings.server.LOG_LEVEL.lower(),
        access_log=settings.server.DEBUG
    )