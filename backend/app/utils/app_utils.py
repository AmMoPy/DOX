import os
import time
import logging
import traceback
from uuid import uuid4
from typing import Callable
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
from app.config.setting import settings
from app.config.sys_chkr import SystemChecker
from app.config.dir_mngr import DirectoryManager
from app.config.config_val import ConfigValidator
from app.core.llm_client import llm_client
from app.core.rate_limiter import rate_limiter
from app.core.embedding_client import embedding_client
from app.db.db_factory import auth_store, query_store
# from app.db.utils_db.async_bridge import async_bridge
from app.db.db import initialize_databases, cleanup_databases
from app.auth.auth_mngr import auth_mgr # auth_store factory instance, call after initialize_databases()
from app.auth.sec_prov.base import AuthMethod
from app.utils.prog_trac import progress_tracker

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""

    # Startup
    logger.info("Starting DOX...")
    
    try:
        # Create necessary directories
        directory_manager = DirectoryManager(settings.paths)
        created_dirs = directory_manager.create_directories()
        if created_dirs:
            logger.info(f"Created directories: {', '.join(created_dirs)}")
        
        # Validate and optimize configuration
        validator = ConfigValidator(settings)
        issues_fixed = validator.validate_all() # Modifies settings in-place
        total_fixes = len(issues_fixed)
        if issues_fixed:
            for i, fix in enumerate(issues_fixed):
                logger.info(f"CONFIG UPDATE # {i + 1}/{total_fixes}: {fix}")
        
        # Check external systems (if not using PostgreSQL exclusively)
        if not settings.USE_POSTGRES:
            ollama_status = SystemChecker.check_ollama(settings.models.OLLAMA_MODEL)
            if ollama_status["available"]:
                logger.info(f"Ollama found: {ollama_status['version']}")
                if ollama_status.get("model_available"):
                    logger.info(f"Model {settings.models.OLLAMA_MODEL} is available")
                else:
                    logger.warning(f"Model {settings.models.OLLAMA_MODEL} not found. Install with: ollama pull {settings.models.OLLAMA_MODEL}")
            else:
                reason = ollama_status.get("reason", "unknown")
                if reason == "ollama_not_found":
                    logger.info("Ollama not found. AI features will use cloud providers only.")
                else:
                    logger.warning(f"Ollama check failed: {reason}")
        
        # Validate provider configurations
        _validate_and_log_providers()

        # Initialize embedding client first
        embedding_client.initialize()
        logger.info("Embedding client initialized")
        
        # Initialize all databases and related background cleanup tasks
        await initialize_databases()

        # Initialize upload tracker background cleanup task
        # use longer interval, callers handle cleanup internally
        await progress_tracker.start_cleanup_task()

        # # db hotfix (if any)
        # await _db_hotfix(auth_store)
        
        # Admin creation Flow:
        # 1. Option A: Set env vars -> admin auto-created -> endpoint disabled
        # 2. Option B: No env vars -> setup endpoint available -> create via UI or SSH
        # Either way, after first admin exists, creation is disabled, setup endpoint returns 403
        
        # Check for environment-based auto-creation (Option A)
        # In production use proper deployment system environment variables
        admin_created = await _create_initial_admin()

        if not admin_created:
            # Keep setup endpoint enabled for manual creation (Option B)
            logger.info("No admin was created from environment variables. Visit /setup to create initial admin")
        else:
            # Disable setup endpoint after auto-creation
            settings.auth.ALLOW_ADMIN_CREATION = False
           
        # Log configuration summary if in debug mode
        if settings.server.DEBUG:
            _log_configuration_summary()
        
        logger.info("DOX startup completed successfully!")
        
    except Exception as e:
        logger.error(f"Failed to initialize DOX: {e}")
        logger.error(traceback.format_exc())
        raise
    
    yield
    
    # Shutdown
    logger.info("Shutting down DOX...")
    try:
        await rate_limiter.shutdown()
        await cleanup_databases()
        await llm_client.cleanup()
        logger.info("DOX shutdown completed")
    except Exception as e:
        logger.error(f"Error during shutdown: {e}")


async def enhanced_middleware(request: Request, call_next: Callable):
    """Enhanced middleware with request tracking and error handling"""
    start_time = time.time()
    request_id = str(uuid4())[:8]
    
    # Log incoming request
    logger.debug(f"[{request_id}] {request.method} {request.url.path}")
    
    try:
        response = await call_next(request)
        
        # Log successful response
        process_time = time.time() - start_time
        logger.debug(f"[{request_id}] Response: {response.status_code} ({process_time:.3f}s)")
        
        # Add request ID to response headers
        response.headers["X-Request-ID"] = request_id
        
        return response
        
    except Exception as e:
        process_time = time.time() - start_time
        logger.error(f"[{request_id}] Unhandled exception ({process_time:.3f}s): {str(e)}")
        logger.error(f"[{request_id}] Traceback: {traceback.format_exc()}")
        
        # Return structured error response
        return JSONResponse(
            status_code=500,
            content={
                "detail": "Internal server error",
                "request_id": request_id,
                "error_type": type(e).__name__
            },
            headers={"X-Request-ID": request_id}
        )


# Helper functions
async def _create_initial_admin():
    """Create initial admin from environment variables if configured"""

    # .pop() immediately clear environment variables for security
    # however, environment variables are loaded into Python process's memory
    # upon startup before Python code even executes pop(). TODO: use 
    # .get() for stability across all scenarios (single/multiple instances startup)
    # and let the database check handle the "run once" logic safely across all environments and restarts?
    admin_email = os.environ.pop('INITIAL_ADMIN_EMAIL', None)
    admin_password = os.environ.pop('INITIAL_ADMIN_PASSWORD', None)

    if not admin_email or not admin_password:
        logger.info("No initial admin configuration found (INITIAL_ADMIN_EMAIL/PASSWORD not set)")

        return # use other methods
    
    # Check if any admin exists
    try:
        existing_admins = await auth_store.list_users(role='admin', limit=1)

        if existing_admins:
            logger.info("Admin account already exists - skipping initial admin creation")
            
            return True # Admin exists, flag to disable further checks
    
        # Create initial admin
        logger.info(f"Creating initial admin: {admin_email}") # never log password!
        
        from app.auth.sec_prov.base import UserIdentity
        
        identity = UserIdentity(
            user_id="",
            email=admin_email,
            role='admin',
            auth_method=AuthMethod.LOCAL,
            mfa_enabled=False
        )
        
        admin_user = await auth_mgr.create_user(identity, password=admin_password)
        
        logger.info(f"Initial admin created from environment variables: {admin_user.email}")

        return True

    except Exception as e:
        logger.error(f"Failed to create initial admin: {e}")
        return # fail silently, dont crash app, use other method 


def _validate_and_log_providers():
    """Validate and log provider configurations"""
    providers_status = []
    suggestions = []
    status = settings.models.get_provider_status()
    
    # Check Ollama
    if  status["ollama"]:
        providers_status.append("Local Ollama: configured")
    else:
        providers_status.append("Local Ollama: not configured")
        suggestions.append("Consider setting up Ollama for local AI processing")
    
    # Check Cloudflare
    if  status["cloudflare"]:
        providers_status.append("Cloudflare: configured")
    else:
        providers_status.append("Cloudflare: not configured")
        suggestions.append("Consider configuring Cloudflare Workers AI for cloud processing")
    
    # Check OpenRouter
    if  status["openrouter"]:
        providers_status.append("OpenRouter: configured")
    else:
        providers_status.append("OpenRouter: not configured")
        suggestions.append("Consider configuring OpenRouter for additional cloud AI options")
    
    if settings.server.DEBUG:
        logger.info("Provider Configuration:")
        for status in providers_status:
            logger.info(f"  {status}")
        
        if suggestions:
            logger.info("Setup suggestions:")
            for suggestion in suggestions:
                logger.info(f"  - {suggestion}")


def _log_configuration_summary():
    """Log optimized configuration summary for debug mode"""
    logger.info("\n=== Optimized Configuration Summary ===")
    logger.info(f"Database: {'PostgreSQL' if settings.USE_POSTGRES else 'SQLite/ChromaDB'}")
    logger.info(f"Database strategies: {settings.database.DATABASE_STRATEGIES}")
    logger.info(f"Max File Size: {settings.processing.MAX_FILE_SIZE / (1024*1024):.0f}MB")
    logger.info(f"Stream Buffer: {settings.processing.STREAM_BUFFER_SIZE / (1024*1024):.1f}MB")
    logger.info(f"Memory Threshold: {settings.processing.MEMORY_PRESSURE_THRESHOLD / (1024*1024):.0f}MB")
    logger.info(f"Concurrent Uploads: {settings.processing.MAX_CONCURRENT_UPLOADS}")
    logger.info(f"Chunk Size: {settings.processing.CHUNK_SIZE} chars")
    logger.info(f"Cache Max Entries: {settings.cache.CACHE_MAX_ENTRIES}")
    logger.info(f"Provider Preference: {settings.models.LLM_PROVIDER_PREFERENCE}")
    logger.info("==========================================\n")


# async def _db_hotfix(db):
#     """
#     Introduce hotfixes upon app initialization, 
#     adjust imports and query based on needed changes
#     """
#     from app.db.utils_db.sql_pool_mngr import SQLiteHashPool
#     from app.db.utils_db.async_bridge import async_bridge
#     from app.db.utils_db.circuit_breaker import sql_cb

#     try: 
#         async with db.pool.get_connection() as conn:
#             await sql_cb.execute(
#                 async_bridge.run_in_db_thread(
#                     lambda: conn.execute('''
#                         ALTER TABLE sessions ADD COLUMN mfa_verified INTEGER DEFAULT 0
#                     ''',
#                     )
#                 )   
#             )

#         logger.info("***hotfix applied***")

#     except Exception as e:
#         logger.error(f"Could not apply hotfix: {e}")