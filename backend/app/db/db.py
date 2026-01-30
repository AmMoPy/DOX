import time
import logging
import asyncio
from typing import Dict, Any
from app.config.setting import settings
from app.core.llm_client import llm_client
from app.db.utils_db.bg_tasks import bg_task_mngr
from app.db.db_factory import auth_store, doc_store, query_store, hash_store

logger = logging.getLogger(__name__)


async def initialize_databases():
    """
    Initialize all database components with enhanced sequencing, error handling
    and event loop behavior examples
    """
    try:
        logger.info("Initializing database components...")
        start_time = time.time()
        
        # Phase 1: Core database initialization
        logger.info("Phase 1: Initializing core databases...")
        
        # Initialize auth database first (PostgreSQL/SQLite)
        # AWAIT - COROUTINE (initialize_databases) PAUSES
        # A coroutine is a function (async) that can pause its execution and yield control
        # back to the event loop, then resume later from where it left off.
        # Event Loop: "OK, initialize_databases is waiting for auth_store.initialize()
        # I'll pause it and run auth_store.initialize() until it completes"
        await auth_store.initialize()
        logger.info("✓ Auth store initialized")

        # Initialize file hash database
        await hash_store.initialize()
        # RESUMES after hash_store completes
        logger.info("✓ Hash store initialized")
        
        # Initialize query database if enabled
        if settings.cache.ENABLE_QUERY_CACHE:
            # AWAIT - COROUTINE PAUSES AGAIN
            await query_store.initialize()
            # Event Loop: "initialize_databases is waiting again, 
            # I'll run query_store.initialize()"
            logger.info("✓ Query store initialized")
        
        # Initialize document database
        await doc_store.initialize()
        logger.info("✓ Document store initialized")
        
        # Phase 2: Cleanup and optimization
        logger.info("Phase 2: Running initial cleanup...")
        
        # Clean up any old failed uploads on startup
        cleaned_uploads = await hash_store.cleanup_failed_uploads(
            older_than_minutes = 60
        )
        if cleaned_uploads > 0:
            logger.info(f"✓ Cleaned up {cleaned_uploads} stale upload records")
        
        # Clean up expired cache entries if cache is enabled
        if settings.cache.ENABLE_QUERY_CACHE:
            cleaned_cache = await query_store.cleanup_expired()
            if cleaned_cache > 0:
                logger.info(f"✓ Cleaned up {cleaned_cache} expired cache entries")
        
        # Phase 3: Background tasks
        logger.info("Phase 3: Starting background tasks...")
        await bg_task_mngr.start()
        
        # Phase 4: Provider warmup - The Critical Decision Point
        if settings.server.ENABLE_MODEL_WARMUP:
            logger.info("Phase 4: Warming up providers...")
            
            if settings.server.ENABLE_ASYNC_WARMUP:
                # Non-blocking warmup - don't wait for completion
                # asyncio.create_task() = "Run in Background"
                # This coroutine (initialize_databases) CONTINUES immediately
                # Even though _warmup_providers uses 'await' internally,
                # it doesn't block the CURRENT coroutine that created the task
                # server continues without waiting for Phase 5 to finish
                # The task (Phase 5) coroutine runs concurrently in the background
                # The event loop says: "OK, I'll add this (warmup) as a NEW coroutine to run,
                # and the current coroutine (initialize_databases) can continue immediately"
                # The event loop might:
                    # 1. Run initialize_databases to print "✓ Started async provider warmup"
                    # 2. THEN switch to _warmup_providers
                    # 3. OR interleave them depending on who hits 'await' first
                asyncio.create_task(_warmup_providers())
                logger.info("✓ Started async provider warmup") # ← Runs IMMEDIATELY
            else:
                # Blocking - wait for warmup coroutine to complete before continuing
                # await = "Block THIS Coroutine"
                # The event loop says: "OK, this coroutine (initialize_databases) is waiting, 
                # I'll pause it and run other coroutines"
                await _warmup_providers()  # Same function, just awaited
                # Server continues only after warmup completes
        
        # Phase 5: System health check
        logger.info("Phase 5: Running system health check...")
        health_status = await get_system_health() # This might run BEFORE warmup finishes!
        if health_status["overall_status"] == "healthy":
            logger.info("✓ System health check passed")
        else:
            logger.warning(f"System health check: {health_status['overall_status']}")
        
        total_time = time.time() - start_time
        logger.info(f"🚀 All database components initialized successfully in {total_time:.2f}s!")
        
        # Log configuration summary
        await _log_initialization_summary()
            
    except Exception as e:
        logger.error(f"Failed to initialize databases: {e}")
        # Attempt cleanup of partially initialized components
        await _cleanup_on_failure()
        raise


async def _warmup_providers():
    """Async warmup task that doesn't block startup"""
    try:
        # Small delay to let server fully start
        # This is where the coroutine YIELDS CONTROL back to event loop
        # as it PAUSES the warmup coroutine for 2 seconds
        # This delay gives the server time to fully start
        # before we start hammering providers with warmup requests
        # without it this might interfere with server startup or cause timeouts
        # TODO: Creates race condition with get_system_health that calls llm_client.health_check? 
        await asyncio.sleep(2)  # "I'm going to be busy for ~2 seconds, run others!"

        warmup_results = await llm_client.warmup_providers()
        successful = [name for name, success in warmup_results.items() if success]
        failed = [name for name, success in warmup_results.items() if not success]
        
        # This might print AFTER Phase 5 logger: "All database components initialized"
        logger.info(f"Async warmup completed: {len(successful)} successful, {len(failed)} failed")
        
        if failed:
            logger.warning(f"Warmup failed for: {', '.join(failed)}")
            
    except Exception as e:
        logger.error(f"Async warmup failed: {e}")


async def _cleanup_on_failure():
    """Clean up partially initialized components on failure"""
    try:
        logger.info("Cleaning up after initialization failure...")
        
        # Stop background tasks
        await bg_task_mngr.stop()
        
        # Clean up vector store
        await doc_store.close()
        
        # Close database connections
        if hash_store and hash_store._initialized:
            await hash_store.close()
        
        if settings.cache.ENABLE_QUERY_CACHE:
            await query_store.close()

        logger.info("Cleanup completed")
        
    except Exception as e:
        logger.error(f"Error during failure cleanup: {e}")


async def _log_initialization_summary():
    """Log initialization summary with key metrics"""
    try:
        configured_providers = settings.models.get_configured_providers()
        database_type = "PostgreSQL" if settings.USE_POSTGRES else "SQLite"

        if settings.cache.ENABLE_QUERY_CACHE:
            try:
                cache_stats = await query_store.get_cache_stats()
                msg = f"'Enabled' with {cache_stats.get('valid_entries', 0)} valid entries"
            except Exception as e:
                logger.warning(f"Could not get cache stats: {e}")
        else:
            msg = 'Disabled'
        
        logger.info("=== Initialization Summary ===")
        logger.info(f"Database: {database_type}")
        logger.info(f"Configured Providers: {', '.join(configured_providers) if configured_providers else 'None'}")
        logger.info(f"Query Cache: {msg}")
        logger.info(f"Background Tasks: {'Enabled' if settings.processing.ENABLE_BACKGROUND_CLEANUP else 'Disabled'}")
        logger.info(f"Max File Size: {settings.processing.MAX_FILE_SIZE / (1024*1024):.0f}MB")
        logger.info("==============================")
        
    except Exception as e:
        logger.error(f"Error logging initialization summary: {e}")


async def cleanup_databases():
    """Cleanup all database components with enhanced error handling"""
    try:
        logger.info("Starting enhanced database cleanup...")
        
        # Stop background tasks first
        await bg_task_mngr.stop()
        logger.info("✓ Background tasks stopped")
        
        # Close database connections
        await auth_store.close()
        logger.info("✓ Auth store closed")

        await hash_store.close()
        logger.info("✓ Hash store closed")

        await doc_store.close()
        logger.info("✓ Document store closed")
        
        # Final cache cleanup
        if settings.cache.ENABLE_QUERY_CACHE:
            try:
                cleaned = await query_store.cleanup_expired()
                if cleaned > 0:
                    logger.info(f"✓ Final cache cleanup: {cleaned} entries removed")
                # Close database connections
                await query_store.close()
            except Exception as e:
                logger.warning(f"Error during final cache cleanup: {e}")
        
        logger.info("Database cleanup completed successfully")
        
    except Exception as e:
        logger.error(f"Error during database cleanup: {e}")


async def get_system_health() -> Dict[str, Any]:
    """Get comprehensive system health status with enhanced monitoring"""
    health = {
        "overall_status": "healthy",
        "components": {},
        "timestamp": int(time.time()),
        "performance_metrics": {}
    }
    
    try:
        start_time = time.time()
        
        component_tasks = {
            "auth_store": auth_store.health_check(),
            "doc_store": doc_store.health_check(),
            "hash_store": hash_store.health_check(),
            "llm_providers": llm_client.health_check(),
        }
        
        if settings.cache.ENABLE_QUERY_CACHE:
            component_tasks["query_store"] = query_store.health_check()
        
        component_results = await asyncio.wait_for(
            asyncio.gather(*component_tasks.values(), return_exceptions=True),
            timeout=settings.server.HEALTH_CHECK_TIMEOUT
            )

        component_names = list(component_tasks.keys())
        
        for i, result in enumerate(component_results):
            if i >= len(component_names):
                continue

            component_name = component_names[i]
            
            if isinstance(result, Exception):
                health["components"][component_name] = {
                    "status": "unhealthy",
                    "error": str(result)
                }
                health["status"] = "degraded"
            else:
                if result:
                    health["components"][component_name] = result
                    if result.get("status") != "healthy":
                        health["status"] = "degraded"
        
        # Check background tasks health
        try:
            task_stats = bg_task_mngr.get_task_stats()
            health["components"]["background_tasks"] = {
                "status": "healthy" if task_stats["running"] else "disabled",
                "stats": task_stats
            }
        except Exception as e:
            health["components"]["background_tasks"] = {
                "status": "unhealthy",
                "error": str(e)
            }
        
        # Add performance metrics
        health_check_time = time.time() - start_time
        health["performance_metrics"] = {
            "health_check_time_ms": int(health_check_time * 1000),
            "configuration": {
                "database_type": "PostgreSQL" if settings.USE_POSTGRES else "SQLite",
                "max_file_size_mb": settings.processing.MAX_FILE_SIZE / (1024 * 1024)
            }
        }
    
    except Exception as e:
        health["overall_status"] = "unhealthy"
        health["error"] = str(e)
        logger.error(f"Health check failed: {e}")
    
    return health


async def get_performance_metrics() -> Dict[str, Any]:
    """Get detailed performance metrics"""
    try:
        metrics = {
            "timestamp": int(time.time()),
            "memory": {},
            "database": {},
            "doc_store": {},
            "cache": {}
        }
        
        # Memory metrics (if psutil available)
        try:
            import psutil

            # System memory info
            memory = psutil.virtual_memory()

            metrics["memory"] = {
                "available_mb": memory.available / (1024 * 1024),
                "percent_used": memory.percent
            }

        except ImportError:
            metrics["memory"] = {"error": "psutil not available"}
                
        # Vector store metrics
        try:
            vector_stats = await doc_store.get_collection_stats()
            metrics["doc_store"] = vector_stats
        except Exception as e:
            metrics["doc_store"] = {"error": str(e)}
        
        # Cache metrics
        if settings.cache.ENABLE_QUERY_CACHE:
            try:
                cache_stats = await query_store.get_cache_stats()
                metrics["cache"] = cache_stats
            except Exception as e:
                metrics["cache"] = {"error": str(e)}
        
        # Background task metrics
        try:
            task_stats = bg_task_mngr.get_task_stats()
            metrics["background_tasks"] = task_stats
        except Exception as e:
            metrics["background_tasks"] = {"error": str(e)}
        
        return metrics
        
    except Exception as e:
        logger.error(f"Failed to get performance metrics: {e}")
        return {"error": str(e), "timestamp": int(time.time())}


async def optimize_system():
    """Run system optimization tasks manually"""
    try:
        logger.info("Starting manual system optimization...")
        optimization_results = {}
        
        # # Optimize vector store, skipped as upload is low frequency
        # try:
        #     await doc_store.optimize_collections()
        #     optimization_results["doc_store"] = "optimized"
        # except Exception as e:
        #     optimization_results["doc_store"] = f"failed: {e}"
        
        # Clean up expired cache
        if settings.cache.ENABLE_QUERY_CACHE:
            try:
                cleaned = await query_store.cleanup_expired()
                optimization_results["cache_cleanup"] = f"removed {cleaned} entries"
            except Exception as e:
                optimization_results["cache_cleanup"] = f"failed: {e}"
        
        # Clean up failed uploads
        try:
            cleaned = await hash_store.cleanup_failed_uploads()
            optimization_results["failed_uploads_cleanup"] = f"removed {cleaned} records"
        except Exception as e:
            optimization_results["failed_uploads_cleanup"] = f"failed: {e}"
        
        # Memory management
        try:
            import gc
            collected = gc.collect()
            optimization_results["memory_gc"] = f"collected {collected} objects"
        except Exception as e:
            optimization_results["memory_gc"] = f"failed: {e}"
        
        logger.info("Manual system optimization completed")
        return optimization_results
        
    except Exception as e:
        logger.error(f"System optimization failed: {e}")
        return {"error": str(e)}