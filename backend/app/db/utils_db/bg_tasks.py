import gc
import time
import asyncio
import logging
from threading import Lock
from typing import Dict, Any
from concurrent.futures import ThreadPoolExecutor
from app.config.setting import settings
from app.db.db_factory import auth_store, doc_store, query_store, hash_store

logger = logging.getLogger(__name__)


class BackgroundTaskManager:
    """Optimized background tasks"""
    
    def __init__(self):
        self.tasks = {}
        self.running = False
        self.task_stats = {}
        self._executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="bg_task")
        self._lock = Lock()
    
    async def start(self):
        """Start optimized background tasks"""
        if self.running:
            return
        
        self.running = True
        logger.debug("Starting optimized background task manager...")
        
        if settings.processing.ENABLE_BACKGROUND_CLEANUP:
            # Schedule optimized cleanup tasks with different intervals
            self.tasks["cleanup_failed_uploads"] = asyncio.create_task(
                self._cleanup_failed_uploads()
            )

            self.tasks["cleanup_expired_tokens"] = asyncio.create_task(
                self._cleanup_expired_tokens()
            )
            
            self.tasks["cleanup_expired_cache"] = asyncio.create_task(
                self._cache_cleanup()
            )
            
            self.tasks["memory_management"] = asyncio.create_task(
                self._memory_management()
            )
            
            # Add cache maintenance task
            self.tasks["cache_maintenance"] = asyncio.create_task(
                self._cache_maintenance_task()
            )
            
            logger.info("✓ Background tasks started")
        else:
            logger.info("Background cleanup disabled")
    

    async def stop(self):
        """Stop all background tasks"""
        self.running = False
        
        for task_name, task in self.tasks.items():
            try:
                task.cancel()
                try:
                    await asyncio.wait_for(task, timeout=5.0)
                except asyncio.TimeoutError:
                    logger.warning(f"Task {task_name} did not stop gracefully")
            except asyncio.CancelledError:
                logger.debug(f"Background task {task_name} cancelled")
            except Exception as e:
                logger.error(f"Error stopping task {task_name}: {e}")
        
        # Shutdown thread pool
        self._executor.shutdown(wait=True)
        
        self.tasks.clear()
        logger.info("Optimized background tasks stopped")
    

    async def _cleanup_failed_uploads(self):
        """Smart cleanup that adjusts frequency based on activity"""
        base_interval = settings.processing.CLEANUP_INTERVAL_MINUTES * 60
        
        while self.running:
            try:
                start_time = time.time()
                
                cleaned_count = await hash_store.cleanup_failed_uploads(
                    older_than_minutes = settings.processing.FAILED_UPLOAD_CLEANUP_MINUTES
                    )

                execution_time = time.time() - start_time
                
                with self._lock:
                    self.task_stats["cleanup_failed_uploads"] = {
                        "last_run": int(time.time()),
                        "cleaned_count": cleaned_count,
                        "execution_time_ms": int(execution_time * 1000)
                    }
                
                if cleaned_count > 0:
                    logger.info(f"Cleanup: removed {cleaned_count} failed uploads")
                
                # Adaptive interval: if we found stuff to clean, check more frequently
                sleep_interval = base_interval // 2 if cleaned_count > 5 else base_interval
                await asyncio.sleep(sleep_interval)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in cleanup task: {e}")
                await asyncio.sleep(60)


    async def _cleanup_expired_tokens(self):
        """Clean up expired sessions, refresh tokens, and password reset tokens"""
        base_interval = settings.auth.CLEANUP_INTERVAL_HOURS * 3600 # Default: 24 hours

        while self.running:
            try:
                start_time = time.time()
                total_cleaned = 0

                # Clean expired sessions (most frequent)
                try:
                    session_count = await auth_store.cleanup_expired_sessions()
                    total_cleaned += session_count
                    if session_count > 0:
                        logger.info(f"Cleaned up {session_count} expired sessions")
                except Exception as e:
                    logger.error(f"Session cleanup failed: {e}")
                
                # Clean expired refresh tokens (30 days old)
                try:
                    rtoken_max_days = settings.auth.REFRESH_TOKEN_RETENTION_DAYS
                    refresh_count = await auth_store.cleanup_expired_refresh_tokens(days=rtoken_max_days)
                    total_cleaned += refresh_count
                    if refresh_count > 0:
                        logger.info(f"Cleaned up {refresh_count} expired refresh tokens")
                except Exception as e:
                    logger.error(f"Refresh token cleanup failed: {e}")
                
                # Clean expired password reset tokens (7 days old - more aggressive)
                try:
                    ptoken_max_days = settings.auth.PASSWORD_RESET_RETENTION_DAYS
                    reset_count = await auth_store.cleanup_expired_password_resets(days=ptoken_max_days)
                    total_cleaned += reset_count
                    if reset_count > 0:
                        logger.info(f"Cleaned up {reset_count} expired password reset tokens")
                except Exception as e:
                    logger.error(f"Password reset cleanup failed: {e}")
                
                # Clean old audit logs (optional, keep last 90 days)
                try:
                    # # Only if we want to clean old audit logs
                    # audit_count = await auth_store.cleanup_old_audit_logs(days=90)
                    # total_cleaned += audit_count
                    # if audit_count > 0:
                    #     logger.info(f"Cleaned up {audit_count} old audit logs")
                    pass
                except Exception as e:
                    logger.error(f"Audit log cleanup failed: {e}")
                
                execution_time = time.time() - start_time
                
                # Adaptive interval logic
                if total_cleaned > 100:
                    # High activity - check every 1 hour
                    sleep_interval = 3600
                elif total_cleaned > 10:
                    # Medium activity - check every 6 hours
                    sleep_interval = 6 * 3600
                elif total_cleaned > 0:
                    # Low activity - check every 12 hours
                    sleep_interval = 12 * 3600
                else:
                    # No activity - use base interval (24 hours)
                    sleep_interval = base_interval

                # Store stats
                with self._lock:
                    self.task_stats["cleanup_expired_tokens"] = {
                        "last_run": int(time.time()),
                        "total_cleaned": total_cleaned,
                        "execution_time_ms": int(execution_time * 1000),
                        "next_run_in_hours": sleep_interval / 3600
                    }
                
                if total_cleaned:
                    logger.info(
                        f"Token cleanup: {total_cleaned} items, next in {sleep_interval/3600:.1f}h"
                        )

                await asyncio.sleep(sleep_interval)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Auth cleanup task failed: {e}")


    async def _cache_cleanup(self):
        """Smart cache cleanup with adaptive scheduling"""
        if not settings.cache.ENABLE_QUERY_CACHE:
            return
        
        # Start with shorter intervals for cache
        base_interval = 15 * 60  # 15 minutes
        
        while self.running:
            try:
                start_time = time.time()
                
               # Run cleanup
                cleaned_count = await query_store.cleanup_expired()
                
                execution_time = time.time() - start_time
                
                with self._lock:
                    self.task_stats["cleanup_expired_cache"] = {
                        "last_run": int(time.time()),
                        "cleaned_count": cleaned_count,
                        "execution_time_ms": int(execution_time * 1000)
                    }
                
                if cleaned_count > 0:
                    logger.info(f"Cache cleanup: {cleaned_count} expired")
                
                # Adaptive interval based on activity
                if cleaned_count > 20:
                    sleep_interval = base_interval // 2  # More frequent if lots of cleanup
                elif cleaned_count == 0:
                    sleep_interval = base_interval * 2  # Less frequent if nothing to do
                else:
                    sleep_interval = base_interval
                
                await asyncio.sleep(sleep_interval)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in cache cleanup: {e}")
                await asyncio.sleep(60)
    
    
    # # skipped as upload is low frequency
    # async def _vector_optimization(self): 
    #     """Smart vector store optimization with load awareness"""
    #     while self.running:
    #         try:
    #             start_time = time.time()

    #             # Run optimization
    #             await doc_store.optimize_collections()

    #             execution_time = time.time() - start_time
                
    #             with self._lock:
    #                 self.task_stats["optimize_doc_store"] = {
    #                     "last_run": int(time.time()),
    #                     "execution_time_ms": int(execution_time * 1000)
    #                 }
                
    #             logger.debug("Vector optimization completed")
                
    #             # Longer interval for vector optimization (every 4 hours)
    #             await asyncio.sleep(4 * 60 * 60)
                
    #         except asyncio.CancelledError:
    #             break
    #         except Exception as e:
    #             logger.error(f"Error in vector optimization: {e}")
    #             await asyncio.sleep(300)  # 5 minute retry
    

    async def _memory_management(self):
        """Smart memory management with threshold-based actions"""
        while self.running:
            try:
                start_time = time.time()
                
                # Get memory info if available
                memory_info = {}
                try:
                    import psutil
                    process = psutil.Process()
                    memory_data = process.memory_info()
                    memory_mb = memory_data.rss / 1024 / 1024
                    
                    memory_info = {
                        "memory_mb": memory_mb,
                        "memory_percent": process.memory_percent()
                    }
                    
                    # Aggressive cleanup if memory usage is high
                    if memory_mb > 800:  # 800MB threshold
                        logger.warning(f"High memory usage detected: {memory_mb:.1f}MB")
                        
                        # Force multiple garbage collection cycles
                        collected = 0
                        for _ in range(3):
                            collected += gc.collect()
                            await asyncio.sleep(0.1)
                        
                            cache_size = len(doc_store.embedding_cache)
                            
                        # Clear some caches
                        if hasattr(doc_store, 'embedding_cache'):
                            if cache_size > 100:
                                # Clear half the embedding cache
                                keys_to_remove = list(doc_store.embedding_cache.keys())[:cache_size//2]
                                for key in keys_to_remove:
                                    del doc_store.embedding_cache[key]
                                logger.info(f"Cleared {len(keys_to_remove)} embedding cache entries due to memory pressure")
                        
                        memory_info["aggressive_cleanup"] = True
                        memory_info["gc_collected"] = collected
                    else:
                        # Normal garbage collection
                        collected = gc.collect()
                        memory_info["gc_collected"] = collected
                    
                except ImportError:
                    # psutil not available, just run GC
                    collected = gc.collect()
                    memory_info = {"gc_collected": collected}
                
                execution_time = time.time() - start_time
                
                with self._lock:
                    self.task_stats["memory_management"] = {
                        "last_run": int(time.time()),
                        "execution_time_ms": int(execution_time * 1000),
                        **memory_info
                    }
                
                # Log significant memory management activities
                if memory_info.get("memory_mb", 0) > 500:
                    logger.debug(f"Memory management: {memory_info.get('memory_mb', 0):.1f}MB, collected {memory_info.get('gc_collected', 0)} objects")
                
                # Adaptive interval based on memory usage
                memory_mb = memory_info.get("memory_mb", 300)
                if memory_mb > 600:
                    await asyncio.sleep(5 * 60)   # Every 5 minutes if high memory
                elif memory_mb > 400:
                    await asyncio.sleep(10 * 60)  # Every 10 minutes if moderate memory
                else:
                    await asyncio.sleep(15 * 60)  # Every 15 minutes if low memory
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in memory management: {e}")
                await asyncio.sleep(60)
    

    async def _cache_maintenance_task(self):
        """Dedicated task for cache maintenance and optimization"""
        if not settings.cache.ENABLE_QUERY_CACHE:
            return
        
        while self.running:
            try:
                start_time = time.time()

                # Get cache stats to determine maintenance needs
                stats = await query_store.get_cache_stats()

                maintenance_actions = [] # TODO: INCLUDE LRU CACHE
                
                execution_time = time.time() - start_time
                
                with self._lock:
                    self.task_stats["cache_maintenance"] = {
                        "last_run": int(time.time()),
                        "execution_time_ms": int(execution_time * 1000),
                        "actions": maintenance_actions,
                        "cache_stats": stats
                    }
                
                if maintenance_actions:
                    logger.info(f"Cache maintenance: {', '.join(maintenance_actions)}")
                
                # Run every hour
                await asyncio.sleep(60 * 60)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in cache maintenance: {e}")
                await asyncio.sleep(300)  # 5 minute retry
    

    def get_task_stats(self) -> Dict[str, Any]:
        """Get statistics for all background tasks"""
        with self._lock:
            return {
                "running": self.running,
                "active_tasks": list(self.tasks.keys()),
                "task_stats": self.task_stats.copy(),
                "thread_pool_info": {
                    "max_workers": self._executor._max_workers,
                    "active_threads": len([t for t in self._executor._threads if t.is_alive()]) if hasattr(self._executor, '_threads') else 0
                }
            }


# Global (singelton) instance
bg_task_mngr = BackgroundTaskManager()