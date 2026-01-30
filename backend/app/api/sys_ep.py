import time
import asyncio
import logging
from fastapi import APIRouter, HTTPException, Depends, Request
from datetime import datetime, UTC
from app.core.llm_client import llm_client
from app.core.rate_limiter import rate_limiter
from app.config.setting import settings
from app.auth.dependencies import require_admin
from app.db.db_factory import auth_store, doc_store, hash_store, query_store
from app.auth.compliance.sec_audit_log import audit_logger

logger = logging.getLogger(__name__)

# Shared Instances
router = APIRouter(prefix="/sys", tags=["stats"], dependencies=[Depends(require_admin)]) # Blocks non-adms, no parameter injection


# Stats
@router.get("/stats")
async def sys_stats(request: Request):
    """Get comprehensive system statistics and performance metrics"""
    try:
        stats_start = time.time()

        tasks = [
            doc_store.get_collection_stats(),
            hash_store.list_all_files(),
            llm_client.get_provider_status(),
        ]
        
        if settings.cache.ENABLE_QUERY_CACHE:
            tasks.append(query_store.get_cache_stats())

        # Execute ALL coroutines concurrently
        # gather is for concurrent operations - multiple independent things that can run together
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        content_stats = results[0] if not isinstance(results[0], Exception) else {}
        files_info = results[1] if not isinstance(results[1], Exception) else []
        provider_status = results[2] if not isinstance(results[2], Exception) else {}
        cache_stats = results[3] if len(results) > 3 and not isinstance(results[3], Exception) else {}
        
        stats_time = time.time() - stats_start
        
        # # Audit log - enable if needed (good for debugging frontend recursive ticks)
        # admin_user = request.state.current_user
        # await audit_logger.log_event(
        #     event_type="system_stats_viewed",
        #     user_id=admin_user.user_id,
        #     email=admin_user.email,
        #     ip_address=request.client.host,
        #     success=True
        # )

        return {
            "content_chunks": content_stats.get("total_chunks", 0),
            "partitions": content_stats.get("partitions", {}),
            "total_files": len(files_info),
            "completed_files": len([f for f in files_info if f.get("status") == "complete"]),
            "processing_files": len([f for f in files_info if f.get("status") == "processing"]),
            "cache_stats": cache_stats, # Database only, LRU is not monitored
            "provider_status": provider_status,
            "available_providers": [
                name for name, info in provider_status.items() 
                if info.get("available", False)
            ],
            "database_types": settings.get_configured_database_types(),
            "performance": {
                "stats_generation_time_ms": int(stats_time * 1000),
                "memory_config": settings.get_memory_configuration(),
                "concurrency_config": settings.get_concurrency_configuration()
            },
            "timestamp": datetime.now(UTC).isoformat()
        }
    except Exception as e:
        logger.error(f"Failed to get optimized stats: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get stats: {str(e)}")


@router.get("/health")
async def sys_health_check(request: Request):
    """Concurrent component health checking"""
    try:
        health_start = time.time()
        
        health_status = {
            "status": "healthy",
            "error_details": [],
            "timestamp": datetime.now(UTC).isoformat(),
            "components": {},
            "performance": {}
        }
        
        # Check components concurrently
        component_tasks = {
            "auth_store": auth_store.health_check(),
            "doc_store": doc_store.health_check(),
            "hash_store": hash_store.health_check(),
            "llm_providers": llm_client.health_check(),
            "rate_limiter": rate_limiter.health_check()
        }
        
        if settings.cache.ENABLE_QUERY_CACHE:
            component_tasks["query_store"] = query_store.health_check()
        
        # Wait for all health checks with timeout
        try:
            component_results = await asyncio.wait_for(
                asyncio.gather(*component_tasks.values(), return_exceptions=True),
                timeout=settings.server.HEALTH_CHECK_TIMEOUT
            )
        except asyncio.TimeoutError:
            health_status["status"] = "degraded"
            health_status["error"] = "Health check timeout"
            logger.warning("Health check timeout occurred")
            return health_status
        
        # Process component results
        component_names = list(component_tasks.keys())
        for i, result in enumerate(component_results):
            component_name = component_names[i]
            
            if isinstance(result, Exception):
                health_status["components"][component_name] = {
                    "status": "unhealthy",
                    "error": str(result)
                }
                health_status["status"] = "degraded"
            else:
                health_status["components"][component_name] = result
                if result.get("status") != "healthy":
                    health_status["status"] = "degraded"
                    health_status["error_details"].append(result.get("error"))

        
        # Add performance metrics
        health_check_time = time.time() - health_start
        health_status["performance"] = {
            "health_check_time_ms": int(health_check_time * 1000),
            "memory_config": settings.get_memory_configuration(),
            "optimization_level": "high" if len(settings.models.get_configured_providers()) >= 2 else "basic"
        }

        # # Audit log - enable if needed (good for debugging frontend recursive ticks)
        # admin_user = request.state.current_user
        # await audit_logger.log_event(
        #     event_type="system_health_viewed",
        #     user_id=admin_user.user_id,
        #     email=admin_user.email,
        #     ip_address=request.client.host,
        #     success=True
        # )
        
        return health_status
        
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return {
            "status": "unhealthy",
            # "timestamp": int(time.time()),
            "timestamp": datetime.now(UTC).isoformat(),
            "error": str(e)
        }


@router.get("/performance")
async def get_performance_metrics(request: Request):
    """Get detailed performance metrics"""
    try:
        metrics = {
            "timestamp": datetime.now(UTC).isoformat(),
            "memory": {},
            "processing": {},
            "cache": {},
            "recommendations": []
        }
        
        # Memory metrics
        try:
            import psutil

            # Process info, this is specific 
            # for the process initializing the http request
            # TODO: monitor all proccess related to the APP
            process = psutil.Process()
            memory_info = process.memory_info()
                  
            metrics["memory"] = {
                "rss_mb": round(memory_info.rss / 1024 / 1024, 2), # real memory used
                "vms_mb": round(memory_info.vms / 1024 / 1024, 2), # total memory allocated
                "cpu_percent": process.cpu_percent(),
                "memory_percent": process.memory_percent()
            }
            
            # Memory recommendations
            if metrics["memory"]["rss_mb"] > 800:
                metrics["recommendations"].append("High memory usage detected - consider reducing concurrent uploads")

        except ImportError:
            metrics["memory"] = {"error": "psutil not available"}
        
        # Processing metrics
        files_info = await hash_store.list_all_files()
        metrics["processing"] = {
            "total_files": len(files_info),
            "completed_files": len([f for f in files_info if f.get("status") == "complete"]),
            "average_file_size_mb": round(
                sum(f.get("file_size", 0) for f in files_info) / max(len(files_info), 1) / (1024*1024), 2
            )
        }
        
        # Cache metrics
        if settings.cache.ENABLE_QUERY_CACHE:
            cache_stats = await query_store.get_cache_stats()
            metrics["cache"] = cache_stats
            
            # Cache recommendations
            if cache_stats.get("valid_entries", 0) > settings.cache.CACHE_MAX_ENTRIES * 0.9:
                metrics["recommendations"].append("Query cache near capacity - consider increasing CACHE_MAX_ENTRIES")
        
        # Configuration recommendations
        memory_config = settings.get_memory_configuration()
        if memory_config["max_file_size_mb"] > 50 and settings.processing.MAX_CONCURRENT_UPLOADS > 2:
            metrics["recommendations"].append("Large file support with high concurrency may cause memory issues")
        
        # Audit log
        admin_user = request.state.current_user
        await audit_logger.log_event(
            event_type="system_metrics_viewed",
            user_id=admin_user.user_id,
            email=admin_user.email,
            ip_address=request.client.host,
            success=True
        )

        return metrics
        
    except Exception as e:
        logger.error(f"Failed to get performance metrics: {e}")
        # return {"error": str(e), "timestamp": int(time.time())}
        return {"error": str(e), "timestamp": datetime.now(UTC).isoformat()}