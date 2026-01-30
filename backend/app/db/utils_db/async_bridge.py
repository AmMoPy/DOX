# Future self: "Bridge masks whatever is passed to it with a coroutine execution"

import asyncio
import functools
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Any, Awaitable
import logging

logger = logging.getLogger(__name__)


class AsyncBridge:
    """
    Centralized thread pool management (async/sync)
    The bridge is specifically designed for concurrent execution 
    It wraps synchronous functions in coroutines that can run in 
    thread pools concurrently with true async operations.

    It's a general-purpose tool for any blocking call (async event loop) during runtime 
    """
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                # General rule for max_workers in:
                # ThreadPoolExecutor -> Cores * 5 to 10 (assuming existance of enough RAM)
                # ProcessPoolExecutor -> Number of Physical Cores
                cls._instance._db_executor = ThreadPoolExecutor(
                    max_workers=5, 
                    thread_name_prefix="db_sync"
                )
                cls._instance._io_executor = ThreadPoolExecutor(
                    max_workers=3, 
                    thread_name_prefix="io_sync"
                )
                cls._instance._emb_executor = ThreadPoolExecutor(
                    # single queries should be fast anyway and concurrent batch uploads are not frequent 
                    # since embedding generation is CPU-intensive and we are using a lock, having many 
                    # threads might not actually speed things up due to the Global Interpreter Lock (GIL) 
                    # contention and the overhead of acquiring/releasing the lock. However, potentially 
                    # creating a small queueing delay and  if traffic spikes hitting the server with complex 
                    # queries at the exact same millisecond constantly.
                    max_workers=2, # prioritizes stability and thread safety over raw, uncapped throughput
                    thread_name_prefix="emb_sync"
                )
        return cls._instance
    

    async def run_in_db_thread(self, func: Callable, *args, **kwargs) -> Any:
        """
        Run database sync operations in dedicated thread pool

        Bridge accepts *args, **kwargs, so lambda is OPTIONAL:
        await async_bridge.run_in_db_thread(conn.execute, query, params)  # Works
        await async_bridge.run_in_db_thread(lambda: conn.execute(query, params))  # Also works

        Example when combined with circuit breaker:
        await sql_cb.execute(
            async_bridge.run_in_db_thread(lambda: conn.execute(query, params))
        ) # Flow: lambda -> bridge -> coroutine -> circuit breaker -> await coroutine
        """
        try:
            loop = asyncio.get_event_loop()
            partial_func = functools.partial(func, *args, **kwargs) # Binds parameters (accepts *args, **kwargs)
            return await loop.run_in_executor(self._db_executor, partial_func) # coroutines - they work exactly like true async methods with gather()
        except asyncio.CancelledError:
            logger.warning(f"DB thread operation cancelled: {func.__name__}")
            raise  # Re-raise cancellation so caller knows
        except Exception as e:
            logger.error(f"Error in DB thread execution {func.__name__}: {str(e)}")
            raise # TODO: Either re-raise or return error object based needs


    async def run_in_io_thread(self, func: Callable, *args, **kwargs) -> Any:
        """Run I/O sync operations in dedicated thread pool"""
        try:
            loop = asyncio.get_event_loop()
            partial_func = functools.partial(func, *args, **kwargs)
            return await loop.run_in_executor(self._io_executor, partial_func)
        except asyncio.CancelledError:
            logger.warning(f"IO thread operation cancelled: {func.__name__}")
            raise
        except Exception as e:
            logger.error(f"Error in IO thread execution {func.__name__}: {str(e)}")
            raise       


    async def run_in_emb_thread(self, func: Callable, *args, **kwargs) -> Any:
        """Run embedding sync operations in dedicated thread pool"""
        try:
            loop = asyncio.get_event_loop()
            partial_func = functools.partial(func, *args, **kwargs)
            return await loop.run_in_executor(self._emb_executor, partial_func)
        except asyncio.CancelledError:
            logger.warning(f"EMB thread operation cancelled: {func.__name__}")
            raise
        except Exception as e:
            logger.error(f"Error in EMB thread execution {func.__name__}: {str(e)}")
            raise     
    

    def cleanup(self):
        """Clean up executors"""
        
        if hasattr(self, '_db_executor'):
            try:
                self._db_executor.shutdown(wait=True)
                logger.info("DB executor shutdown completed")
            except Exception as e:
                logger.error(f"Error shutting down DB executor: {str(e)}")
        
        if hasattr(self, '_io_executor'):
            try:
                self._io_executor.shutdown(wait=True)
                logger.info("IO executor shutdown completed")
            except Exception as e:
                logger.error(f"Error shutting down IO executor: {str(e)}")

        if hasattr(self, '_emb_executor'):
            try:
                self._emb_executor.shutdown(wait=True)
                logger.info("EMB executor shutdown completed")
            except Exception as e:
                logger.error(f"Error shutting down EMB executor: {str(e)}")


# Global instance
async_bridge = AsyncBridge()