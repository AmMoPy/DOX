import asyncpg # core asynchronous PostgreSQL driver for Python (talk to the database)
import asyncio
import logging
import time
from typing import Optional, Dict, Any
from contextlib import asynccontextmanager
from pgvector.asyncpg import register_vector # specialized codec (type handler), enable native language support for vector embeddings.
from app.config.setting import settings
from app.db.utils_db.circuit_breaker import pg_cb, DatabaseError

logger = logging.getLogger(__name__)


class PostgreSQLPoolManager:
    """
    Lightweight shared connection pool for PostgreSQL.
    Components manage their own schemas.
    """
    def __init__(self):
        self.pool: Optional[asyncpg.Pool] = None
        self._initialized = False
        self._component_registry = {}
        self._lock = asyncio.Lock()

    async def initialize(self, component_name: str, schema_version: str = "1.0"):
        """
        Initialize pool on first component request.
        Track which components are using the pool.
        """
        async with self._lock:
            # Register component
            self._component_registry[component_name] = {
                "schema_version": schema_version,
                "initialized_at": time.time()
            }
            
            if self._initialized:
                logger.debug(f"PostgreSQL pool already initialized, registering {component_name}")
                return

            try:
                logger.info("Initializing shared PostgreSQL connection pool...")
                
                database_url = settings.database.get_pg_db_url()
                
                # Single connection pool configuration
                self.pool = await asyncpg.create_pool(
                    database_url,
                    min_size=settings.database.PG_POOL_MIN_SIZE,
                    max_size=settings.database.PG_POOL_MAX_SIZE,
                    max_queries=settings.database.PG_POOL_MAX_QUERIES,
                    max_inactive_connection_lifetime=settings.database.PG_POOL_MAX_INACTIVE,
                    command_timeout=settings.database.PG_CONNECTION_TIMEOUT,
                    server_settings={
                        # these settings are applied on a per-session 
                        # basis when a connection is created in the pool
                        'jit': 'off',
                        # 'shared_preload_libraries': 'vector',  # Always enable (no-op if not used, apply manually as it requires full server restart)
                        'work_mem': settings.database.PG_WORK_MEM,
                        'maintenance_work_mem': settings.database.PG_MAINT_MEM,
                        'effective_cache_size': settings.database.PG_CACHE_SIZE,
                        'random_page_cost': settings.database.PG_RANDOM_PAGE_COST,
                        'timezone': settings.database.PG_TIMEZONE
                        # 'hnsw.ef_search': str(settings.database.DOC_HNSW_SEARCH_EF) # applies to all queries, less flexible
                    },
                    init=self._on_connect_init # This runs on every new connection, register pgvector codecs
                )
                
                # Enable extensions (idempotent, safe to call multiple times)
                async with self.pool.acquire() as conn:
                    # ensure the server extension enabled first via shared_preload_libraries
                    await conn.execute('CREATE EXTENSION IF NOT EXISTS vector')
                
                self._initialized = True
                logger.info(
                    f"PostgreSQL pool created "
                    f"(component: {component_name}, "
                    f"connections: {self.pool.get_min_size()}-{self.pool.get_max_size()})"
                )
                
            except Exception as e:
                logger.error(f"Failed to initialize PostgreSQL pool: {e}")
                raise DatabaseError(f"Pool initialization failed: {e}")


    @asynccontextmanager
    async def get_connection(self, max_retries: int = 3, timeout: float = 10.0, context: str = None):
        """Get connection from pool with retry logic and error handling"""
        if not self._initialized:
            raise DatabaseError("PostgreSQL pool not initialized")
        
        ctx = f"for '{context}' " if context else '' # only display when needed (e.g.: no CB call, let pool provide context)
        
        for attempt in range(max_retries):
            try:
                # Add timeout to prevent indefinite blocking
                async with asyncio.timeout(timeout):
                    async with self.pool.acquire() as conn:
                        yield conn
                        return  # Exit successfully

            except asyncio.TimeoutError:
                if attempt == max_retries - 1:
                    raise DatabaseError(
                        f"Connection pool timeout {ctx}- too many concurrent requests"
                        )
                await asyncio.sleep(0.5 * (2 ** attempt))
            except asyncpg.TooManyConnectionsError as e:
                logger.error(f"Connection pool exhausted: {e}")
                # don't retry - backpressure at app level
                raise DatabaseError(
                    f"Connection pool exhausted {ctx}- reduce concurrency"
                    ) 
            except asyncpg.PostgresConnectionError as e:
                logger.error(f"PostgreSQL connection failed: {e}")
                raise DatabaseError(f"Database connection lost: {e}")
            except asyncpg.PostgresError as e:
                logger.error(f"PostgreSQL error: {e}")
                raise DatabaseError(f"Database error:: {e}")
            except Exception as e:
                if attempt == max_retries - 1:
                    logger.error(f"Unexpected connection error: {e}")
                    raise DatabaseError(f"Unexpected database connection error {ctx}: {e}")

                logger.warning(f"Connection retry {ctx}{attempt + 1}/{max_retries}: {e}")
                await asyncio.sleep(0.1 * (2 ** attempt))


    async def get_pool_stats(self) -> Dict[str, Any]:
        """Get connection pool statistics"""
        if not self.pool:
            return {"status": "not_initialized"}
        
        size = self.pool.get_size()
        idle_connections = self.pool.get_idle_size()

        return {
            "status": "initialized",
            "size": size,
            "min_size": self.pool.get_min_size(),
            "max_size": self.pool.get_max_size(),
            "idle_connections": idle_connections,
            "active_connections": size - idle_connections,
            "active_components": list(self._component_registry.keys()),
            "component_count": len(self._component_registry)
        }


    async def health_check(self) -> dict:
        """Check pool health"""
        if not self._initialized:
            return {"status": "not_initialized"}
        
        try:
            async with self.get_connection() as conn:
                await conn.fetchval('SELECT 1')
            
                # Get database-level metrics
                db_metrics = await conn.fetchrow('''
                    SELECT 
                        pg_database_size(current_database()) as db_size_bytes,
                        (SELECT COUNT(*) FROM pg_stat_activity WHERE state = 'active') as active_db_connections,
                        (SELECT setting::int FROM pg_settings WHERE name = 'max_connections') as max_db_connections
                ''')

            pool_stats = await self.get_pool_stats()

            return {
                "status": "healthy",
                "pool": pool_stats,
                "database": {
                    "size_mb": db_metrics['db_size_bytes'] / (1024 * 1024),
                    "active_connections": db_metrics['active_db_connections'],
                    "max_connections": db_metrics['max_db_connections']
                    },
                "circuit_breaker": {
                    "failures": pg_cb.failures,
                    "is_open": pg_cb.is_open()
                }
            }
        except Exception as e:
            return {"status": "unhealthy", "error": str(e)}


    async def unregister_component(self, component_name: str):
        """
        Unregister component from pool.
        Close pool only when all components are done.
        """
        async with self._lock:
            self._component_registry.pop(component_name, None)
            
            # Only close when no active component - pool is shared!
            if not self._component_registry and self.pool:
                logger.info("All components closed, closing PostgreSQL pool")
                await self.pool.close()
                self.pool = None
                self._initialized = False


    async def close(self):
        """Force close pool (for shutdown)"""
        async with self._lock:
            if self.pool:
                logger.info("Forcefully closing PostgreSQL pool")
                await self.pool.close()
                self.pool = None
                self._initialized = False
                self._component_registry.clear()


    async def _on_connect_init(self, conn):
        """Register pgvector codecs when a new connection is established."""
        await register_vector(conn)
        # add other per-connection setup here if needed


# Module singleton (Forced by async (can't use __new__ with async lock))
pg_pool = PostgreSQLPoolManager()