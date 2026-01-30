import asyncpg
import asyncio
import logging
from uuid import UUID
from datetime import datetime, UTC
from typing import Optional, Dict, Any
from app.config.setting import settings
from app.db.utils_db.pg_pool_mngr import pg_pool
from app.db.utils_db.async_bridge import async_bridge
from app.db.utils_db.services_search import search_service
from app.db.utils_db.circuit_breaker import pg_cb, DatabaseError

logger = logging.getLogger(__name__)


class PostgreSQLQueryStore:
    """
    Standalone Vectorized query store using shared pool 
    and PostgreSQL pgvector for semantic similarity
    """
    
    def __init__(self):
        """initializing the attributes of the already created instance"""
        self._lock = asyncio.Lock()
        self._initialized = False
        self.COMPONENT_NAME = "query_store"
        self.SCHEMA_VERSION = "1.0"
        self.similarity_threshold = settings.cache.QUERY_SIMILARITY_THRESHOLD
        self.ttl_hours = settings.cache.CACHE_DEFAULT_TTL_HOURS
        self._init_search_config()

    
    def _init_search_config(self):
        """Initialize search configurations"""
        config_params = {} # populate as needed
        
        # Update search service config
        search_service.update_config(**config_params)


    async def initialize(self):
        """Initialize with optimized PostgreSQL settings"""
        async with self._lock:
            if self._initialized:
                return

            try:
                logger.debug("Initializing PostgreSQL Query Store...")
    
                # Register with shared pool
                await pg_pool.initialize(self.COMPONENT_NAME, self.SCHEMA_VERSION)
     
                # Setup own schema
                async with pg_pool.get_connection() as conn:
                    await pg_cb.execute(
                        lambda: self._setup_schema(conn)
                        )
                    
                self._initialized = True
                logger.debug("PostgreSQL Query Store initialized")
                
            except Exception as e:
                logger.error(f"Failed to initialize PostgreSQL query store: {e}")
                # raise
                raise DatabaseError(f"Unexpected database initialization error: {e}")

    
    async def _setup_schema(self, conn: asyncpg.Connection):
        """Setup optimized database schema"""

        # Create main table with correct data types and constraints
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS vectorized_query_cache (
                cache_key TEXT PRIMARY KEY,
                user_id UUID NOT NULL,
                question_text TEXT NOT NULL,
                question_embedding vector(384), -- Adjust dimension based on model used
                response_text TEXT NOT NULL,
                provider_used TEXT NOT NULL,
                tokens_used INTEGER DEFAULT 0 CHECK (tokens_used >= 0),
                response_time_ms INTEGER DEFAULT 0 CHECK (response_time_ms >= 0),
                created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMPTZ NOT NULL,
                hit_count INTEGER DEFAULT 0 CHECK (hit_count >= 0),
                last_accessed TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                response_length INTEGER GENERATED ALWAYS AS (length(response_text)) STORED
            )
        ''')
        
        # Create optimized indexes for different query patterns
        indexes = [
            'CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_vec_qcache_valid ON vectorized_query_cache(expires_at DESC)', # B-tree index
            'CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_vec_qcache_user ON vectorized_query_cache(user_id, last_accessed DESC)',
            'CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_vec_qcache_hit_count ON vectorized_query_cache(hit_count DESC, last_accessed DESC)',
            'CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_vec_qcache_provider ON vectorized_query_cache(provider_used, created_at)',
            # HNSW index for semantic similarity search (most important for performance)
            f'''CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_vec_qcache_embedding_hnsw 
               ON vectorized_query_cache USING hnsw (question_embedding vector_cosine_ops) 
               WITH (
                m = {settings.database.QUERY_HNSW_M}, 
                ef_construction = {settings.database.QUERY_HNSW_CONSTRUCTION_EF}
            )'''
        ]
        
        for index in indexes:
            try:
                await conn.execute(index)
                logger.debug(f"Index creation success")
            except Exception as e:
                logger.debug(f"Index creation note: {e}")
        
        # create materialized view for analytics, materialized view is a
        # cashed copy of a query stored on disk, only re-runs calculations
        # only when the view is refreshed, otherwise it returns the data of
        # initial creation
        await conn.execute('''
            CREATE MATERIALIZED VIEW IF NOT EXISTS vec_cache_analytics AS -- This runs the query immediately and populates the view
            SELECT 
                provider_used,
                COUNT(*) as total_entries,
                COUNT(*) FILTER (WHERE expires_at > CURRENT_TIMESTAMP) as valid_entries,
                SUM(hit_count) as total_hits,
                AVG(hit_count) as avg_hits_per_query,
                AVG(response_time_ms) as avg_response_time,
                AVG(response_length) as avg_response_length,
                PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY response_time_ms) as median_response_time,
                PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY response_time_ms) as p95_response_time
            FROM vectorized_query_cache
            GROUP BY provider_used
        ''')

        # Add a Unique Index to the Materialized View
        # This is the crucial step that enables the CONCURRENTLY refresh
        await conn.execute('''
            CREATE UNIQUE INDEX IF NOT EXISTS idx_vec_cache_analytics_provider 
            ON vec_cache_analytics(provider_used)
        ''')
        
        # Create function for batch cleanup
        await conn.execute('''
            CREATE OR REPLACE FUNCTION cleanup_expired_vec_cache(batch_size INTEGER DEFAULT 1000)
            RETURNS INTEGER AS $$ 
            DECLARE
                deleted_count INTEGER := 0;
                total_deleted INTEGER := 0;
            BEGIN
                LOOP
                    DELETE FROM vectorized_query_cache 
                    WHERE cache_key IN (
                        SELECT cache_key FROM vectorized_query_cache 
                        WHERE expires_at <= CURRENT_TIMESTAMP 
                        LIMIT batch_size
                    );
                    
                    GET DIAGNOSTICS deleted_count = ROW_COUNT;
                    total_deleted := total_deleted + deleted_count;
                    
                    EXIT WHEN deleted_count = 0;
                    PERFORM pg_sleep(0.01);
                END LOOP;
                
                IF total_deleted > 100 THEN
                    REFRESH MATERIALIZED VIEW CONCURRENTLY vec_cache_analytics;
                    ANALYZE vectorized_query_cache;
                END IF;
                
                RETURN total_deleted;
            END;
            $$ LANGUAGE plpgsql;
        ''')
        
        logger.debug("Query store schema setup completed")

    
    async def search(self, question: str, cache_key: str, user_id: UUID) -> Optional[Dict[str, Any]]:
        """Optimized search"""

        if not question or not isinstance(question, str) or not question.strip():
            return None

        try:
            # Semantic search only
            logger.info(f"Searching for question: '{question[:100]}'")
            
            # Exact search
            result = await self._find_exact_query(cache_key)
            question_text = result.get('question_text')

            if question_text:
                similarity_score = 1
                match_type = "exact"

                logger.info(f"Exact query cache HIT: '{question_text[:50]}...'")

            else:
                # Semantic search
                result = await self._find_similar_query(question)
                question_text = result.get('question_text')
                
                # Check if we have any results
                if not question_text:
                    logger.info("No cached queries found")
                    return None

                # Strict threshold check
                # The SQL function returns similarity directly
                similarity_score = float(result['similarity'])

                if similarity_score < self.similarity_threshold:
                    logger.debug(
                        f"Cached query below threshold: {similarity_score:.2%} < {self.similarity_threshold:.2%}"
                    )
                    return None

                match_type = "semantic"
        
                logger.info(
                    f"Semantic query cache HIT: {similarity_score:.2%} - '{question_text[:50]}...'"
                )
                
            # Check expiration
            expires_at = result['expires_at']
            if expires_at <= datetime.now(UTC):
                logger.debug("Cached query expired")
                # TODO: delete expired entry here?
                return None

            # Update hit count for semantic match 
            asyncio.create_task(self._update_stats_async(result["cache_key"]))

            return {
                'question_text': question_text,
                'response_text': result["response_text"],
                'provider_used': result["provider_used"],
                'similarity_score': similarity_score,
                'hit_count': result["hit_count"] + 1, # account for current hit
                'cache_level': "postgresdb",
                'match_type': match_type,
                'expires_at': expires_at
            }

        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Search failed: {e}")
            # return None # TODO: RAISE?
            raise DatabaseError(f"Unexpected database search error: {e}")


    async def _find_exact_query(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """Fast exact match lookup - no embedding computation"""
        try:
            async with pg_pool.get_connection() as conn:
                result = await conn.fetchrow("""
                    SELECT cache_key, question_text, response_text, 
                           provider_used, created_at, hit_count,
                           tokens_used, response_time_ms, expires_at
                    FROM vectorized_query_cache 
                    WHERE cache_key = $1 AND expires_at > CURRENT_TIMESTAMP
                """, cache_key)
 
                if result:
                    return result

                return {}
            
        except Exception as e:
            logger.warning(f"Exact query cache search failed: {e}")
            # return None
            raise DatabaseError(f"Unexpected database exact query search error: {e}")


    async def _find_similar_query(
        self, 
        question: str
    ) -> Optional[Dict[str, Any]]:
        """
        Find semantically similar cached query
        
        Returns cached answer if similarity >= threshold, else None
        
        Args:
            question: Original user question (NOT enhanced)
        
        Returns:
            Dict with response_text, similarity_score, etc. or None
        """
        try:
            question_embedding = await async_bridge.run_in_emb_thread(
                search_service.get_embedding,
                question
            )
             
            async with pg_pool.get_connection() as conn:
                # SET LOCAL: sets the configuration parameter only for the duration of the current
                # transaction (async with pg_pool.get_connection())
                await conn.execute(f"SET LOCAL hnsw.ef_search = {settings.database.QUERY_HNSW_SEARCH_EF};")

                similar_result = await conn.fetchrow('''
                    SELECT
                        cache_key,
                        question_text,
                        response_text,
                        provider_used,
                        created_at,
                        hit_count,
                        tokens_used,
                        response_time_ms,
                        expires_at,
                        1 - (question_embedding <=> $1) as similarity
                    FROM vectorized_query_cache
                    WHERE expires_at > CURRENT_TIMESTAMP
                    AND 1 - (question_embedding <=> $1) >= $2
                    ORDER BY question_embedding <=> $1
                    LIMIT 1
                    ''', question_embedding, self.similarity_threshold
                    )
                
                if similar_result:
                    return similar_result
                
                return {}

        except Exception as e:
            logger.error(f"Semantic query cache search failed: {e}")
            # return None
            raise DatabaseError(f"Unexpected database semantic query search error: {e}")

    
    async def _update_stats_async(self, cache_key: str):
        """Update statistics asynchronously"""
        try:
            async with pg_pool.get_connection() as conn:
                await pg_cb.execute( # CB optional (non-critical)
                    lambda: conn.execute('''
                        UPDATE vectorized_query_cache 
                        SET hit_count = hit_count + 1, last_accessed = CURRENT_TIMESTAMP
                        WHERE cache_key = $1
                    ''', cache_key
                    )
                )
        except DatabaseError:
            raise         
        except Exception as e:
            logger.error(f"Failed to update cache stats: {e}")
            raise DatabaseError(f"Unexpected database cache stats update error: {e}") # TODO: fail silently?

        
    async def store_response(
        self, 
        question: str,  # original question
        cache_key: str, # question cash key
        response: str,
        provider_used: str, 
        user_id: UUID,
        tokens_used: int = 0, 
        response_time_ms: int = 0,
        ttl_hours: Optional[int] = None
    ) -> bool:
        """Store response with vectorized indexing"""  
        try:
            # Get embedding
            question_embedding = await async_bridge.run_in_emb_thread(
                search_service.get_embedding,
                question
            )

            # set expiration
            ttl = ttl_hours or self.ttl_hours
            
            # Store in database
            async with pg_pool.get_connection() as conn:
                await pg_cb.execute(
                    lambda: conn.execute('''
                        INSERT INTO vectorized_query_cache 
                        (cache_key, user_id, question_text, question_embedding, response_text,
                         provider_used, tokens_used, response_time_ms, expires_at, 
                         hit_count, last_accessed)
                        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 
                                CURRENT_TIMESTAMP + (INTERVAL '1 hour' * $9), 0, CURRENT_TIMESTAMP)
                        ON CONFLICT (cache_key) DO UPDATE SET
                            response_text = EXCLUDED.response_text,
                            question_embedding = EXCLUDED.question_embedding,
                            provider_used = EXCLUDED.provider_used,
                            expires_at = EXCLUDED.expires_at,
                            last_accessed = CURRENT_TIMESTAMP
                    ''',
                    cache_key, user_id, question[:1000], question_embedding, response,
                    provider_used, tokens_used, response_time_ms, ttl)
                )
                        
            logger.debug(f"Stored vectorized query for {cache_key[:8]}...")
            return True
        
        except DatabaseError:
            raise    
        except Exception as e:
            logger.error(f"Failed to store vectorized query: {e}")
            # return False
            raise DatabaseError(f"Unexpected database query storing error: {e}")

    
    async def cleanup_expired(self) -> int:
        """Cleanup expired entries"""
        try:
            async with pg_pool.get_connection() as conn:
                db_cleaned = await pg_cb.execute(
                    lambda: conn.fetchval('SELECT cleanup_expired_vec_cache(1000)')
                )
            
            total_cleaned = db_cleaned
            logger.debug(f"Cleaned {total_cleaned} expired entries (DB: {db_cleaned}")
            return total_cleaned
        
        except DatabaseError:
            raise          
        except Exception as e:
            logger.error(f"Cleanup failed: {e}")
            # return 0
            raise DatabaseError(f"Unexpected database cleanup error: {e}")

    
    async def get_cache_stats(self) -> Dict[str, Any]:
        """Get comprehensive cache statistics"""
        try:
            async with pg_pool.get_connection() as conn:
                # Refresh analytics on-demand when stats are requested
                await conn.execute('REFRESH MATERIALIZED VIEW CONCURRENTLY vec_cache_analytics')

                # Basic statistics - fresh
                basic_stats = await conn.fetchrow('''
                    SELECT 
                        COUNT(*) as total_entries,
                        COUNT(*) FILTER (WHERE expires_at > CURRENT_TIMESTAMP) as valid_entries,
                        SUM(hit_count) as total_hits,
                        AVG(hit_count) as avg_hits_per_query,
                        AVG(response_time_ms) as avg_response_time,
                        pg_size_pretty(pg_total_relation_size('vectorized_query_cache')) as table_size
                    FROM vectorized_query_cache
                ''')
                

                # Provider analytics
                provider_stats = await conn.fetch('SELECT * FROM vec_cache_analytics ORDER BY total_hits DESC')
            
            # Connection pool stats
            pool_stats = await pg_pool.get_pool_stats()
            
            return {
                "database_stats": {
                    "total_entries": basic_stats["total_entries"],
                    "valid_entries": basic_stats["valid_entries"],
                    "expired_entries": basic_stats["total_entries"] - basic_stats["valid_entries"],
                    "total_hits": basic_stats["total_hits"],
                    "hit_rate": (basic_stats["total_hits"] / max(basic_stats["total_entries"], 1)) * 100 if basic_stats["total_hits"] else 0,
                    "avg_hits_per_query": basic_stats["avg_hits_per_query"],
                    "avg_response_time_ms": basic_stats["avg_response_time"],
                    "table_size": basic_stats["table_size"]
                },
                "provider_usage": {
                    row["provider_used"]: {
                        "total_entries": row["total_entries"],
                        "valid_entries": row["valid_entries"],
                        "total_hits": row["total_hits"],
                        "avg_hits": row["avg_hits_per_query"],
                        "avg_response_time": row["avg_response_time"],
                        "median_response_time": row["median_response_time"],
                        "p95_response_time": row["p95_response_time"]
                    } for row in provider_stats
                },
                "connection_pool": pool_stats,
                "circuit_breaker": {
                    "failures": pg_cb.failures,
                    "is_open": pg_cb.is_open()
                },
                "database_type": "PostgreSQL with pgvector",
                "features": ["exact_match", "semantic_similarity", "context_matching", "hnsw_index"]
            }
            
        except Exception as e:
            logger.error(f"Failed to get stats: {e}")
            raise DatabaseError(f"Unexpected database stats error: {e}")

    
    async def health_check(self) -> Dict[str, Any]:
        """Comprehensive health check"""
        try:
            async with pg_pool.get_connection() as conn:
                # Test connectivity and pgvector
                await conn.fetchval('SELECT 1')
                extension_check = await conn.fetchval('''
                    SELECT EXISTS(SELECT 1 FROM pg_extension WHERE extname = 'vector')
                ''')
                
                if not extension_check:
                    return {"status": "unhealthy", "error": "pgvector extension not available"}
                
                # Get counts
                total_entries = await conn.fetchval('SELECT COUNT(*) FROM vectorized_query_cache')
                valid_entries = await conn.fetchval('''
                    SELECT COUNT(*) FROM vectorized_query_cache 
                    WHERE expires_at > CURRENT_TIMESTAMP
                ''')
            
            if pg_cb.is_open():
                status = "degraded"
                error = "circuit breaker open"
            else:
                status = "healthy"
                error = None
            
            health_info = {
                "status": status,
                "database_type": "PostgreSQL with pgvector",
                "total_entries": total_entries,
                "valid_entries": valid_entries,
                "circuit_breaker_status": "open" if pg_cb.is_open() else "closed"
            }

            if error:
                health_info["error"] = error

            return health_info
            
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return {"status": "unhealthy", "error": str(e)}
            # raise DatabaseError(f"Unexpected database health check error: {e}")

    
    async def close(self):
        """Cleanup resources"""
        async with self._lock:
            if self._initialized:
                try:     
                    # Cleanup search service first
                    search_service.cleanup()
                    
                    # Close connection pool gracefully
                    await pg_pool.unregister_component(self.COMPONENT_NAME)
                    self._initialized = False
                    # logger.debug("Query store closed successfully")

                except Exception as e:
                    logger.error(f"Error closing query store: {e}")
                    raise DatabaseError(f"Unexpected database closing error: {e}")
