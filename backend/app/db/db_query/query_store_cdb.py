import chromadb
import logging
import asyncio
from uuid import UUID
from threading import Lock
from typing import Optional, Dict, List, Any
from datetime import datetime, timedelta, UTC
from chromadb.config import Settings as ChromaSettings
from app.config.setting import settings
from app.db.utils_db.async_bridge import async_bridge
from app.db.utils_db.services_search import search_service
from app.db.utils_db.circuit_breaker import cdb_cb, DatabaseError

logger = logging.getLogger(__name__)


class ChromaQueryStore:
    """
    Dedicated ChromaDB for query caching
    """
    
    # class attribute
    _lock = Lock()
    _instance = None

    def __new__(cls):
        """Overriding constructor for singleton pattern"""
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance.client = None
                cls._instance._initialized = False
                cls._instance.write_semaphore = asyncio.Semaphore(5)
                cls._instance.similarity_threshold = settings.cache.QUERY_SIMILARITY_THRESHOLD
                cls._instance.ttl_hours = settings.cache.CACHE_DEFAULT_TTL_HOURS
        
            return cls._instance


    async def initialize(self):
        """Initialize query cache with optimized settings"""
        with self._lock:
            if self.client is None and not self._initialized:
                try:
                    logger.debug("Initializing ChromaDB Query Cache...")
                    
                    # Separate database and Single collection for queries
                    self.client, self.collection = await cdb_cb.execute(
                        async_bridge.run_in_db_thread(self._setup_cdb_query)
                    )                   

                    self._initialized = True
                    logger.debug("ChromaDB Query Store initialized successfully!")
                    
                except Exception as e:
                    logger.error(f"Failed to initialize ChromaDB query store: {e}")
                    # raise
                    raise DatabaseError(f"Unexpected database initialization error: {e}")


    def _setup_cdb_query(self):
        """Sync setup for thread pool"""
        chroma_settings = ChromaSettings(
            anonymized_telemetry=False,
            allow_reset=False,
            is_persistent=True,
            persist_directory=str(settings.paths.CHROMA_DB_PATH)
        )

        client = chromadb.PersistentClient(
            path=str(settings.paths.CHROMA_DB_PATH / "queries"),
            settings=chroma_settings
        )

        collection = client.get_or_create_collection(
            name=settings.database.QUERY_COLLECTION_NAME,
            metadata={
                "hnsw:space": settings.database.QUERY_HNSW_SPACE,
                "hnsw:construction_ef": settings.database.QUERY_HNSW_CONSTRUCTION_EF,
                "hnsw:search_ef": settings.database.QUERY_HNSW_SEARCH_EF,
                "hnsw:M": settings.database.QUERY_HNSW_M
            }
        )
        
        return client, collection


    async def search(self, question: str, cache_key: str, user_id: UUID) -> Optional[Dict[str, Any]]:
        """Optimized search"""

        if not question or not isinstance(question, str) or not question.strip():
            return None
        
        try:
            logger.info(f"Searching for question: '{question[:100]}'")

            # exact search avoids calling 
            # embedding model if memory cache fails
            result = await async_bridge.run_in_db_thread(
                lambda: self._find_exact_query(cache_key)
            )

            question_text = result['documents']

            if question_text:
                similarity_score = 1
                match_type = "exact"
                metadata = result['metadatas'][0]

                logger.info(f"Exact query cache HIT: '{question_text[0][:50]}...'")
            # Semantic search fallback
            else:
                # Get embedding for ORIGINAL question (NO enhancement!)
                # This is critical as we want to match user phrasing, not expanded versions
                embedding = await async_bridge.run_in_emb_thread(
                    search_service.get_embedding,
                    question
                )    

                result = await async_bridge.run_in_db_thread(
                    lambda: self._find_similar_query(embedding)
                )

                question_text = result['documents'][0]

                # Check if we have any results
                if not question_text:
                    logger.info("No cached queries found")
                    return None

                # Strict threshold check
                best_distance = result['distances'][0][0] # Lower distance = more similar (0.1-0.2)
                similarity_score = 1.0 - best_distance # Convert distance to similarity
                
                if similarity_score < self.similarity_threshold:
                    logger.info(
                        f"Cached query below threshold: {similarity_score:.2%} < {self.similarity_threshold:.2%}"
                    )
                    return None

                match_type = "semantic"
                metadata = result['metadatas'][0][0]

                logger.info(
                    f"Semantic query cache HIT: {similarity_score:.2%} - '{question_text[0][:50]}...'"
                )
                
            # Check expiration
            expires_at = datetime.fromtimestamp(metadata['expires_at'], UTC)
            if expires_at <= datetime.now(UTC).replace(microsecond=0):
                logger.info("Cached query expired")
                # TODO: delete expired entry here?
                return None

            # Update hit count asynchronously (non-blocking)
            cache_key = metadata.get('cache_key')
            if cache_key:
                asyncio.create_task(self._update_stats_async(cache_key))
                        
            return {
                'question_text': question_text[0],
                'response_text': metadata['response_text'],
                'provider_used': metadata.get('provider_used', 'cached'),
                'similarity_score': similarity_score,
                'hit_count': metadata.get('hit_count', 0) + 1, # account for current hit
                'cache_level': 'chromadb',
                'match_type': match_type,
                'expires_at': expires_at # datetime
            }
        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Search failed: {e}")
            raise DatabaseError(f"Unexpected database search error: {e}")


    def _find_exact_query(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """Fast exact match lookup - no embedding computation"""
        try:
            result = self.collection.get(    
                ids=[cache_key],
                include=["documents", "metadatas"]
            )
    
            return result # example: result = {'ids': ['4f...']...}
            
        except Exception as e:
            logger.warning(f"Exact query search failed: {e}")
            raise DatabaseError(f"Unexpected database exact query search error: {e}")


    def _find_similar_query(
        self, 
        # question: str
        embedding: List[float]
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
            result = self.collection.query(
                query_embeddings=[embedding],
                n_results=1,  # Only need best match
                include=["documents", "metadatas", "distances"]
            )
            
            return result # example: result = {'ids': [['4f...']]...}

        except Exception as e:
            logger.error(f"Semantic query cache search failed: {e}")
            raise DatabaseError(f"Unexpected database semantic query search error: {e}")

    
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
        """
        Store query-response pair in cache

        Returns:
            True if stored successfully
        """
        async with self.write_semaphore: # limits concurrent writes
            try:
                ttl = ttl_hours or self.ttl_hours

                # Generate embedding for ORIGINAL question
                embedding = await async_bridge.run_in_emb_thread(
                    search_service.get_embedding,
                    question
                )    

                await cdb_cb.execute(
                    async_bridge.run_in_db_thread(
                        lambda: self._store_response_op(
                            question, embedding, cache_key, response,
                            provider_used, user_id, tokens_used, response_time_ms, ttl
                        )
                    )
                )
                
                logger.debug(f"Stored query cache entry: {cache_key[:8]}... (TTL: {ttl}h)")

                return True
            
            except DatabaseError: 
                raise
            except Exception as e:
                logger.error(f"Failed to store query in database: {e}")
                # return False
                raise DatabaseError(f"Unexpected database query storing error: {e}")

    
    def _store_response_op(
        self,
        question: str,
        embedding: List[float],
        cache_key: str,
        response: str,
        provider_used: str,
        user_id: UUID,
        tokens_used: int,
        response_time_ms: int,
        ttl_hours: int
    ) -> None:
        """Sync store operation"""

        # Calculate expiration
        current_time = datetime.now(UTC)
        expires_at = current_time + timedelta(hours=ttl_hours)

        # Prepare metadata
        metadata = {
            'cache_key': cache_key,
            'response_text': response,
            'provider_used': provider_used,
            'user_id': str(user_id),
            'tokens_used': tokens_used,
            'response_time_ms': response_time_ms,
            'created_at': int(current_time.timestamp()), # metadata doesnt accept datetime
            'expires_at': int(expires_at.timestamp()),
            'hit_count': 0
        }
        
        # Store
        self.collection.upsert( # upsert creates new entries OR updates existing ones, overwrites existing IDs
            documents=[question], # original question
            embeddings=[embedding],
            ids=[cache_key],
            metadatas=[metadata]
        )  

    
    async def _update_stats_async(self, cache_key: str):
        """Update hit count for cached query (async, non-blocking)"""
        try:
            await async_bridge.run_in_db_thread(
                lambda: self._update_stats_op(cache_key)
            )
      
        except Exception as e:
            logger.warning(f"Failed to update hit count: {e}")
            # raise DatabaseError(f"Unexpected database cache stats update error: {e}")
            # TODO: raise instead of failing silently?


    def _update_stats_op(self, cache_key: str) -> None:
        """Sync stats update"""
        result = self.collection.get(
            ids=[cache_key],
            include=["metadatas"]
        )
        
        if result['metadatas']:
            metadata = result['metadatas'][0]
            metadata['hit_count'] = metadata.get('hit_count', 0) + 1
            
            self.collection.update(
                ids=[cache_key],
                metadatas=[metadata]
            )


    async def cleanup_expired(self) -> int:
        """Remove expired cache entries"""
        try:
            deleted_count = await cdb_cb.execute(
                async_bridge.run_in_db_thread(
                    self._cleanup_expired_op
                )
            )
            
            if deleted_count > 0:
                logger.info(f"Cleaned up {deleted_count} expired entries")
            
            return deleted_count

        except DatabaseError:
            raise            
        except Exception as e:
            logger.error(f"Cleanup failed: {e}")
            # return 0
            raise DatabaseError(f"Unexpected database cleanup error: {e}")

    
    def _cleanup_expired_op(self) -> int:
        """Sync cleanup operation"""
        current_time = int(datetime.now(UTC).timestamp())
        
        all_entries = self.collection.get(include=["metadatas"])
        
        expired_ids = [
            id for id, meta in zip(all_entries['ids'], all_entries['metadatas'])
            if meta['expires_at'] <= current_time
        ]
        
        if expired_ids:
            self.collection.delete(ids=expired_ids)
            return len(expired_ids)
        
        return 0


    async def get_cache_stats(self) -> Dict[str, Any]:
        """Get query cache statistics"""
        try:
            # Get all entries
            all_entries = await async_bridge.run_in_db_thread(
                lambda: self.collection.get(include=["metadatas"])
            )
        
            current_time = int(datetime.now(UTC).timestamp())
            
            total_entries = len(all_entries['ids'])
            valid_entries = sum(
                1 for meta in all_entries['metadatas']
                if meta['expires_at'] > current_time
            )
            expired_entries = total_entries - valid_entries
            
            total_hits = sum(
                meta.get('hit_count', 0) for meta in all_entries['metadatas']
            )
            
            # Provider breakdown
            providers = {}
            for meta in all_entries['metadatas']:
                provider = meta.get('provider_used', 'unknown')
                if provider not in providers:
                    providers[provider] = {'count': 0, 'hits': 0}
                providers[provider]['count'] += 1
                providers[provider]['hits'] += meta.get('hit_count', 0)
            
            return {
                "database_stats": {
                    "total_entries": total_entries,
                    "valid_entries": valid_entries,
                    "expired_entries": expired_entries,
                    "total_hits": total_hits,
                    "hit_rate": (total_hits / max(total_entries, 1))  * 100 if total_hits else 0,
                },
                "provider_usage": providers,
                "circuit_breaker": {
                    "failures": cdb_cb.failures,
                    "is_open": cdb_cb.is_open()
                },
                "database_type": "ChromaDB",
                "features": ["exact_match", "semantic_similarity", "context_matching"]
            }
            
        except Exception as e:
            logger.error(f"Failed to get cache stats: {e}")
            raise DatabaseError(f"Unexpected database stats error: {e}")

    
    async def health_check(self) -> Dict[str, Any]:
        """Health check for query cache"""
        try:
            if not self._initialized:
                return {"status": "unhealthy", "error": "Not initialized"}
            
            # Test query
            test_count = await async_bridge.run_in_db_thread(
                lambda: self.collection.count()
            )

            stats = await self.get_cache_stats()
            
            # Determine health
            status = "healthy" if test_count >= 0 and not cdb_cb.is_open() else "degraded"
            
            health_info = {
                "status": status,
                "database_type": "ChromaDB Query Cache",
                "total_entries": stats.get('total_entries', 0),
                "valid_entries": stats.get('valid_entries', 0),
                "circuit_breaker_status": "open" if cdb_cb.is_open() else "closed"
            }

            if status != "healthy":
                health_info["error"] = "circuit breaker open"

            return health_info
            
        except Exception as e:
            logger.error(f"Query cache health check failed: {e}")
            return {"status": "unhealthy", "error": str(e)}


    async def close(self):
        """Cleanup resources"""
        with self._lock:
            try:
                if self.client is not None:
                    self.client = None
                    self._initialized = False
                    
                # Cleanup search service
                search_service.cleanup()
                
                # logger.info("query store cleaned up")
            except Exception as e:
                logger.error(f"Error closing query store: {e}")
                raise DatabaseError(f"Unexpected database closing error: {e}")