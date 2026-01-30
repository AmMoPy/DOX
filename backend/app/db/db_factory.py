import logging
from threading import Lock
from app.config.setting import settings
from app.auth.hash_service import token_hasher # global instance

logger = logging.getLogger(__name__)

class DatabaseFactory:
    """Factory pattern for selecting database implementations"""

    # SINGLETON STRATEGY (reference Note):
    # This codebase uses THREE singleton patterns intentionally:
    # 1. PostgreSQL Pool: Module singleton (pg_pool)
    #    - Reason: Can't use __new__ with asyncio.Lock
    #    - Pattern: instance = PoolClass() at module level
    # 2. SQLite Pool/ChromaDB: Class singleton via __new__
    #    - Reason: Demonstrate __new__ pattern for sync resources
    #    - Pattern: Override __new__ with threading.Lock
    # 3. Factory: Instance caching
    #    - Reason: Convenience + defense in depth
    #    - Pattern: Class method caches returned instances
    # For production, simplify to ONE pattern (likely factory-only or module-only).
    # This hybrid exists for reference purposes.

    # factory caches instances -> Singleton at factory level
    # but also classes enforce singleton -> Singleton at class level
    # Double singleton protection! (Redundant but Safe)
    _auth_store_instance = None
    _hash_store_instance = None
    _doc_store_instance = None
    _query_store_instance = None
    _lock = Lock()

    @classmethod
    def get_auth_store(cls):
        """Get appropriate auth store implementation"""
        with cls._lock:
            if cls._auth_store_instance is None:
                if settings.use_postgres('auth'):
                    logger.debug("Using PostgreSQL Auth Store")
                    from app.db.db_auth.auth_store_pg import PostgreSQLAuthStore
                    cls._auth_store_instance = PostgreSQLAuthStore(token_hasher)
                else:
                    logger.debug("Using SQLite Auth Store")
                    from app.db.db_auth.auth_store_sql import SQLiteAuthStore
                    cls._auth_store_instance = SQLiteAuthStore(token_hasher)
            
            return cls._auth_store_instance


    @classmethod
    def get_hash_store(cls):
        """Get appropriate hash manager implementation"""
        with cls._lock:
            if cls._hash_store_instance is None:
                if settings.use_postgres('file'):
                    logger.debug("Using PostgreSQL Hash Store")
                    from app.db.db_hash.hash_store_pg import PostgreSQLHashStore
                    cls._hash_store_instance = PostgreSQLHashStore()
                else:
                    logger.debug("Using SQLite Hash Store")
                    from app.db.db_hash.hash_store_sql import SQLiteHashStore
                    cls._hash_store_instance = SQLiteHashStore()
            
            return cls._hash_store_instance


    @classmethod
    def get_doc_store(cls):
        """Get appropriate vector store implementation"""
        with cls._lock:
            if cls._doc_store_instance is None:
                if settings.use_postgres('doc'):
                    logger.debug("Using PostgreSQL Document Store with pgvector")
                    from app.db.db_vector.doc_store_pg import PostgreSQLDocStore
                    cls._doc_store_instance = PostgreSQLDocStore()
                else:
                    logger.debug("Using ChromaDB Document Store")
                    from app.db.db_vector.doc_store_cdb import ChromaDocStore
                    cls._doc_store_instance = ChromaDocStore()
            
            return cls._doc_store_instance
    

    @classmethod
    def get_query_cache(cls):
        """Get appropriate query cache implementation"""
        with cls._lock:
            if not settings.cache.ENABLE_QUERY_CACHE:
                return None
                
            if cls._query_store_instance is None:
                if settings.use_postgres('query'):
                    logger.debug("Using PostgreSQL Query Store")
                    from app.db.db_query.query_store_pg import PostgreSQLQueryStore
                    cls._query_store_instance = PostgreSQLQueryStore()
                else:
                    logger.debug("Using ChromaDB Query Store")
                    from app.db.db_query.query_store_cdb import ChromaQueryStore
                    cls._query_store_instance = ChromaQueryStore()
            
            return cls._query_store_instance
        

    @classmethod
    def reset_instances(cls):
        """Reset all instances (useful for testing)"""
        cls._auth_store_instance = None
        cls._hash_store_instance = None
        cls._doc_store_instance = None
        cls._query_store_instance = None


# These singleton instances will be distributed early across the app as "shells" 
# that get populated during the explicit initialization phase, It is critical to ensure that
# all callers respects the following:
# 1. No operations are performed on stores before initialize()
# 2. All initialization happens before any real usage
# 3. No lazy imports trigger operations during import time
auth_store = DatabaseFactory.get_auth_store()
hash_store = DatabaseFactory.get_hash_store()
doc_store = DatabaseFactory.get_doc_store()
query_store = DatabaseFactory.get_query_cache()