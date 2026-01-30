import asyncpg
import asyncio
import json
import logging
from uuid import UUID
from typing import Optional, Dict, List, Any
from app.config.setting import settings
from app.db.utils_db.pg_pool_mngr import pg_pool
from app.db.utils_db.circuit_breaker import pg_cb, DatabaseError
from app.utils.lsh import LSHFingerprint

logger = logging.getLogger(__name__)


class PostgreSQLHashStore:
    """Standalone hash store using shared PostgreSQL pool"""

    def __init__(self):
        self._lock = asyncio.Lock()
        self._initialized = False
        self.COMPONENT_NAME = "hash_store"
        self.SCHEMA_VERSION = "1.0"

            
    async def initialize(self):
        """Initialize hash store with shared pool"""
        async with self._lock:
            if self._initialized:
                logger.debug("PostgreSQL Hash Store already initialized")
                return

            try:
                logger.debug("Initializing PostgreSQL Hash Store...")

                # Register with shared pool (creates pool if needed)
                await pg_pool.initialize(self.COMPONENT_NAME, self.SCHEMA_VERSION)

                # Setup own schema
                async with pg_pool.get_connection() as conn:
                    await pg_cb.execute(
                        lambda: self._setup_schema(conn)
                        )

                self._initialized = True
                logger.debug("PostgreSQL Hash Store initialized")
                
            except Exception as e:
                logger.error(f"Failed to initialize PostgreSQL hash store: {e}")
                raise DatabaseError(f"Unexpected database initialization error: {e}")

    
    async def _setup_schema(self, conn: asyncpg.Connection):
        """Setup optimized database schema"""

        # Create main table with correct data types and constraints
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS file_hashes (
                file_hash TEXT PRIMARY KEY,
                content_hash TEXT,
                document_id TEXT UNIQUE NOT NULL,
                filename TEXT NOT NULL,
                upload_time TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'processing' CHECK (status IN ('processing', 'complete', 'failed')),
                file_size BIGINT DEFAULT 0 CHECK (file_size >= 0),
                user_id UUID NOT NULL,
                fingerprint_data JSONB,  -- Store full fingerprint for verification
                created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        

        # LSH bucket table for efficient candidate retrieval
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS lsh_buckets (
                bucket_id TEXT NOT NULL,
                band_index SMALLINT NOT NULL,
                document_id TEXT NOT NULL,
                created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (bucket_id, band_index, document_id),
                FOREIGN KEY (document_id) REFERENCES file_hashes(document_id) ON DELETE CASCADE
            )
        ''')


        # Create optimized partial indexes
        indexes = [
            'CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_file_hashes_content_partial ON file_hashes(content_hash) WHERE content_hash IS NOT NULL',
            'CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_file_hashes_processing ON file_hashes(status, upload_time) WHERE status = \'processing\'',
            'CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_file_hashes_user_recent ON file_hashes(user_id, upload_time DESC)',
            'CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS idx_file_hashes_doc_unique ON file_hashes(document_id, file_hash)',
            'CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_lsh_buckets_lookup ON lsh_buckets(bucket_id, band_index)',
            'CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_lsh_buckets_document ON lsh_buckets(document_id)',
        ]
        
        for index in indexes:
            try:
                await conn.execute(index)
                logger.debug(f"Index creation success")
            except Exception as e:
                logger.debug(f"Index creation note: {e}")
        
        # Create triggers and functions
        await conn.execute('''
            CREATE OR REPLACE FUNCTION update_updated_at_column()
            RETURNS TRIGGER AS $$
            BEGIN
                NEW.updated_at = CURRENT_TIMESTAMP;
                RETURN NEW;
            END;
            $$ language 'plpgsql';
        ''')
        
        await conn.execute('''
            DROP TRIGGER IF EXISTS update_file_hashes_updated_at ON file_hashes;
            CREATE TRIGGER update_file_hashes_updated_at 
            BEFORE UPDATE ON file_hashes 
            FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
        ''')
        
        await conn.execute('''
            CREATE OR REPLACE FUNCTION cleanup_old_processing_files(cutoff_minutes INTEGER DEFAULT 30)
            RETURNS INTEGER AS $$
            DECLARE
                deleted_count INTEGER;
            BEGIN
                DELETE FROM file_hashes 
                WHERE status = 'processing' 
                AND upload_time < CURRENT_TIMESTAMP - INTERVAL '1 minute' * cutoff_minutes;
                
                GET DIAGNOSTICS deleted_count = ROW_COUNT;
                RETURN deleted_count;
            END;
            $$ LANGUAGE plpgsql;
        ''')

        logger.debug("Hash store schema setup completed")

    
    async def check_file_hash_exists(self, file_hash: str) -> Optional[Dict]:
        """Check file hash with prepared statement optimization"""

        try:
            async with pg_pool.get_connection() as conn:
                return await self._check_file_hash_operation(conn, file_hash)
            
        except Exception as e:
            logger.error(f"Failed to check file hash: {e}")
            # return None
            raise DatabaseError(f"Unexpected database checking file hash error: {e}")

    
    async def _check_file_hash_operation(self, conn: asyncpg.Connection, file_hash: str):
        result = await conn.fetchrow('''
            SELECT filename, upload_time, document_id, status, user_id
            FROM file_hashes 
            WHERE file_hash = $1 
            LIMIT 1
        ''', file_hash
        )
        
        if result:
            file_info = {
                "filename": result['filename'],
                "upload_time": result['upload_time'].isoformat(),
                "document_id": result['document_id'],
                "status": result['status'],
                "user_id": result['user_id']
            }

            return file_info
        
        return None


    async def store_file_hash(
        self,
        file_hash: str,
        document_id: str,
        filename: str,
        user_id: UUID,
        file_size: int = 0
        ) -> None:
        """Store file hash with atomic duplicate detection"""

        try:
            async with pg_pool.get_connection() as conn:
                await pg_cb.execute(
                    lambda: self._store_file_hash_operation(
                        conn, file_hash, document_id, 
                        filename,  user_id, file_size
                        )
                    )
                logger.debug(f"Stored hash for {filename}")
        
        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to store file hash: {e}")
            raise DatabaseError(f"Unexpected database storing file hash error: {e}")


    async def _store_file_hash_operation(
        self, 
        conn: asyncpg.Connection, 
        file_hash: str, 
        document_id: str, 
        filename: str,
        user_id: UUID,
        file_size: int = 0
    ):
        try:
            # Use INSERT with ON CONFLICT for atomic operation
            result = await conn.execute('''
                INSERT INTO file_hashes 
                (file_hash, document_id, filename, user_id, file_size)
                VALUES ($1, $2, $3, $4, $5)
                RETURNING filename, upload_time
            ''', file_hash, document_id, filename, user_id, file_size
            )
            
            if not result:
                # Should not happen with RETURNING, but safety check
                raise ValueError("Insert failed unexpectedly")
            
        except asyncpg.UniqueViolationError: # We should not reach here 
            # Get existing file info for better error message
            existing = await conn.fetchrow(
                'SELECT filename, upload_time FROM file_hashes WHERE file_hash = $1',
                file_hash
            )
            if existing:
                raise ValueError(
                    f"Duplicate file: {existing['filename']} "
                    f"(uploaded {existing['upload_time']})"
                )
            raise ValueError("Duplicate file detected")


    async def check_content_hash_exists(self, content_hash: str) -> Optional[Dict]:
        """Check content hash with prepared statement optimization"""

        try:
            async with pg_pool.get_connection() as conn:
                return await self._check_content_hash_operation(conn, content_hash)
            
        except Exception as e:
            logger.error(f"Failed to check content hash: {e}")
            # return None
            raise DatabaseError(f"Unexpected database content hash check error: {e}")

    
    async def _check_content_hash_operation(self, conn: asyncpg.Connection, content_hash: str):
        result = await conn.fetchrow('''
            SELECT filename, upload_time, document_id, status, user_id
            FROM file_hashes 
            WHERE content_hash = $1 
            LIMIT 1
        ''', content_hash
        )
        
        if result:
            file_info = {
                "filename": result['filename'],
                "upload_time": result['upload_time'].isoformat(),
                "document_id": result['document_id'],
                "status": result['status'],
                "user_id": result['user_id']
            }
            
            return file_info
        
        return None


    async def find_lsh_candidates(
        self, 
        fingerprint: LSHFingerprint,
        max_candidates: int
        ) -> List[Dict]:
        """
        Find candidate duplicates using LSH buckets - O(log n) per bucket!
        
        Returns: List of candidate documents that hash to same LSH buckets
        """

        try:
            async with pg_pool.get_connection() as conn:
                return await self._find_lsh_operation(
                    conn, fingerprint, max_candidates
                    )

        except Exception as e:
            logger.error(f"Failed to find LSH candidates: {e}")
            # return []
            raise DatabaseError(f"Unexpected database finding LSH error: {e}")


    async def _find_lsh_operation(
        self, 
        conn: asyncpg.Connection, 
        fingerprint: LSHFingerprint, 
        max_candidates: int
        ) -> List[Dict]:
        # Query: Find documents that share LSH buckets
        # This is the KEY optimization - indexed lookup!
        results = await conn.fetch('''
            WITH candidate_docs AS (
                SELECT 
                    lb.document_id,
                    COUNT(DISTINCT lb.bucket_id) as bucket_matches
                FROM lsh_buckets lb
                WHERE (lb.bucket_id, lb.band_index) IN (
                    SELECT unnest($1::TEXT[]), unnest($2::SMALLINT[]) -- uses composite index efficiently
                ) 
                GROUP BY lb.document_id
                HAVING COUNT(DISTINCT lb.bucket_id) >= $3 -- Must match at least n bands
                ORDER BY bucket_matches DESC
                LIMIT $4
            )
            SELECT 
                fh.document_id,
                fh.filename,
                fh.content_hash,
                fh.fingerprint_data,  -- ONLY retrieves JSONB and process in Python, don't query it!
                cd.bucket_matches
            FROM candidate_docs cd
            JOIN file_hashes fh ON cd.document_id = fh.document_id
            WHERE fh.content_hash IS NOT NULL -- filtering uses index (idx_file_hashes_content_partial)
        ''', 
        fingerprint.lsh_signatures,  # $1: bucket IDs
        list(range(len(fingerprint.lsh_signatures))),  # $2: band indices
        settings.processing.DOC_MIN_BUCKET_MATCHES, # $3: band count
        max_candidates  # $4: limit
        )
        
        candidates = [
            {
                'document_id': row['document_id'],
                'filename': row['filename'],
                'content_hash': row['content_hash'],
                'fingerprint_data': json.loads(row['fingerprint_data']), # JSONB
                'bucket_matches': row['bucket_matches']
            }
            for row in results
        ]
        
        logger.debug(
            f"Found {len(candidates)} LSH candidates from database "
            f"(min bucket matches: {settings.processing.DOC_MIN_BUCKET_MATCHES})"
        )

        return candidates


    async def store_content_hash(
        self, 
        content_hash: str, 
        document_id: str,
        fingerprint: LSHFingerprint
        ) -> None:
        """
        Store content hash with LSH signatures for fuzzy matching
        """

        try:
            async with pg_pool.get_connection() as conn:
                async with conn.transaction():
                    await pg_cb.execute(
                        lambda: self._store_content_hash_operation(
                            conn, content_hash, 
                            document_id, fingerprint
                            )
                        )
            logger.debug(f"Stored content hash with LSH for {document_id}")
        
        except DatabaseError:
            raise # Circuit breaker is open or DB failed critically
        except Exception as e:
            logger.error(f"Failed to store content hash with LSH: {e}")
            raise DatabaseError(f"Unexpected database storing content hash error: {e}")


    async def _store_content_hash_operation(
        self, 
        conn: asyncpg.Connection, 
        content_hash: str, 
        document_id: str, 
        fingerprint: LSHFingerprint
        ) -> None:
        
        # 1. Update main table with fingerprint
        fingerprint_data = json.dumps({
            'word_signature': fingerprint.word_signature,
            'structural_features': fingerprint.structural_features,
            'txt': fingerprint.txt
        })

        await conn.execute('''
            UPDATE file_hashes 
            SET content_hash = $1, 
                fingerprint_data = $2,
                updated_at = CURRENT_TIMESTAMP
            WHERE document_id = $3
        ''', content_hash, fingerprint_data, document_id
        )
        
        # 2. Insert LSH buckets for candidate retrieval
        if fingerprint.lsh_signatures and settings.processing.ENABLE_FUZZY_CACHE_MATCHING:
            await conn.execute('''
                INSERT INTO lsh_buckets (bucket_id, band_index, document_id)
                SELECT unnest($1::TEXT[]), unnest($2::SMALLINT[]), $3
                ON CONFLICT DO NOTHING
            ''', 
            fingerprint.lsh_signatures, 
            list(range(len(fingerprint.lsh_signatures))), 
            document_id)

        return None


    async def cleanup_failed_uploads(self, older_than_minutes: int = 30) -> int:
        """Optimized cleanup using database function"""

        try:
            async with pg_pool.get_connection() as conn:
                return await pg_cb.execute(lambda: self._cleanup_operation(conn, older_than_minutes))
        
        except DatabaseError:
            raise        
        except Exception as e:
            logger.error(f"Failed to cleanup failed uploads: {e}")
            # return 0
            raise DatabaseError(f"Unexpected database cleanup error: {e}")

    
    async def _cleanup_operation(self, conn: asyncpg.Connection, older_than_minutes: int = 30):
        deleted_count = await conn.fetchval(
            'SELECT cleanup_old_processing_files($1)',
            older_than_minutes
        )
        
        if deleted_count > 0:
            # Analyze table for query optimization
            await conn.execute('ANALYZE file_hashes')
            await conn.execute('ANALYZE lsh_buckets')
            logger.debug(f"PostgreSQL cleanup removed {deleted_count} failed uploads")
        
        return deleted_count


    async def list_all_files(self) -> List[Dict]:
        """Optimized file listing"""

        try:
            async with pg_pool.get_connection() as conn:
                return await self._list_file_operation(conn)
     
        except Exception as e:
            logger.error(f"Failed to list files: {e}")
            raise DatabaseError(f"Unexpected database listing file error: {e}")


    async def _list_file_operation(self, conn: asyncpg.Connection) -> List[Dict]:
        results = await conn.fetch('''
            SELECT document_id, filename, upload_time, status, file_size, user_id
            FROM file_hashes 
            ORDER BY upload_time DESC 
            LIMIT 1000
        ''')
        
        return [
            {
                "document_id": row['document_id'],
                "filename": row['filename'],
                "upload_time": row['upload_time'].isoformat(),
                "status": row['status'],
                "file_size": row.get('file_size', 0),
                "user_id": row['user_id']
            }
            for row in results
        ]


    async def mark_processing_complete(self, document_id: str) -> None:
        """Mark file processing as complete"""

        try:
            async with pg_pool.get_connection() as conn:
                await pg_cb.execute(
                    lambda: conn.execute('''
                        UPDATE file_hashes 
                        SET status = 'complete', 
                            updated_at = CURRENT_TIMESTAMP
                        WHERE document_id = $1
                    ''', document_id
                    )
                )
            
            logger.debug(f"Marked document {document_id} as complete")
        
        except DatabaseError:
            raise 
        except Exception as e:
            logger.error(f"Failed to mark processing complete: {e}")
            raise DatabaseError(f"Unexpected database mark processing error: {e}")


    async def remove_file_hash(self, file_hash: str) -> None:
        """Remove file hash with cache cleanup"""

        try:
            async with pg_pool.get_connection() as conn:
                await pg_cb.execute( 
                    lambda: conn.execute('''
                        DELETE FROM file_hashes 
                        WHERE file_hash = $1
                    ''', file_hash
                    )
                )
            
            logger.debug(f"Removed file hash: {file_hash[:16]}...")
        
        except DatabaseError:
            raise   
        except Exception as e:
            logger.error(f"Failed to remove file hash: {e}")
            raise DatabaseError(f"Unexpected database file removal error: {e}")

    
    async def get_file_by_document_id(self, document_id: str) -> Optional[Dict]:
        """Get file info by document ID with caching"""

        try:
            async with pg_pool.get_connection() as conn:
                result = await conn.fetchrow('''
                    SELECT file_hash, filename, upload_time, status, file_size, user_id 
                    FROM file_hashes WHERE document_id = $1 LIMIT 1
                ''', document_id
                )
                
                if result:
                    return {
                        "file_hash": result['file_hash'],
                        "filename": result['filename'],
                        "upload_time": result['upload_time'].isoformat(),
                        "status": result['status'],
                        "file_size": result['file_size'],
                        "user_id": result['user_id']
                    }
                return None
                
        except Exception as e:
            logger.error(f"Failed to get file by document ID: {e}")
            # return None
            raise DatabaseError(f"Unexpected database getting file error: {e}")


    async def get_hash_stats(self) -> Dict[str, Any]:
        """Get comprehensive statistics with PostgreSQL-specific metrics"""
        try:
            async with pg_pool.get_connection() as conn:
                stats = await self._stats_operation(conn)
                        
            return {
                **stats,
                "database_type": "PostgreSQL",
                "circuit_breaker": {
                    "failures": pg_cb.failures,
                    "is_open": pg_cb.is_open()
                }
            }
            
        except Exception as e:
            logger.error(f"Failed to get hash stats: {e}")
            return {"error": str(e)}
            # raise DatabaseError(f"Unexpected database stats error: {e}")

    
    async def _stats_operation(self, conn: asyncpg.Connection):
        # Basic file statistics
        basic_stats = await conn.fetchrow('''
            SELECT 
                COUNT(*) as total_files,
                COUNT(*) FILTER (WHERE status = 'processing') as processing_files,
                COUNT(*) FILTER (WHERE status = 'complete') as completed_files,
                COUNT(*) FILTER (WHERE content_hash IS NOT NULL) as files_with_content_hash,
                AVG(file_size) as avg_file_size,
                pg_size_pretty(pg_total_relation_size('file_hashes')) as table_size
            FROM file_hashes
        ''')
        
        # Connection pool stats
        pool_stats = await pg_pool.get_pool_stats()
        
        return {
            "total_files": basic_stats['total_files'],
            "processing_files": basic_stats['processing_files'],
            "completed_files": basic_stats['completed_files'],
            "files_with_content_hash": basic_stats['files_with_content_hash'],
            "avg_file_size_bytes": float(basic_stats['avg_file_size']) if basic_stats['avg_file_size'] else 0,
            "table_size": basic_stats['table_size'],
            "connection_pool": pool_stats
        }


    async def health_check(self) -> Dict[str, Any]:
        """Comprehensive health check with PostgreSQL metrics"""
        try:
            async with pg_pool.get_connection() as conn:
                db_stats = await self._health_operation(conn)
            
            pool_stats = await pg_pool.get_pool_stats()

            return {
                "status": "healthy",
                "database_type": "PostgreSQL Hash Store",
                "total_files": db_stats["total_files"],
                "connection_pool_health": pool_stats,
                "circuit_breaker_status": "closed" if not pg_cb.is_open() else "open"
            }
            
        except Exception as e:
            logger.error(f"PostgreSQL hash store health check failed: {e}")
            return {"status": "unhealthy", "error": str(e)}

    
    async def _health_operation(self, conn: asyncpg.Connection):
        # Test basic connectivity
        await conn.fetchval('SELECT 1')
        
        # Check table existence and basic stats
        total_files = await conn.fetchval('SELECT COUNT(*) FROM file_hashes')
        
        return {"total_files": total_files}


    async def close(self):
        """Clean up resources"""
        async with self._lock:
            if self._initialized:
                try:
                    # Close connection pool gracefully
                    await pg_pool.unregister_component(self.COMPONENT_NAME)
                    self._initialized = False
                    # logger.debug("Hash store closed successfully")

                except Exception as e:
                    logger.error(f"Error closing Hash store: {e}")
                    raise DatabaseError(f"Unexpected database closing error: {e}")