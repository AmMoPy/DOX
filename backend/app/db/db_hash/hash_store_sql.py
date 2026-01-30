import json
import sqlite3
import logging
from uuid import UUID
from typing import Optional, Dict, List, Any
from datetime import datetime, timedelta, UTC
from app.config.setting import settings
from app.utils.lsh import LSHFingerprint
from app.db.utils_db.async_bridge import async_bridge
from app.db.utils_db.sql_pool_mngr import SQLiteHashPool
from app.db.utils_db.circuit_breaker import sql_cb, DatabaseError

logger = logging.getLogger(__name__)


class SQLiteHashStore:
    """Optimized SQLite store for file's binary and content hash"""
    
    def __init__(self):
        self.pool = SQLiteHashPool()
        self._initialized = False


    async def initialize(self):
        """Initialize hash manager with monitoring"""
        if self._initialized:
            logger.debug("SQL Hash Store already initialized")
            return

        try:
            await async_bridge.run_in_db_thread(
                lambda: self.pool.initialize(
                    settings.paths.SQL_DB_PATH / "file_hashes.db",
                    settings.database.HASH_CACHE_POOL_SIZE
                    )
                )

            # Setup own schema
            async with self.pool.get_connection() as conn:
                await sql_cb.execute(
                    async_bridge.run_in_db_thread(
                        lambda: self._setup_schema(conn)
                    )   
                )

            self._initialized = True
            logger.debug("SQLite hash store initialized")
        except Exception as e:
            logger.error(f"Failed to initialize hash store: {e}")
            raise DatabaseError(f"Unexpected database initialization error: {e}")


    def _setup_schema(self, conn: sqlite3.Connection):
        """Setup database with optimized schema"""

        # Create optimized table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS file_hashes (
                file_hash TEXT PRIMARY KEY,
                content_hash TEXT,
                document_id TEXT NOT NULL,
                filename TEXT NOT NULL,
                upload_time INTEGER DEFAULT (unixepoch('now')),
                status TEXT DEFAULT 'processing',
                file_size INTEGER DEFAULT 0,
                user_id TEXT,
                fingerprint_json TEXT,  -- JSON string in SQLite
                created_at INTEGER DEFAULT (unixepoch('now')),
                updated_at INTEGER DEFAULT (unixepoch('now'))
            ) WITHOUT ROWID
        ''')

        # LSH buckets
        conn.execute('''
            CREATE TABLE IF NOT EXISTS lsh_buckets (
                bucket_id TEXT NOT NULL,
                band_index INTEGER NOT NULL,
                document_id TEXT NOT NULL,
                created_at INTEGER DEFAULT (unixepoch('now')),
                PRIMARY KEY (bucket_id, band_index, document_id),
                FOREIGN KEY (document_id) REFERENCES file_hashes(document_id) ON DELETE CASCADE
            ) WITHOUT ROWID
        ''')
        
        # Create optimized indexes with better selectivity
        indexes = [
            'CREATE INDEX IF NOT EXISTS idx_cache_fingerprint ON file_hashes(fingerprint_json) WHERE fingerprint_json IS NOT NULL',
            'CREATE INDEX IF NOT EXISTS idx_lsh_lookup ON lsh_buckets(bucket_id, band_index)',
            'CREATE INDEX IF NOT EXISTS idx_lsh_document ON lsh_buckets(document_id)',
            'CREATE INDEX IF NOT EXISTS idx_content_hash ON file_hashes(content_hash) WHERE content_hash IS NOT NULL',
            'CREATE INDEX IF NOT EXISTS idx_document_id ON file_hashes(document_id)',
            'CREATE INDEX IF NOT EXISTS idx_status_time ON file_hashes(status, upload_time) WHERE status = "processing"',
            'CREATE INDEX IF NOT EXISTS idx_user_recent ON file_hashes(user_id, upload_time DESC)',
            'CREATE UNIQUE INDEX IF NOT EXISTS idx_doc_hash_unique ON file_hashes(document_id, file_hash)'
        ]
        
        for index in indexes:
            try:
                conn.execute(index)
            except Exception as e:
                logger.debug(f"Index creation note: {e}")
        
        # Update table statistics
        conn.execute('ANALYZE file_hashes')
        conn.execute('ANALYZE lsh_buckets')

            
    async def check_file_hash_exists(self, file_hash: str) -> Optional[Dict]:
        """Check file hash existence with optimized caching"""
        try:
            async with self.pool.get_connection() as conn:
                result = await async_bridge.run_in_db_thread(
                    lambda: conn.execute('''
                        SELECT filename, upload_time, document_id, status, user_id
                        FROM file_hashes 
                        WHERE file_hash = ?
                        LIMIT 1
                    ''', (file_hash,)).fetchone()
                    )
                
                
                if result:
                    file_info = {
                        "filename": result['filename'],
                        "upload_time": datetime.fromtimestamp(result['upload_time'], UTC).isoformat(),
                        "document_id": result['document_id'],
                        "status": result['status'],
                        "user_id": UUID(result['user_id'])
                    }

                    return file_info
                
                return None
                
        except Exception as e:
            logger.error(f"Failed to check file hash: {e}")
            # return None
            raise DatabaseError(f"Unexpected database checking file hash error: {e}")


    async def store_file_hash(
        self, 
        file_hash: str,
        document_id: str,
        filename: str,
        user_id: UUID,
        file_size: int = 0
        ) -> None:
        """Store file hash"""

        # If we reach here, check_file_hash_exists should have returned None
        # So we can assume no duplicate and just insert
        try:
            async with self.pool.get_connection() as conn:
                await sql_cb.execute(
                    async_bridge.run_in_db_thread(
                        lambda: self._store_file_hash_op(
                            conn, file_hash, document_id, filename, file_size, user_id
                        )
                    )
                )
            logger.debug(f"Stored hash for {filename}")
        
        except DatabaseError:
            raise  
        except ValueError:
            raise # Domain error, re-raise as-is
        except Exception as e:
            logger.error(f"Failed to store file hash: {e}")
            raise DatabaseError(f"Unexpected database storing file hash error: {e}")


    def _store_file_hash_op(
        self, 
        conn: sqlite3.Connection,
        file_hash: str, 
        document_id: str, 
        filename: str,
        file_size: int, 
        user_id: UUID
    ) -> None:
        """Sync operation for thread pool"""
        try:
            conn.execute('''
                INSERT INTO file_hashes 
                (file_hash, document_id, filename, file_size, user_id)
                VALUES (?, ?, ?, ?, ?)
            ''', (file_hash, document_id, filename, file_size, user_id))
            
        except sqlite3.IntegrityError:
            # Duplicate file - get existing info
            existing = conn.execute(
                'SELECT filename, upload_time FROM file_hashes WHERE file_hash = ?',
                (file_hash,)
            ).fetchone()
            if existing:
                raise ValueError(
                    f"Duplicate file: {existing['filename']} "
                    f"(uploaded at {existing['upload_time']})"
                )
            raise ValueError("Duplicate file detected")


    async def check_content_hash_exists(self, content_hash: str) -> Optional[Dict]:
        """Check content hash existence with caching"""

        try:
            async with self.pool.get_connection() as conn:
                result = await async_bridge.run_in_db_thread(
                    lambda: conn.execute('''
                        SELECT filename, upload_time, document_id, status, user_id
                        FROM file_hashes 
                        WHERE content_hash = ? 
                        LIMIT 1
                    ''', (content_hash,)).fetchone()
                    )
                
                
                if result:
                    file_info = {
                        "filename": result['filename'],
                        "upload_time": datetime.fromtimestamp(result['upload_time'], UTC).isoformat(),
                        "document_id": result['document_id'],
                        "status": result['status'],
                        "user_id": UUID(result['user_id'])
                    }
                    
                    return file_info
                      
                return None
                
        except Exception as e:
            logger.error(f"Failed to check content hash: {e}")
            raise DatabaseError(f"Unexpected database content hash check error: {e}")


    async def find_lsh_candidates(
        self,
        fingerprint: LSHFingerprint,
        max_candidates: int
        ) -> List[Dict]:
        """Find candidates using LSH"""

        if not fingerprint:
            logger.warning("No fingerprint provided")
            return []

        try:
            async with self.pool.get_connection() as conn:
                # Build query with parameter placeholders
                placeholders = ','.join(['?'] * len(fingerprint.lsh_signatures))

                query = f'''
                    WITH candidate_docs AS (
                        SELECT 
                            document_id,
                            COUNT(DISTINCT bucket_id) as bucket_matches,
                            GROUP_CONCAT(DISTINCT band_index) as matched_bands
                        FROM lsh_buckets
                        WHERE bucket_id IN ({placeholders})
                        GROUP BY document_id
                        HAVING COUNT(DISTINCT bucket_id) >= ?
                        ORDER BY bucket_matches DESC
                        LIMIT ?
                    )
                    SELECT 
                        fh.document_id,
                        fh.filename,
                        fh.content_hash,
                        fh.fingerprint_json,
                        cd.bucket_matches,
                        cd.matched_bands
                    FROM candidate_docs cd
                    JOIN file_hashes fh ON cd.document_id = fh.document_id
                    WHERE fh.content_hash IS NOT NULL
                      AND fh.fingerprint_json IS NOT NULL
                '''
                
                # Parameters: all bucket IDs, then min_matches, max_candidates
                params = list(fingerprint.lsh_signatures) + [
                    settings.processing.DOC_MIN_BUCKET_MATCHES,
                    max_candidates
                ]          

                results = await async_bridge.run_in_db_thread(
                    lambda: conn.execute(query, params).fetchall()
                )

                candidates = [
                    {
                        'document_id': row['document_id'],
                        'filename': row['filename'],
                        'content_hash': row['content_hash'],
                        'fingerprint_data': json.loads(row['fingerprint_json']),  # Parse JSON
                        'bucket_matches': row['bucket_matches']
                    }
                    for row in results
                ]
                
                logger.debug(
                    f"Found {len(candidates)} LSH candidates from database "
                    f"(min bucket matches: {settings.processing.DOC_MIN_BUCKET_MATCHES})"
                )

                return candidates
                
        except Exception as e:
            logger.error(f"Failed to find LSH candidates: {e}")
            # return []
            raise DatabaseError(f"Unexpected database finding LSH error: {e}")


    async def store_content_hash(
        self,
        content_hash: str,
        document_id: str,
        fingerprint: LSHFingerprint
    ) -> None:
        """
        Store content hash with LSH signatures for fuzzy matching
        with optimized batch insert for LSH buckets
        """

        try:
            async with self.pool.get_connection() as conn:
                # SQLite doesn't have native transaction context managers,
                # but we can use BEGIN/COMMIT for atomicity
                await sql_cb.execute(
                    async_bridge.run_in_db_thread(
                        lambda: self._store_content_hash_operation(
                            conn, content_hash, document_id, fingerprint
                        )
                    )
                )
            
            logger.debug(f"Stored content hash with LSH for {document_id}")
        
        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to store content hash with LSH: {e}")
            raise DatabaseError(f"Unexpected database storing content hash error: {e}")


    def _store_content_hash_operation(
        self,
        conn: sqlite3.Connection,
        content_hash: str,
        document_id: str,
        fingerprint: LSHFingerprint
        ) -> None:
        """
        Synchronous operation for thread pool execution
        SQLite requires explicit transaction management for atomicity
        """
        try:
            # Begin explicit transaction for atomicity
            conn.execute('BEGIN IMMEDIATE')
            
            # 1. Update main table with fingerprint
            fingerprint_json = json.dumps({
                'word_signature': fingerprint.word_signature,
                'structural_features': fingerprint.structural_features,
                'txt': fingerprint.txt
            })
            
            conn.execute('''
                UPDATE file_hashes 
                SET content_hash = ?,
                    fingerprint_json = ?,
                    updated_at = unixepoch('now')
                WHERE document_id = ?
            ''', (content_hash, fingerprint_json, document_id))
            
            # Verify update succeeded
            if conn.total_changes == 0: # to ensure the UPDATE actually modified a row
                raise DatabaseError(f"Failed to update document {document_id} - not found")
            
            # 2. Batch insert LSH buckets for efficient indexing
            if fingerprint.lsh_signatures and settings.processing.ENABLE_FUZZY_CACHE_MATCHING:
                    
                # SQLite supports executemany for batch operations
                # More efficient than individual inserts for the 16 LSH buckets (default num_bands)
                lsh_records = [
                    (bucket_id, band_idx, document_id)
                    for band_idx, bucket_id in enumerate(fingerprint.lsh_signatures)
                ]
                
                # INSERT OR IGNORE: SQLite's conflict resolution for duplicate bucket entries 
                # (equivalent to PostgreSQL's ON CONFLICT DO NOTHING)
                conn.executemany('''
                    INSERT OR IGNORE INTO lsh_buckets 
                    (bucket_id, band_index, document_id)
                    VALUES (?, ?, ?)
                ''', lsh_records)
            
            # Commit transaction
            conn.execute('COMMIT')
            
        except Exception as e:
            # Rollback on any error
            try:
                conn.execute('ROLLBACK')
            except Exception as rollback_error:
                logger.error(f"Rollback failed: {rollback_error}")
            
            logger.error(f"LSH storage operation failed: {e}")
            raise DatabaseError(f"Unexpected database storing content hash error: {e}")


    async def cleanup_failed_uploads(self, older_than_minutes: int = 30) -> int:
        """Optimized cleanup with batch processing"""

        try:
            async with self.pool.get_connection() as conn:
                deleted_count = await sql_cb.execute(
                    async_bridge.run_in_db_thread(
                        lambda: self._cleanup_failed_uploads_op(conn, older_than_minutes)
                    )
                )
                
                if deleted_count > 0:
                    logger.debug(f"Cleaned up {deleted_count} failed uploads")

                return deleted_count
        
        except DatabaseError:
            raise     
        except Exception as e:
            logger.error(f"Failed to cleanup failed uploads: {e}")
            # return 0
            raise DatabaseError(f"Unexpected database cleanup error: {e}")


    def _cleanup_failed_uploads_op(self, conn: sqlite3.Connection, older_than_minutes: int = 30) -> int:
        """Sync cleanup operation"""

        cutoff_time = int((datetime.now(UTC) - timedelta(minutes=older_than_minutes)).timestamp())
        
        cursor = conn.execute('''
            DELETE FROM file_hashes 
            WHERE status = 'processing' 
            AND upload_time < ?
        ''', (cutoff_time,))
        
        deleted_count = cursor.rowcount
        
        if deleted_count > 0:
            conn.execute('PRAGMA optimize')
        
        return deleted_count


    async def list_all_files(self) -> List[Dict]:
        """Optimized file listing"""

        try:
            async with self.pool.get_connection() as conn:
                results = await async_bridge.run_in_db_thread(
                    lambda: conn.execute(''' 
                        SELECT document_id, filename, upload_time, status, file_size, user_id 
                        FROM file_hashes 
                        ORDER BY upload_time DESC 
                        LIMIT 1000
                        ''').fetchall()
                    )
                
                return [
                    {
                        "document_id": row['document_id'],
                        "filename": row['filename'],
                        "upload_time": datetime.fromtimestamp(row['upload_time'], UTC).isoformat(),
                        "status": row['status'],
                        "file_size": row['file_size'] if 'file_size' in row.keys() else 0,
                        "user_id": UUID(row['user_id'])
                    }
                    for row in results
                ]
                
        except Exception as e:
            logger.error(f"Failed to list files: {e}")
            raise DatabaseError(f"Unexpected database listing file error: {e}")

    
    async def mark_processing_complete(self, document_id: str) -> None:
        """Mark file processing as complete"""

        try:
            async with self.pool.get_connection() as conn:
                await sql_cb.execute(
                    async_bridge.run_in_db_thread(
                        lambda: conn.execute('''
                            UPDATE file_hashes 
                            SET status = 'complete',
                                updated_at = unixepoch('now')
                            WHERE document_id = ?
                            ''', (document_id,))
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
            # Deleting by file_hash from database automatically removes the 
            # associated hashes and all other columns in that row.
            async with self.pool.get_connection() as conn:
                await sql_cb.execute(
                    async_bridge.run_in_db_thread(
                        lambda: conn.execute('''
                            DELETE FROM file_hashes WHERE file_hash = ?
                            ''', (file_hash,))
                        )
                    )
            
            logger.debug(f"Removed file hash: {file_hash[:16]}...")

        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to remove file hash: {e}")
            raise DatabaseError(f"Unexpected database file removal error: {e}")


    async def get_file_by_document_id(self, document_id: str) -> Optional[Dict]:
        """Get file info by document ID"""

        try:
            async with self.pool.get_connection() as conn:
                result = await async_bridge.run_in_db_thread(
                    lambda: conn.execute('''
                        SELECT file_hash, filename, upload_time, status, file_size, user_id 
                        FROM file_hashes WHERE document_id = ? LIMIT 1
                        ''', (document_id,)).fetchone()
                    )
                
                
                if result:
                    return {
                        "file_hash": result['file_hash'],
                        "filename": result['filename'],
                        "upload_time": datetime.fromtimestamp(result['upload_time'], UTC).isoformat(),
                        "status": result['status'],
                        "file_size": result['file_size'],
                        "user_id": UUID(result['user_id'])
                    }
                return None
                
        except Exception as e:
            logger.error(f"Failed to get file by document ID: {e}")
            # return None
            raise DatabaseError(f"Unexpected database getting file error: {e}")


    async def get_hash_stats(self) -> Dict[str, Any]:
        """Get comprehensive hash manager statistics"""
        try:
            async with self.pool.get_connection() as conn:
                stats = await async_bridge.run_in_db_thread(
                    lambda: {
                    "total_files": conn.execute("SELECT COUNT(*) FROM file_hashes").fetchone()[0],
                    "processing_files": conn.execute("SELECT COUNT(*) FROM file_hashes WHERE status = 'processing'").fetchone()[0],
                    "completed_files": conn.execute("SELECT COUNT(*) FROM file_hashes WHERE status = 'complete'").fetchone()[0],
                    "files_with_content_hash": conn.execute("SELECT COUNT(*) FROM file_hashes WHERE content_hash IS NOT NULL").fetchone()[0],
                    "db_size_mb": conn.execute("PRAGMA page_count").fetchone()[0] * conn.execute("PRAGMA page_size").fetchone()[0] / (1024 * 1024)
                    }
                )
            
            return {
                **stats,
                "database_type": "SQLite",
                "circuit_breaker": {
                    "failures": sql_cb.failures,
                    "is_open": sql_cb.is_open()
                }
            }
            
        except Exception as e:
            logger.error(f"Failed to get hash stats: {e}")
            # return {"error": str(e)}
            raise DatabaseError(f"Unexpected database stats error: {e}")


    async def health_check(self) -> Dict[str, Any]:
        """Comprehensive health check"""
        try:
            # Test database connectivity
            async with self.pool.get_connection() as conn:
                await async_bridge.run_in_db_thread(
                    lambda: conn.execute("SELECT 1").fetchone()
                )
            
            # Get basic stats
            stats = await self.get_hash_stats()
            
            return {
                "status": "healthy",
                "database_type": "SQLite",
                "total_files": stats["total_files"],
                "circuit_breaker_status": "closed" if not sql_cb.is_open() else "open"
            }
            
        except Exception as e:
            logger.error(f"Hash store health check failed: {e}")
            return {"status": "unhealthy", "error": str(e)}

    
    async def close(self):
        """Clean up resources"""
        try:
            if self.pool:
                await self.pool.close()
            self._initialized = False
            # logger.debug("SQLite hash manager closed")
        except Exception as e:
            logger.error(f"Error closing Hash store: {e}")
            raise DatabaseError(f"Unexpected database closing error: {e}")