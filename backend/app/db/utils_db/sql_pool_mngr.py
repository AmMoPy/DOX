import queue
import sqlite3
import logging
from uuid import UUID
from pathlib import Path
from threading import Lock
from contextlib import asynccontextmanager
from app.db.utils_db.async_bridge import async_bridge
from app.db.utils_db.circuit_breaker import DatabaseError

logger = logging.getLogger(__name__)

# Register adapter globally for auto UUID -> STR conversion at insertion time
sqlite3.register_adapter(UUID, lambda u: str(u))

# # Register a converter for reading back into UUID objects, 
# # less necessary, using row_factory for conversion when needed
# # ENSURE defining detect_types in sqlite3.connect() if enabled
# sqlite3.register_converter("UUID", lambda b: UUID(b.decode('utf-8')))


class SQLiteHashPool:
    """
    Simple SQLite connection pool that handles:

    - Pool exhaustion → Create new connections
    - Pool full → Close excess connections
    - Exceptions → Proper cleanup
    - Thread safety → Queue handles concurrency
    """
    
    def __init__(self):
        self._lock = Lock()
        self._initialized = False


    def initialize(
        self,
        db_path: Path,
        pool_size: int = 5
        ):
        """Initialize connection pool with optimized settings"""
        with self._lock:
            if self._initialized:
                return
            
            try:    
                # ensure directory exists
                self.db_path = db_path
                self.db_path.parent.mkdir(parents=True, exist_ok=True)
 
                # Pre-populate pool
                self._pool = queue.Queue(maxsize=pool_size)
                
                for _ in range(pool_size):
                    conn = self._create_connection()
                    self._pool.put(conn)
                
                self._initialized = True
                logger.debug(f"SQLite pool initialized with {pool_size} connections")
            
            except DatabaseError:
                raise         
            except Exception as e:
                logger.error(f"Failed to initialize SQLite pool: {e}")
                raise DatabaseError(f"Unexpected database error: {e}")
    

    def _create_connection(self):
        """Create optimized SQLite connection"""
        conn = sqlite3.connect(
            str(self.db_path),
            check_same_thread=False,
            timeout=30.0,
            isolation_level=None,  # Autocommit for better concurrency, no transactions - each execute is permanent
            # # detect_types is needed for automatic conversion of database output, it control how
            # # the driver decides which Python converter function (from register_converter) to apply 
            # # when reading data out of the database. The below are REQUIRED for conversion if register_converter is defined:
            # # PARSE_DECLTYPES: Looks at the CREATE TABLE column type name (e.g., id UUID PRIMARY KEY, name TEXT) note that 
            # # UUID must match function name in register_converter, name TEXT explicitly sets the column's type affinity to TEXT
            # # PARSE_COLNAMES: Looks for [type] hints within the result column name (e.g., SELECT name AS "user_name [UUID]" FROM users)
            # detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES
        )

        # CRITICAL: sqlite3.Row factory changes the behavior of database results. 
        # Instead of returning raw tuples ('value_A', 'value_B'), it returns 
        # dictionary-like rows that allow access by column name row['column_name']
        conn.row_factory = sqlite3.Row
        
        # Production optimizations
        optimizations = [
            'PRAGMA journal_mode=WAL',
            'PRAGMA synchronous=NORMAL',
            'PRAGMA cache_size=-32000',     # 32MB cache (negative = KB)
            'PRAGMA temp_store=MEMORY',
            'PRAGMA mmap_size=268435456',   # 256MB memory map
            'PRAGMA busy_timeout=30000',    # 30 second busy timeout
            'PRAGMA optimize',
            'PRAGMA threads=4',             # Multi-threaded operations
            'PRAGMA read_uncommitted=1'     # Faster reads (acceptable for cache)
        ]
        
        for pragma in optimizations:
            conn.execute(pragma)
        
        return conn
    

    @asynccontextmanager
    async def get_connection(self):
        """Get connection from pool"""

        if not self._initialized:
            raise DatabaseError("SQL pool not initialized")

        conn = None

        try:
            # Try to get from pool
            try:
                conn = await async_bridge.run_in_db_thread(
                    lambda: self._pool.get(timeout=5.0)
                )
            except queue.Empty:
                # Pool exhausted, create new connection
                conn = await async_bridge.run_in_db_thread(
                    self._create_connection
                )
            
            yield conn
            
        except Exception as e:
            logger.error(f"Pool connection failed: {e}")
            raise DatabaseError(f"Unexpected database error: {e}")

        finally:
            if conn:
                try:
                    # Return connection to pool only if it's still valid
                    await async_bridge.run_in_db_thread(
                        lambda: self._pool.put(conn, timeout=1.0)
                    )
                except queue.Full:
                    # Pool full, close connection
                    await async_bridge.run_in_db_thread(conn.close)
                    # Don't need to do anything else - connection is closed and discarded
    

    async def close(self):
        """Close all connections in pool"""
        await async_bridge.run_in_db_thread(self._close_all)
        self._initialized = False


    def _close_all(self):
        """ """
        while not self._pool.empty():
            try:
                conn = self._pool.get_nowait()
                conn.close()
            except queue.Empty:
                break    