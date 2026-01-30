import asyncpg
import asyncio
import time
import json
import logging
import heapq
from datetime import datetime, timedelta, UTC
from typing import List, Optional, Dict, Any, Tuple
from app.config.setting import settings
from app.db.utils_db.pg_pool_mngr import pg_pool
from app.db.utils_db.async_bridge import async_bridge
from app.db.utils_db.circuit_breaker import pg_cb, DatabaseError
from app.db.utils_db.services_search import search_service

logger = logging.getLogger(__name__)


class PostgreSQLDocStore:
    """PostgreSQL Document store with pgvector extension and shared pool"""
    
    def __init__(self):
        """initializing the attributes of the already created instance"""
        self._lock = asyncio.Lock()
        self._initialized = False
        self.COMPONENT_NAME = "doc_store"
        self.SCHEMA_VERSION = "1.0"
        self.partition_strategy = settings.database.DOC_PARTITION_STRATEGY
        self._partitions = set() # cache main and frequently used partitions
        self._init_search_config()


    def _init_search_config(self):
        """Initialize search configurations"""
        config_params = {} # populate as needed
        
        # Update search service config
        search_service.update_config(**config_params)
    

    async def initialize(self):
        """Initialize PostgreSQL vector store with connection pooling"""
        async with self._lock:
            if self._initialized:
                return
            
            try:
                logger.debug("Initializing PostgreSQL Document Store with pgvector...")
                
                # Register with shared pool (pgvector extension already enabled by pool)
                await pg_pool.initialize(self.COMPONENT_NAME, self.SCHEMA_VERSION)
                
                # Setup own schema
                async with pg_pool.get_connection() as conn:
                    await pg_cb.execute(
                        lambda: self._setup_schema(conn)
                        )
                    
                # Initialize partition management
                await self._initialize_partitions()
                
                self._initialized = True
                logger.debug("PostgreSQL Document Store initialized successfully!")
                
            except Exception as e:
                logger.error(f"Failed to initialize PostgreSQL Document Store: {e}")
                raise DatabaseError(f"Unexpected database initialization error: {e}")
    

    async def _setup_schema(self, conn: asyncpg.Connection):
        """Setup PostgreSQL database with optimized schema and indexes"""

        # Create main table with correct data types and constraints
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS vector_chunks (
                document_id TEXT NOT NULL,
                chunk_id TEXT NOT NULL,
                content TEXT NOT NULL,
                embedding vector(384),  -- Adjust dimension based on model used
                metadata JSONB DEFAULT '{}',
                partition_key TEXT NOT NULL,
                chunk_position INTEGER DEFAULT 0,
                chunk_length INTEGER NOT NULL,
                created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (chunk_id, partition_key) -- composite Primary Key, main identifier for a row, unique per chunk
            ) PARTITION BY LIST (partition_key)
        ''')
        
        # since CONCURRENTLY can not be used with partitioned tables there are two options: 
        # A) remove it! But this will lock the table (blocks writes)
        # B) make placeholders on the parent table and build indexes CONCURRENTLY on each child partition
        parent_indexes = [
            'CREATE INDEX IF NOT EXISTS idx_chunks_document ON ONLY vector_chunks(document_id, partition_key)',
            'CREATE INDEX IF NOT EXISTS idx_chunks_partition ON ONLY vector_chunks(partition_key)',
            'CREATE INDEX IF NOT EXISTS idx_chunks_created ON ONLY vector_chunks(created_at DESC)',
            'CREATE INDEX IF NOT EXISTS idx_chunks_metadata_gin ON ONLY vector_chunks USING GIN(metadata)',
            # No need for HNSW index at parent even for uncategorized search on a partitioned table
            # PostgreSQL's query planner operates like this:
            # 1. It identifies which partitions need to be scanned (in this case, all of them).
            # 2. It uses a UNION ALL implicitly across all relevant partitions.
            # 3. Crucially: The planner scans the individual HNSW indexes that exist on each child partition.
            # 4. It then gathers the top candidates from all partitions and sorts them globally to find the final top K results.
            # 5. The parent table itself is just a logical container. The HNSW index data resides entirely within the physical index files of the child tables.
        ]
        
        for index in parent_indexes:
            try:
                await conn.execute(index)
                logger.debug(f"Parent index creation success")
            except Exception as e:
                logger.debug(f"Parent index creation note: {e}")
        
        # create optimized partition management functions
        # note that primary key on a partitioned table must 
        # globally uniquely identify a row, which means it must
        # include the column(s) used to determine which partition the row lives in.
        await conn.execute('''
            CREATE OR REPLACE FUNCTION create_partition(partition_name TEXT, partition_key_value TEXT)
            RETURNS void AS $$
            BEGIN
                -- Create partition if not exists
                EXECUTE format(
                    'CREATE TABLE IF NOT EXISTS %I PARTITION OF vector_chunks FOR VALUES IN (%L)', 
                    partition_name, partition_key_value
                );
            END;
            $$ LANGUAGE plpgsql;
        ''')
        
        # Create performance monitoring views
        # The columns are standard columns provided by 
        # PostgreSQL in the pg_stat_user_tables system view
        await conn.execute('''
            CREATE OR REPLACE VIEW partition_stats AS
            SELECT 
                schemaname,
                relname as partition_name,
                n_tup_ins as inserts, -- number of rows inserted
                n_tup_upd as updates,
                n_tup_del as deletes,
                n_live_tup as live_tuples,
                n_dead_tup as dead_tuples,
                last_vacuum,
                last_autovacuum,
                last_analyze,
                last_autoanalyze
            FROM pg_stat_user_tables 
            WHERE relname LIKE 'vector_chunks_%'
            ORDER BY live_tuples DESC;
        ''')

        logger.debug("Document store schema setup completed")


    async def _create_partition_indexes(self, partition_name: str, partition_key: str):  
        """Create indexes CONCURRENTLY on a partition"""
        async with pg_pool.get_connection() as conn:
            try:
                # All these run in autocommit mode - perfect for CONCURRENTLY
                
                # HNSW index - this is a non standard index that MUST be created 
                # in each partition, doesn't propagate properly from parent resulting
                # in non-indexed poor search results
                await conn.execute(f'''
                    CREATE INDEX CONCURRENTLY IF NOT EXISTS {partition_name}_embedding_hnsw 
                    ON {partition_name} USING hnsw (embedding vector_cosine_ops) 
                    WITH (m = {settings.database.DOC_HNSW_M}, 
                          ef_construction = {settings.database.DOC_HNSW_CONSTRUCTION_EF})
                ''')

                # Regular indexes
                indexes_to_create = [
                    ('document', f'{partition_name}_document', '(document_id, partition_key)', 'idx_chunks_document'),
                    ('partition', f'{partition_name}_partition', '(partition_key)', 'idx_chunks_partition'),
                    ('created', f'{partition_name}_created', '(created_at DESC)', 'idx_chunks_created'),
                    ('metadata_gin', f'{partition_name}_metadata_gin', 'USING GIN(metadata)', 'idx_chunks_metadata_gin'),
                ]
                
                for index_type, index_name, index_def, parent_index in indexes_to_create:
                    try:
                        # Create index concurrently
                        if 'USING GIN' in index_def:
                            sql = f'CREATE INDEX CONCURRENTLY IF NOT EXISTS {index_name} ON {partition_name} {index_def}'
                        else:
                            sql = f'CREATE INDEX CONCURRENTLY IF NOT EXISTS {index_name} ON {partition_name}{index_def}'
                        
                        await conn.execute(sql)
                        logger.debug(f"Created {index_name}")

                        # # latest PG version(18) no need explicit 
                        # # ATTACH the code is there for backward comp
                        # # Wait for index to become valid
                        # await self._wait_for_index_valid(conn, partition_name, index_name)
                        
                        # # Attach to parent
                        # await conn.execute(f'''
                        #     ALTER INDEX {parent_index} ATTACH PARTITION {index_name}
                        # ''')
                        # logger.info(f"Attached {index_name} to {parent_index}")
                    except Exception as e:
                        logger.error(f"Failed to create/attach {index_name}: {e}")
                        continue

            except Exception as e:
                logger.error(f"Failed to create indexes for {partition_name}: {e}")
                # # Partition still usable without indexes, just slower with stinky 
                # # search results (no HNSW). So it is better to raise than failing silently
                # raise


    # async def _wait_for_index_valid(self, conn, table_name: str, index_name: str, timeout: int = 30):
    #     """Wait for concurrent index to become valid"""
    #     start_time = time.time()
        
    #     while time.time() - start_time < timeout:
    #         is_valid = await conn.fetchval('''
    #             SELECT i.indisvalid
    #             FROM pg_index i
    #             JOIN pg_class c ON c.oid = i.indexrelid
    #             WHERE c.relname = $1
    #         ''', index_name)
            
    #         if is_valid:
    #             logger.debug(f"Index {index_name} is valid")
    #             return True
            
    #         logger.debug(f"Waiting for {index_name} to become valid...")
    #         await asyncio.sleep(0.5)
        
    #     raise TimeoutError(f"Index {index_name} did not become valid within {timeout}s")


    async def _initialize_partitions(self):
        """Initialize partitions based on strategy"""
        async with pg_pool.get_connection() as conn:
            if self.partition_strategy == "category":
                categories = settings.database.DOC_DEFAULT_CATEGORIES
            elif self.partition_strategy == "time":
                categories = []
                current_time = datetime.now(UTC)
                for i in range(-1, 12):
                    month_time = current_time - timedelta(days=30 * i) # mind the time drift
                    categories.append(month_time.strftime("%Y_%m"))
            elif self.partition_strategy == "shard":
                shard_count = settings.database.SHARD_COUNT
                categories = [f"shard_{i}" for i in range(shard_count)]
            else:
                categories = ["default"]
            
            for category in categories:
                await self._ensure_partition(category)


    async def _ensure_partition(self, partition_key: str):
        """Ensure partition exists with cached check"""
        partition_name = f'vector_chunks_{partition_key}'
        
        if partition_name in self._partitions:
            return  # already verified from cache
        
        async with pg_pool.get_connection() as conn:
            # Check if partition exists
            exists = await conn.fetchval('''
                SELECT EXISTS (
                    SELECT 1 FROM pg_tables 
                    WHERE tablename = $1
                )
            ''', partition_name)
            
            if exists:
                self._partitions.add(partition_name)
                return
            
            # Create partition and indexes
            # race condition possible here, so what!
            # PostgreSQL's CREATE TABLE IF NOT EXISTS is idempotent 
            # so duplicate attempts are harmless
            # the worst case is wasted database calls
            try:
                await conn.execute(
                    'SELECT create_partition($1, $2)',
                    partition_name, partition_key
                )
                self._partitions.add(partition_name)
                
                # Create indexes in background (don't block writes)
                asyncio.create_task(self._create_partition_indexes(partition_name, partition_key))
                
            except Exception as e:
                if "already exists" in str(e).lower():
                    self._partitions.add(partition_name)
                else:
                    raise


    def _get_partition_key(self, metadata: Dict[str, Any]) -> str:
        """Determine partition key with runtime configurability"""
        strategy = getattr(self, '_current_strategy', self.partition_strategy)
        
        if strategy == "category":
            return metadata.get("category", "uncategorized").lower()
        elif strategy == "time":
            timestamp = datetime.fromtimestamp(metadata["timestamp"], UTC) # inserted as int in upload endpoint
            return timestamp.strftime("%Y_%m")
        elif strategy == "shard":
            doc_id = metadata.get("document_id", "")
            hash_val = hash(doc_id) & 0x7FFFFFFF
            shard_count = settings.database.SHARD_COUNT
            return f"shard_{hash_val % shard_count}"
        else:
            return "default"
    

    async def update_partition_strategy(self, strategy: str):
        """Update partition strategy at runtime"""
        if strategy in ["category", "time", "shard", "default"]:
            self._current_strategy = strategy
            await self._initialize_partitions()  # Create new partitions if needed
            logger.info(f"Partition strategy updated to: {strategy}")
        else:
            raise ValueError(f"Invalid partition strategy: {strategy}")
    

    async def search(self, query: str, limit: int, category: Optional[str] = None) -> Dict[str, Any]:
        """
        Optimized hybrid search with advanced PostgreSQL features

        The default search flow is:
        1. Traverse HNSW graph (approximate algorithm)
        2. Return candidates based on graph structure
        3. May miss some true nearest neighbors
        
        Result: APPROXIMATE nearest neighbors (~95-98% recall)
        """        
        if not query or not isinstance(query, str) or not query.strip():
            return {"documents": [[]], "metadatas": [[]], "distances": [[]]}
        
        try:
            # Step 1: Primary semantic search with early termination
            # Try WITHOUT enhancement first (use cached embedding from endpoint's query cache semantic check!)
            semantic_results = await self._semantic_search(query, limit, category) # REUSES EMBEDDING CACHE!
            logger.info(f"Semantic results: {len(semantic_results)}")

            # Step 2: Distance filtering
            filtered_results = search_service.apply_distance_filter(semantic_results)
            logger.info(f"Filtered results: {len(filtered_results)}")

            if not filtered_results and search_service.config.enable_query_enhancement:
                # Enhance query
                enhanced_query, keywords = search_service.enhance_query(query)
                logger.info(f"Searching for Enhanced query: '{enhanced_query}' and "
                            f"Keywords: {keywords} in category: {category}")
            
                # try with enhancement
                enhanced_results = await self._semantic_search(enhanced_query, limit, category) # NEW EMBEDDING!
                logger.info(f"Enhanced semantic results: {len(enhanced_results)}")
                
                # did enhancement help?
                filtered_results = search_service.apply_distance_filter(enhanced_results)
                logger.info(f"Enhanced filtered results: {len(filtered_results)}")
            
            # Step 3: Keyword fallback if enabled
            if (search_service.config.enable_keyword_fallback and 
                not filtered_results and keywords):
                keyword_results = await self._keyword_search(keywords, limit, category)
                logger.info(f"Fallback keyword results: {len(keyword_results)}")
                filtered_results = keyword_results
            
            # Step 4: Final fallback if enabled, ensure minimum results
            if (search_service.config.enable_search_fallback and 
                not filtered_results and semantic_results):
                # Return best semantic results even if above threshold
                filtered_results = semantic_results[:limit]
                logger.info("Using fallback semantic results")
            
            # Format and return results
            return self._format_results(filtered_results)
        
        except DatabaseError:
            raise     
        except Exception as e:
            logger.error(f"Search failed: {e}")
            raise DatabaseError(f"Unexpected database search error: {e}")
    

    async def _semantic_search(self, query: str, limit: int, category: Optional[str]) -> List[Tuple[str, Dict, float]]:
        """Semantic search with optimized PostgreSQL queries"""
        try:
            query_embedding = await async_bridge.run_in_emb_thread(
                search_service.get_embedding,
                query
            )
            
            async with pg_pool.get_connection() as conn:
                # should be >= limit, ideally 2-4x limit for good recall
                # could be set once at pool manager (per-connection init) but here (pe-connection runtime) is most flexible
                await conn.execute(f"SET LOCAL hnsw.ef_search = {settings.database.DOC_HNSW_SEARCH_EF};")

                # Build optimized query based on category filter
                if category:
                    # Use partition pruning for better performance
                    # IMPORTANT NOTE:
                    # <-> is for Euclidean distance
                    # <#> is for Inner product distance (negative)
                    # <=> is for cosine distance (dissimilarity measure)
                    # which ranges [0, 2] where:
                    # 0.0 = identical vectors
                    # 1.0 = orthogonal (90° angle)
                    # 2.0 = opposite vectors
                    # needs conversion (1 - distance) to present 
                    # cosine similarity score (relatedness measure)  
                    # which ranges [-1, 1] where
                    # -1.0 = opposite (not applicable for text data as vectors are non-negative)
                    # 0.0 = orthogonal 
                    # 1.0 = identical
                    # it is best to store and sort by the raw distance value, 
                    # and only perform the (1 - distance) conversion to present 
                    # a user-friendly similarity score
                    sql = '''
                        WITH vector_results AS ( -- CTE ensure index usage before category filter
                            SELECT content, metadata, partition_key,
                                   embedding <=> $1 as distance
                            FROM vector_chunks
                            ORDER BY embedding <=> $1
                            LIMIT $3 * 2  -- 2x results to compensate for filtering
                        )
                        SELECT content, metadata, distance
                        FROM vector_results
                        WHERE partition_key = $2 -- this breaks HNSW index if applied directly on vector_chunks table
                        ORDER BY distance
                        LIMIT $3
                    '''
                    params = [query_embedding, category.lower(), limit]
                else:
                    # query all partitions with parallel execution
                    # no partition filter - direct HNSW usage
                    sql = '''
                        SELECT content, metadata, (embedding <=> $1) as distance
                        FROM vector_chunks 
                        ORDER BY embedding <=> $1
                        LIMIT $2
                    '''
                    params = [query_embedding, limit]
                
                # Use prepared statement for better performance
                stmt = await conn.prepare(sql)
                rows = await stmt.fetch(*params)

                if rows:
                    results = [
                        (
                            row['content'], 
                            json.loads(row['metadata']), 
                            float(row['distance'])
                        ) 
                            for row in rows
                    ]
                    
                    return results
                
                return []
                
        except Exception as e:
            logger.error(f"Semantic search error: {e}")
            # return []
            raise DatabaseError(f"Unexpected database semantic search error: {e}")
    

    async def _keyword_search(self, keywords: List[str], limit: int, category: Optional[str]) -> List[Tuple[str, Dict, float]]:
        """Optimized keyword search using PostgreSQL full-text search"""
        if not keywords:
            return []
        
        try:
            keyword_results = []
            top_k = keywords[:search_service.config.max_search_keyword] # Limit to top N keywords for performance

            # Decoupling embedding generation (CPU work) and the database writing (I/O work)
            # since we cant call threadpool while holding asyncpg connection as it corrupts the 
            # connection state causing cancelation error. asyncpg connections are tied to the 
            # event loop task, If connection is idle too long (while in thread pool), asyncpg cancels operations
            # this is specific to Postgres DB as SQL/Chroma are stateless independent connections
            batch_embeddings = await async_bridge.run_in_emb_thread(
                search_service.get_embeddings_batch,
                top_k
            )
            
            async with pg_pool.get_connection() as conn:
                # HNSW optimization: default 40 ~85% recall - fastest
                # ranges: 40, 100(~95% recall), 200(~98% recall), 400(~99% recall)
                await conn.execute(f"SET LOCAL hnsw.ef_search = {settings.database.DOC_HNSW_SEARCH_EF};")

                for idx, keyword in enumerate(top_k):
                    keyword_embedding = batch_embeddings[idx]
                    
                    if category:
                        sql = '''
                            SELECT content, metadata, (embedding <=> $1) as distance
                            FROM vector_chunks 
                            WHERE partition_key = $2 
                            AND content ILIKE $3
                            ORDER BY embedding <=> $1
                            LIMIT $4
                        '''
                        params = [keyword_embedding, category.lower(), f'%{keyword}%', limit]
                    else:
                        sql = '''
                            SELECT content, metadata, (embedding <=> $1) as distance
                            FROM vector_chunks 
                            WHERE content ILIKE $2
                            ORDER BY embedding <=> $1
                            LIMIT $3
                        '''
                        params = [keyword_embedding, f'%{keyword}%', limit]
                    
                    stmt = await conn.prepare(sql)
                    rows = await stmt.fetch(*params)
                    
                    for row in rows:
                        keyword_results.append((
                            row['content'], 
                            json.loads(row['metadata']), 
                            float(row['distance'])
                        ))
            
            # Deduplicate results
            seen_hashes = set()
            unique_results = []
            
            for doc, meta, dist in keyword_results:
                doc_hash = hash(doc) & 0x7FFFFFFF
                if doc_hash not in seen_hashes:
                    seen_hashes.add(doc_hash)
                    unique_results.append((doc, meta, dist))
            
            # still needed for global sorting across keywords
            return heapq.nsmallest(limit, unique_results, key=lambda x: x[2])
            
        except Exception as e:
            logger.error(f"Keyword search error: {e}")
            # return []
            raise DatabaseError(f"Unexpected database keyword search error: {e}")
    

    def _format_results(self, results: List[Tuple[str, Dict, float]]) -> Dict[str, Any]:
        """Format results for API response"""
        if results:
            documents, metadatas, distances = zip(*results)
            return {
                "documents": [list(documents)],
                "metadatas": [list(metadatas)],
                "distances": [list(distances)]
            }
        return {"documents": [[]], "metadatas": [[]], "distances": [[]]}
    

    async def add_single_chunk(
        self, 
        document_id: str,
        chunk: str,
        document_metadata: Dict[str, Any]
        ) -> None:
        """Add single chunk with deduplication and optimized insertion"""

        if not chunk or not chunk.strip():
            return
        
        try:
            # Get embedding and calculate content hash
            embedding = await async_bridge.run_in_emb_thread(
                search_service.get_embedding,
                chunk
            )
            
            # Determine partition
            partition_key = self._get_partition_key(document_metadata)

            # Ensure partition exists
            await self._ensure_partition(partition_key)

            # Create unique chunk ID
            timestamp = int(time.time() * 1_000_000)
            chunk_id = f"{document_id}_chunk_{timestamp}"
            
            chunk_metadata = json.dumps({
                **document_metadata,
            })
            
            async with pg_pool.get_connection() as conn:
                max_retries = 3
                for attempt in range(max_retries): 
                    try:
                        await pg_cb.execute(
                            lambda: conn.execute('''
                                INSERT INTO vector_chunks 
                                (document_id, chunk_id, content, embedding, metadata, partition_key, chunk_length)
                                VALUES ($1, $2, $3, $4, $5, $6, $7)
                            ''', document_id, chunk_id, chunk, embedding, chunk_metadata, partition_key, len(chunk)
                            )
                        )
                        break
                    except Exception as e:
                        if attempt == max_retries - 1:
                            raise
                        wait_time = 0.1 * (2 ** attempt)
                        logger.warning(f"Write retry {attempt + 1}/{max_retries} for chunk {chunk_id} after {wait_time}s: {e}")
                        await asyncio.sleep(wait_time)
                
                logger.debug(f"Added chunk {chunk_id} to partition {partition_key}")
        
        except DatabaseError:
            raise        
        except Exception as e:
            logger.error(f"Failed to add chunk to document store: {e}")
            # raise
            raise DatabaseError(f"Unexpected database chunk write error: {e}")

    
    async def add_chunks_batch(
        self, 
        document_id: str, 
        chunks: List[str],
        document_metadata: Dict[str, Any], 
        batch_size: Optional[int] = None
        ) -> int:
        """Optimized batch insertion with PostgreSQL COPY"""
        if not chunks:
            return 0
        try:
            # Dynamic batch sizing based on memory pressure
            if batch_size is None:
                memory_stats = search_service.get_memory_stats()
                memory_pressure = memory_stats["system_memory"]["percent_used"]
                batch_size = 10 if memory_pressure > 80 else (15 if memory_pressure > 60 else 20)

            # generate ALL embeddings first (outside DB context)
            logger.info(f"Generating embeddings for {len(chunks)} chunks...")
            
            # necessary evil for managing two distinct contexts that must not overlap
            # threadpool context and asyncpg I/O context
            all_embeddings = await self._generate_all_embeddings(chunks, batch_size)

            # batch database writes (with embeddings ready)
            logger.info(f"Writing {len(all_embeddings)} chunks to database...")
            
            total_added = await self._batch_write_chunks(
                document_id,
                chunks,
                all_embeddings,
                document_metadata,
                batch_size
            )
            
            logger.info(f"Added {total_added} chunks to database")

            return total_added
       
        except DatabaseError:
            raise        
        except Exception as e:
            logger.error(f"Failed to add chunks to document store: {e}")
            # raise
            raise DatabaseError(f"Unexpected database chunks write error: {e}")


    async def _generate_all_embeddings(self, chunks: List[str], batch_size: int) -> List[List[float]]:
        """Generate embeddings for all chunks in batches"""
        if not chunks:
            return []

        # could further process in sub-batches to avoid long blocking

        all_embeddings = []

        for i in range(0, len(chunks), batch_size):
            batch = chunks[i:i + batch_size]
            
            # generate embeddings (in thread pool, outside connection pool)
            batch_embeddings = await async_bridge.run_in_emb_thread(
                search_service.get_embeddings_batch,
                batch
            )
            
            all_embeddings.extend(batch_embeddings)
            
            # progress logging
            if (i + batch_size) % 50 == 0:
                logger.info(f"Generated {len(all_embeddings)}/{len(chunks)} embeddings")
            
            # yield control
            await asyncio.sleep(0.001)
        
        return all_embeddings


    async def _batch_write_chunks(
        self,
        document_id: str,
        chunks: List[str],
        embeddings: List[List[float]],
        document_metadata: Dict[str, Any],
        batch_size: int
    ) -> int:
        """Write chunks with pre-computed embeddings to database"""
        if not chunks or not embeddings:
            return 0
        
        if len(chunks) != len(embeddings):
            raise ValueError(
                f"Chunk/embedding mismatch: {len(chunks)} chunks, {len(embeddings)} embeddings"
            )

        # Determine partition
        partition_key = self._get_partition_key(document_metadata)
        
        # Ensure partition exists
        await self._ensure_partition(partition_key)

        total_added = 0
        timestamp = int(time.time() * 1_000_000)
    
        # Acquire connection only for batch writes
        async with pg_pool.get_connection() as conn:            
            # Batch insert loop
            for i in range(0, len(chunks), batch_size):
                batch = chunks[i:i + batch_size]
                batch_embeddings = embeddings[i:i + batch_size]

                # Build batch data, no CPU-intensive work - just data structuring
                batch_data = []
                
                for idx, (chunk, embedding) in enumerate(zip(batch, batch_embeddings)):
                    if not chunk or not chunk.strip():
                        continue
                    
                    chunk_id = f"{document_id}_chunk_{timestamp}_{i}_{idx}"
                    chunk_pos = i + idx
                    
                    chunk_metadata = json.dumps({
                        **document_metadata,
                    })

                    batch_data.append((
                        document_id, chunk_id, chunk, embedding, 
                        chunk_metadata, partition_key, len(chunk), chunk_pos
                    ))
                
                # Batch insert with retry for transient errors
                if batch_data:
                    max_retries = 3
                    for attempt in range(max_retries):
                        try:
                            await pg_cb.execute(
                                # Use executemany for better performance
                                lambda: conn.executemany('''
                                    INSERT INTO vector_chunks 
                                    (document_id, chunk_id, content, embedding, metadata, 
                                     partition_key, chunk_length, chunk_position)
                                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                                    ON CONFLICT (chunk_id, partition_key) DO NOTHING
                                ''', batch_data
                                )
                            )                       
                            total_added += len(batch_data)
                            break
                        except Exception as e:
                            if attempt == max_retries - 1:
                                raise
                            wait_time = 0.1 * (2 ** attempt)
                            logger.warning(f"Batch write retry {attempt + 1}/{max_retries} after {wait_time}s: {e}")
                            await asyncio.sleep(wait_time)
                
                # allow other operations between batches
                await asyncio.sleep(0.001)
    
        return total_added


    async def delete_document(self, document_id: str):
        """Optimized document deletion with cascade handling"""
        try:
            async with pg_pool.get_connection() as conn:
                # Use single query for better performance
                result = await pg_cb.execute(
                    conn.execute('''
                        DELETE FROM vector_chunks WHERE document_id = $1
                    ''', document_id
                    )
                )
                # Extract count from result string like "DELETE 5"
                deleted_count = int(result.split()[-1]) if result.split()[-1].isdigit() else 0
                
                if deleted_count > 0:
                    logger.info(f"Deleted document {document_id} with {deleted_count} chunks")
                else:
                    logger.warning(f"No chunks found for document {document_id}")
        
        except DatabaseError:
            raise        
        except Exception as e:
            logger.error(f"Failed to delete document {document_id}: {e}")
            # raise
            raise DatabaseError(f"Unexpected database document deletion error: {e}")


    async def optimize_collections(self):
        """Adaptive PostgreSQL optimization with VACUUM and ANALYZE"""
        try:
            logger.info("Starting PostgreSQL vector store optimization...")
            
            # Get current memory stats
            memory_stats = search_service.get_memory_stats()
            system_memory_percent = memory_stats["system_memory"]["percent_used"]
            
            logger.info(f"System memory usage: {system_memory_percent:.1f}%")
            
            async with pg_pool.get_connection() as conn:
                # Get partition information for targeted optimization
                partitions = await conn.fetch('''
                    SELECT schemaname, tablename, n_dead_tup, n_live_tup
                    FROM pg_stat_user_tables 
                    WHERE tablename LIKE 'vector_chunks_%'
                    AND n_dead_tup > 100
                    ORDER BY n_dead_tup DESC
                ''')
                
                # Optimize high-churn partitions
                for partition in partitions:
                    table_name = partition['tablename']
                    dead_ratio = partition['n_dead_tup'] / max(partition['n_live_tup'], 1)
                    
                    if dead_ratio > 0.1:  # More than 10% dead tuples
                        logger.info(f"Vacuuming partition {table_name} (dead ratio: {dead_ratio:.2f})")
                        await pg_cb.execute(
                            lambda t=table_name: conn.execute(f'VACUUM ANALYZE {t}')
                            )
                
                # Update statistics for query planner
                await conn.execute('ANALYZE vector_chunks')
                
                # Reindex if needed (based on fragmentation)
                index_stats = await conn.fetch('''
                    SELECT schemaname, tablename, indexname, idx_scan, idx_tup_read, idx_tup_fetch
                    FROM pg_stat_user_indexes 
                    WHERE tablename LIKE 'vector_chunks%'
                    AND idx_scan > 1000
                    ORDER BY idx_scan DESC
                ''')
                
                for idx_stat in index_stats[:5]:  # Only top 5 most used indexes
                    if idx_stat['idx_tup_read'] > idx_stat['idx_tup_fetch'] * 2:
                        index_name = idx_stat['indexname']
                        logger.info(f"Reindexing {index_name} due to fragmentation")
                        await pg_cb.execute(
                            lambda i=index_name: conn.execute(f'REINDEX INDEX CONCURRENTLY {i}')
                        )
            # Adaptive cache management
            hit_ratio = memory_stats["cache"]["hit_ratio"]
            if hit_ratio < search_service.config.cache_hit_ratio_threshold:
                logger.info(f"Low cache hit ratio ({hit_ratio:.3f}), adjusting cache size")
                new_limit = min(200, memory_stats["config"]["memory_limit_mb"] * 1.5)
                search_service.update_config(memory_limit_mb=int(new_limit))
            
            # Memory pressure management
            if system_memory_percent > 80:
                logger.warning("High system memory pressure, reducing cache size")
                search_service.embedding_cache.clear()
                search_service.update_config(memory_limit_mb=50)
            
            logger.info("Advanced PostgreSQL optimization completed")
        
        except DatabaseError:
            raise   
        except Exception as e:
            raise DatabaseError(f"Unexpected database optimization error: {e}")

 
    async def get_collection_stats(self) -> Dict[str, Any]:
        """Enhanced collection statistics with PostgreSQL-specific metrics"""
        try:
            async with pg_pool.get_connection() as conn:
                # Total chunks and partition statistics
                total_chunks = await conn.fetchval('SELECT COUNT(*) FROM vector_chunks')
                
                partition_stats = await conn.fetch('''
                    SELECT partition_key, COUNT(*) as count, 
                           AVG(chunk_length) as avg_chunk_length,
                           MIN(created_at) as oldest_chunk,
                           MAX(created_at) as newest_chunk
                    FROM vector_chunks 
                    GROUP BY partition_key
                    ORDER BY count DESC
                ''')

                partitions = {
                    row['partition_key']: {
                        'count': row['count'],
                        'avg_chunk_length': float(row['avg_chunk_length']) if row['avg_chunk_length'] else 0,
                        'oldest_chunk': row['oldest_chunk'],
                        'newest_chunk': row['newest_chunk']
                    }
                    for row in partition_stats
                }
                
                # Database performance statistics
                db_stats = await conn.fetchrow('''
                    SELECT 
                        pg_size_pretty(pg_database_size(current_database())) as db_size,
                        pg_size_pretty(pg_total_relation_size('vector_chunks')) as table_size
                ''')
                
                # Connection pool statistics
                pool_stats = await pg_pool.get_pool_stats()
                
                # Get search service stats
                memory_stats = search_service.get_memory_stats()
                
                return {
                    "total_chunks": total_chunks,
                    "partitions": partitions,
                    "database_stats": {
                        "database_size": db_stats['db_size'],
                        "table_size": db_stats['table_size']
                    },
                    "connection_pool": pool_stats,
                    "database_type": "PostgreSQL with pgvector",
                    "partition_strategy": self.partition_strategy,
                    "search_type": "optimized_hybrid_postgres",
                    "memory_stats": memory_stats,
                    "performance": {
                        "cache_hit_ratio": memory_stats["cache"]["hit_ratio"],
                        "memory_efficiency": memory_stats["cache"]["memory_mb"] / memory_stats["config"]["memory_limit_mb"]
                    },
                    "circuit_breaker": {
                        "failures": pg_cb.failures,
                        "is_open": pg_cb.is_open()
                    }
                }
                
        except Exception as e:
            logger.error(f"Failed to get collection stats: {e}")
            raise DatabaseError(f"Unexpected database stats error: {e}")

        
    async def health_check(self) -> Dict[str, Any]:
        """Comprehensive health check with PostgreSQL-specific metrics"""
        try:
            if not self._initialized:
                return {"status": "unhealthy", "error": "Not initialized"}
            
            async with pg_pool.get_connection() as conn:
                # Test basic operations
                await conn.fetchval('SELECT 1')
                
                # Check pgvector extension
                extension_check = await conn.fetchval('''
                    SELECT EXISTS(SELECT 1 FROM pg_extension WHERE extname = 'vector')
                ''')
                
                if not extension_check:
                    return {"status": "unhealthy", "error": "pgvector extension not available"}
                
                # Database connection and performance metrics
                db_metrics = await conn.fetchrow('''
                    SELECT 
                        pg_database_size(current_database()) as db_size_bytes,
                        (SELECT COUNT(*) FROM vector_chunks) as total_chunks,
                        (SELECT COUNT(*) FROM pg_stat_activity WHERE state = 'active') as active_connections,
                        (SELECT setting::int FROM pg_settings WHERE name = 'max_connections') as max_connections
                ''')
                
                # Get LRU cache memory and performance stats
                memory_stats = search_service.get_memory_stats()
                
                # Connection pool health
                pool_stats = await pg_pool.get_pool_stats()
                
                # Determine health status
                connection_ratio = db_metrics['active_connections'] / db_metrics['max_connections']
                memory_healthy = memory_stats["cache"]["memory_usage_percent"] < 90
                
                if connection_ratio > 0.9:
                    status = "unhealthy"
                    error = "Connection pressure"
                elif not memory_healthy:
                    status = "degraded"
                    error = "Memory pressure"
                else:
                    status = "healthy"
                    error = None
                
                health_info = {
                    "status": status,
                    "database_type": "PostgreSQL with pgvector",
                    "total_chunks": db_metrics['total_chunks'],
                    "database_size_mb": db_metrics['db_size_bytes'] / (1024 * 1024),
                    "connection_health": {
                        "active_connections": db_metrics['active_connections'],
                        "max_connections": db_metrics['max_connections'],
                        "connection_ratio": connection_ratio,
                        "pool_stats": pool_stats
                    },
                    "memory_stats": memory_stats,
                    "partition_strategy": self.partition_strategy,
                    "performance_metrics": {
                        "lru_cache_status": memory_stats["cache"]["status"],
                        "cache_hit_ratio": memory_stats["cache"]["hit_ratio"],
                        "cache_memory_usage_mb": memory_stats["cache"]["memory_mb"],
                        "cache_memory_utilization_percent": memory_stats["cache"]["memory_usage_percent"]
                    },
                    "circuit_breaker_status": "open" if pg_cb.is_open() else "closed"
                }

                if error:
                    health_info["error"] = error

                return health_info
                
        except Exception as e:
            logger.error(f"PostgreSQL health check failed: {e}")
            return {"status": "unhealthy", "error": str(e)}
            # raise DatabaseError(f"Unexpected database health check error: {e}")

    
    async def get_search_debug_info(self, query: str, category: Optional[str] = None) -> Dict[str, Any]:
        """Enhanced debug information with PostgreSQL-specific insights"""
        try:
            enhanced_query, keywords = search_service.enhance_query(query)
            semantic_results = await self._semantic_search(enhanced_query, 10, category)
            
            # Get embedding stats
            query_embedding = await async_bridge.run_in_emb_thread(
                search_service.get_embedding,
                query
            )
            embedding_stats = {
                "is_zero_vector": all(x == 0.0 for x in query_embedding),
                "embedding_norm": sum(x*x for x in query_embedding) ** 0.5,
                "non_zero_dimensions": sum(1 for x in query_embedding if abs(x) > 1e-6)
            }
            
            # Get database query performance stats
            async with pg_pool.get_connection() as conn:
                if category:
                    partition_info = await conn.fetchrow('''
                        SELECT COUNT(*) as chunk_count,
                               AVG(pg_column_size(embedding)) as avg_embedding_size
                        FROM vector_chunks 
                        WHERE partition_key = $1
                    ''', category.lower()
                    )
                else:
                    partition_info = await conn.fetchrow('''
                        SELECT COUNT(*) as chunk_count,
                               AVG(pg_column_size(embedding)) as avg_embedding_size
                        FROM vector_chunks
                    ''')
            
            # Connection pool health
            pool_stats = await pg_pool.get_pool_stats()

            # Get memory and performance stats
            memory_stats = search_service.get_memory_stats()
            
            return {
                "original_query": query,
                "enhanced_query": enhanced_query,
                "extracted_keywords": keywords,
                "embedding_stats": embedding_stats,
                "search_results_enhanced_query": {
                    "semantic_count": len(semantic_results),
                    "semantic_distances": [r[2] for r in semantic_results[:5]]
                },
                "database_info": {
                    "partition_chunk_count": partition_info['chunk_count'] if partition_info else 0,
                    "avg_embedding_size_bytes": float(partition_info['avg_embedding_size']) if partition_info and partition_info['avg_embedding_size'] else 0,
                    "searched_partition": category.lower() if category else "all_partitions"
                },
                "distance_interpretation": "Lower distances = better matches (0.0-0.4: excellent, 0.4-0.6: good, 0.6-0.8: acceptable)",
                "performance_stats": memory_stats,
                "configuration": {
                    "partition_strategy": self.partition_strategy,
                    "distance_threshold": search_service.config.distance_threshold,
                    "adaptive_threshold_enabled": search_service.config.enable_adaptive_threshold
                },
                "pool_stats": pool_stats
            }
            
        except Exception as e:
            logger.error(f"Debug info generation failed: {e}")
            # return {"error": str(e)}
            raise DatabaseError(f"Unexpected database debug info generation error: {e}")


    async def close(self):
        """Cleanup resources"""
        async with self._lock:
            if self._initialized:
                try:
                    # Cleanup search service first
                    search_service.cleanup()

                    # Clear partition cache
                    self._partitions.clear()

                    # Close connection pool gracefully
                    await pg_pool.unregister_component(self.COMPONENT_NAME)
                    self._initialized = False
                    # logger.info("Document Store closed successfully")

                except Exception as e:
                    logger.error(f"Error closing document store: {e}")
                    raise DatabaseError(f"Unexpected database closing error: {e}")