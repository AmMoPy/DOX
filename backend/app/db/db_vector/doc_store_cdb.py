import chromadb
import heapq
import time
import asyncio
import logging
from threading import Lock
from datetime import datetime, timedelta, UTC
from typing import List, Optional, Dict, Any, Tuple
from chromadb.config import Settings as ChromaSettings
from app.config.setting import settings
from app.db.utils_db.circuit_breaker import cdb_cb, DatabaseError
from app.db.utils_db.services_search import search_service
from app.db.utils_db.async_bridge import async_bridge

logger = logging.getLogger(__name__)


class ChromaDocStore:
    """
    ChromaDB vector store with optimized performance
    """
    
    # class attribute
    _lock = Lock()
    _instance = None
    

    def __new__(cls):
        """
        Overriding constructor for singleton pattern

        __new__ method is the first step in instance creation in Python. 
        Overriding it is crucial for implementing the Singleton pattern, 
        where only one instance of a class should exist.

        Why singleton via __new__ and not via Module (global instance)? Yes!
        """

        # The primary purpose of the lock in this context is to ensure that 
        # only one thread can execute the instance creation logic at a time. 
        # The first thread acquires the lock, creates the single instance, 
        # and subsequent threads wait until the lock is released, 
        # then see that the instance is already created and return the existing one
        with cls._lock: # Thread-safe singleton
            if cls._instance is None:
                cls._instance = super().__new__(cls) # creates the one and only object
                cls._instance.client = None
                cls._instance.collections = {} # lazy load in memory collections that are actually used
                cls._instance._initialized = False
                cls._instance.write_semaphore = asyncio.Semaphore(5)
                cls._instance.partition_strategy = settings.database.DOC_PARTITION_STRATEGY
                cls._instance._init_search_config()
                
            return cls._instance


    def _init_search_config(self):
        """Initialize search configuration"""
        config_params = {} # populate as needed
        
        # Update search service config
        search_service.update_config(**config_params)

    
    async def initialize(self):
        """Initialize ChromaDB with optimized settings"""
        with self._lock:
            if self.client is None and not self._initialized:
                try:
                    logger.debug("Initializing ChromaDB Vector cache...")

                    # Setup client
                    self.client = await cdb_cb.execute(
                        # Execution Timeline:
                        # self._setup_cdb_doc method OBJECT is passed to run_in_db_thread
                        # run_in_db_thread CALLS the method inside the thread pool
                        # and return a COROUTINE
                        # if passed self._setup_cdb_doc() this calls
                        # it IMMEDIATELY (blocks main thread!), the RESULT not the FUNCTION 
                        # is passed to and recieved by run_in_db_thread
                        # () is critical for timing while usage of 
                        # lambda = Closure/Complex Parameter Binding e.g. DB query (OPTIONAL). 
                        # because bridge already binds params using partial.
                        # Analogy:
                        # run(make_pizza) -> "Here's the pizza recipe" (deferred)
                        # similar to run(lambda: make_pizza())
                        # run(make_pizza, True) "Here's the pizza with extra cheese recipe " (deferred)
                        # similar to run(lambda: make_pizza(extra_cheese=True))
                        # run(make_pizza()) -> "I cooked it, here's the pizza" (immediate)
                        async_bridge.run_in_db_thread(self._setup_cdb_doc)
                    )

                    # Initialize collections based on strategy
                    await self._initialize_collections()
                    
                    self._initialized = True
                    logger.debug("ChromaDB Document store initialized successfully!")
                
                except DatabaseError:
                    raise            
                except Exception as e:
                    logger.error(f"Failed to initialize ChromaDB Document store: {e}")
                    raise DatabaseError(f"Unexpected database initialization error: {e}")

    
    def _setup_cdb_doc(self):
        """Sync setup for thread pool"""
        chroma_settings = ChromaSettings(
            anonymized_telemetry=False,
            allow_reset=False,
            is_persistent=True,
            persist_directory=str(settings.paths.CHROMA_DB_PATH)
        )
        
        client = chromadb.PersistentClient(
            path=str(settings.paths.CHROMA_DB_PATH / "docs"), # Data persists here
            settings=chroma_settings
        )

        return client

    
    async def _initialize_collections(self):
        """Initialize collections based on partition strategy"""
        # Collections = Logical Partitions, example of categoriesd collection
        # categories = ["hr", "finance", "legal", "it"]
        # Querying "hr" documents doesn't scan "finance" vectors - requires Cross-Category Search implementation
        # Vectors within same category are more similar
        # Cosine similarity works better in homogeneous spaces
        if self.partition_strategy == "category":
            categories = settings.database.DOC_DEFAULT_CATEGORIES
        elif self.partition_strategy == "time":
            # Initialize with current and recent months
            current_time = datetime.now(UTC) # UTC-based
            categories = []
            for i in range(-1, 12):  # Lookahead + current + next 12 months
                month_time = current_time - timedelta(days=30 * i) # fixed 30 days causes time drifts, acceptable for now, switch if exact start/end date of the calendar month is a requirement
                categories.append(month_time.strftime("%Y_%m")) # i.e.: 2025_12
        elif self.partition_strategy == "shard": # TODO: Future implementation Search Across All Shards
            shard_count = settings.database.SHARD_COUNT
            categories = [f"shard_{i}" for i in range(shard_count)]  # ["shard_0", "shard_1", ...]
        else:
            categories = ["default"]
        
        for category in categories:
            await self._ensure_collection(category)

    
    async def _ensure_collection(self, partition_key: str) -> chromadb.Collection:
        """Ensure collection exists with optimized HNSW parameters"""
        collection_name = f"{settings.database.DOC_COLLECTION_NAME}_{partition_key.lower()}"
        
        if collection_name not in self.collections:
            try:
                collection = await cdb_cb.execute(
                     async_bridge.run_in_db_thread(
                        lambda: self._create_collection(collection_name, partition_key)
                    )
                )
                self.collections[collection_name] = collection
                logger.debug(f"Collection created/loaded: {collection_name}")
            
            except DatabaseError:
                raise 
            except Exception as e:
                logger.error(f"Failed to create collection {collection_name}: {e}")
                # raise
                raise DatabaseError(f"Unexpected database collection creation error: {e}")
        
        return self.collections[collection_name]

    
    def _create_collection(self, collection_name: str, partition_key: str):
        """Sync collection creation, return collection if already on disk"""
        collection = self.client.get_or_create_collection( # gets from disk or creates new
            name=collection_name,
            metadata={
                "hnsw:space": settings.database.DOC_HNSW_SPACE,
                "hnsw:construction_ef": settings.database.DOC_HNSW_CONSTRUCTION_EF,
                "hnsw:search_ef": settings.database.DOC_HNSW_SEARCH_EF, 
                "hnsw:M": settings.database.DOC_HNSW_M,
                "partition_key": partition_key
            }
        )
        return collection


    def _get_partition_key(self, metadata: Dict[str, Any]) -> str:
        """Determine partition key with runtime configurability"""
        strategy = getattr(self, '_current_strategy', self.partition_strategy)
        
        if strategy == "category":
            return metadata.get("category", "uncategorized").lower()
        elif strategy == "time":
            timestamp = datetime.fromtimestamp(metadata["timestamp"], UTC) # inserted as int in upload endpoint
            return timestamp.strftime("%Y_%m")
        elif strategy == "shard": # Sharding strategy: this evenly spreads load across multiple collections
            doc_id = metadata.get("document_id", "")
            # Use faster hash function
            # Hash functions spread values randomly
            # Modulo ensures equal distribution across shards
            # Each shard gets ~25% of documents (with shard_count=4)
            # Example output: doc1 → hash 123456789 → shard_1  (123456789 % 4 = 1)
            hash_val = hash(doc_id) & 0x7FFFFFFF  # Ensure positive
            shard_count = settings.database.SHARD_COUNT # Number of distributed partitions to split data across
            return f"shard_{hash_val % shard_count}" # Documents are distributed using: hash(document_id) % shard_count
        else:
            return "default"

    
    def update_partition_strategy(self, strategy: str):
        """Update partition strategy at runtime"""
        if strategy in ["category", "time", "shard", "default"]:
            self._current_strategy = strategy
            logger.info(f"Partition strategy updated to: {strategy}")
        else:
            raise ValueError(f"Invalid partition strategy: {strategy}")

    
    async def search(self, query: str, limit: int, category: Optional[str] = None) -> Dict[str, Any]:
        """
        Optimized hybrid search with Multiple quality checks:
        
        1. DB returns top-k by distance
        2. heapq.nsmallest ensures we get the absolute best (Rank)
        3. Distance threshold removes marginal matches (filter - quality control)

        The default (in-memory/embedded mode) search flow is:
        1. Load entire collection into memory (in-process)
        2. Compute ALL distances using numpy/BLAS
        3. Sort ALL results
        4. Return top K
        
        Result: EXACT nearest neighbors (100% recall), it often performs a 
        brute-force, exact search across all vectors loaded into memory for 
        smaller datasets, guaranteeing 100% recall. This is fast for small 
        collections but is exactly why it wouldn't scale > 1M vectors efficiently.
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
            # return {"documents": [[]], "metadatas": [[]], "distances": [[]]}
            raise DatabaseError(f"Unexpected database search error: {e}")

    
    async def _semantic_search(self, query: str, limit: int, category: Optional[str]) -> List[Tuple[str, Dict, float]]:
        """
        Semantic search with parallel collection querying and early termination 
        """
        try:
            query_embedding = await async_bridge.run_in_emb_thread(
                search_service.get_embedding,
                query
            )
            collections_to_search = await self._get_collections_for_search(category)
            
            # Use heap for efficient top-k results
            all_results = []
            results_found = 0
            
            for collection_name, collection in collections_to_search:
                try:
                    results = await async_bridge.run_in_db_thread(
                        # c=collection is an explicit capture, captures 
                        # 'collection' at DEFINITION time (Early binding)
                        # while lambda: collection.query() uses 'collection' 
                        # at CALL time (Late binding). However, python 3+ the
                        # loop variables in lambdas do capture the current value
                        # Each iteration creates a NEW closure with the current 'collection' value
                        # could have used lambda collection.query() directly but let it be a
                        # reference to early vs late binding 
                        lambda c=collection: c.query(
                            query_embeddings=[query_embedding],
                            n_results=limit,
                            include=["documents", "metadatas", "distances"]
                            )
                        )
                    
                    if results and results.get("documents") and results["documents"][0]:
                        for doc, meta, dist in zip(
                            results["documents"][0],
                            results["metadatas"][0], 
                            results["distances"][0]
                        ):
                            all_results.append((doc, meta, float(dist)))
                            results_found += 1
                            
                        # Early termination if we have enough good results
                        # No need to query remaining collections after 2x desired results
                        # Saves time on less-relevant collections
                        # Still enough results for heapq to rank effectively
                        if results_found >= limit * 2:
                            break
                
                except Exception as e:
                    logger.warning(f"Semantic search failed for collection {collection_name}: {e}")
                    continue
            
            # Use heapq for efficient cross-partition (collection)
            # distance based ranking, lower = better similarity
            # Why heapq and not sorted()? time complexity
            # sorted() is O(n log n) - sorts ALL results (limit * N collection) while
            # heapq.nsmallest() is O(n log k) where k=limit - only maintains top-limit heap
            # for 1000 results, top 20: full sort O(1000 log 1000) ≈ 9966 ops vs 
            # O(1000 log 20) ≈ 4321 ops which is 57% faster
            return heapq.nsmallest(limit, all_results, key=lambda x: x[2])
            
        except Exception as e:
            logger.error(f"Semantic search error: {e}")
            # return []
            raise DatabaseError(f"Unexpected database semantic search error: {e}")

    
    async def _keyword_search(self, keywords: List[str], limit: int, category: Optional[str]) -> List[Tuple[str, Dict, float]]:
        """Optimized keyword search with embedding-based matching"""
        if not keywords:
            return []
        
        try:
            collections_to_search = await self._get_collections_for_search(category)
            keyword_results = []
            top_k = keywords[:search_service.config.max_search_keyword] # Limit to top N keywords for performance
            
            for collection_name, collection in collections_to_search:
                try:
                    # Search for documents containing any of the keywords
                    for keyword in top_k:
                        keyword_embedding = await async_bridge.run_in_emb_thread(
                            search_service.get_embedding,
                            keyword
                        )

                        results = await async_bridge.run_in_db_thread(
                            lambda c=collection, ke=keyword_embedding: c.query(
                                # query_texts=[keyword],  # Use text query instead of embedding, this download Chroma's default embedding model
                                query_embeddings=[ke],
                                n_results=limit,
                                include=["documents", "metadatas", "distances"]
                            )
                        )
                        
                        if results and results.get("documents") and results["documents"][0]:
                            for doc, meta, dist in zip(
                                results["documents"][0],
                                results["metadatas"][0], 
                                results["distances"][0]
                            ):
                                # Verify keyword actually appears in text
                                if keyword.lower() in doc.lower():
                                    keyword_results.append((doc, meta, float(dist)))
                
                except Exception as e:
                    logger.warning(f"Keyword search failed for collection {collection_name}: {e}")
                    continue
            
            # Deduplicate using fast hash-based approach
            seen_hashes = set()
            unique_results = []
            
            for doc, meta, dist in keyword_results:
                doc_hash = hash(doc) & 0x7FFFFFFF
                if doc_hash not in seen_hashes:
                    seen_hashes.add(doc_hash)
                    unique_results.append((doc, meta, dist))
            
            return heapq.nsmallest(limit, unique_results, key=lambda x: x[2])
            
        except Exception as e:
            logger.error(f"Keyword search error: {e}")
            # return []
            raise DatabaseError(f"Unexpected database keyword search error: {e}")

    
    async def _get_collections_for_search(self, category: Optional[str]) -> List[Tuple[str, chromadb.Collection]]:
        """Get collections with hot partition prioritization"""
        collections_to_search = []
        
        try:
            if category:
                partition_key = category.lower()
                collection_name = f"{settings.database.DOC_COLLECTION_NAME}_{partition_key}"
                if collection_name in self.collections:
                    collections_to_search.append((collection_name, self.collections[collection_name]))
            else:
                # Sort by collection size for hot partition prioritization
                collection_sizes = []
                for name, collection in self.collections.items():
                    try:
                        size = await async_bridge.run_in_db_thread(
                            lambda c=collection: c.count()
                            )
                        
                        collection_sizes.append((name, collection, size))
                    except Exception:
                        collection_sizes.append((name, collection, 0))
                
                # Prioritize larger collections (likely to have more relevant content)
                collection_sizes.sort(key=lambda x: x[2], reverse=True)
                collections_to_search = [(name, coll) for name, coll, _ in collection_sizes]
            
            return collections_to_search

        except Exception as e:
            logger.error(f"Failed to get collection: {e}")
            # raise
            raise DatabaseError(f"Unexpected database collection error: {e}")

    
    def _format_results(self, results: List[Tuple[str, Dict, float]]) -> Dict[str, Any]:
        """Format results for API response"""
        if results:
            documents, metadatas, distances = zip(*results)
            return {
                "documents": [list(documents)],
                "metadatas": [list(metadatas)],
                "distances": [list(distances)]
            }
        logger.info("No results found")
        return {"documents": [[]], "metadatas": [[]], "distances": [[]]}

    
    async def add_single_chunk(self, document_id: str, chunk: str, document_metadata: Dict[str, Any]) -> None:
        """Add single chunk"""
        if not chunk or not chunk.strip():
            return
        
        async with self.write_semaphore:
            try:
                partition_key = self._get_partition_key(document_metadata)
                collection = await self._ensure_collection(partition_key)
                
                # Insert new chunk
                max_retries = 3
                for attempt in range(max_retries):
                    try:
                        # TODO: Could also call in cb
                        embedding = await async_bridge.run_in_emb_thread(
                            search_service.get_embedding,
                            chunk
                        )                   
                             
                        await cdb_cb.execute(
                            async_bridge.run_in_db_thread(
                                lambda: self._add_single_chunk_op(
                                    collection, document_id, chunk, 
                                    embedding, document_metadata, partition_key
                                )
                            )
                        )
                        break
                    except Exception as e:
                        if attempt == max_retries - 1:
                            raise
                        wait_time = 0.1 * (2 ** attempt)  # Exponential backoff
                        logger.warning(f"Write retry {attempt + 1}/{max_retries} for chunk {chunk_id} after {wait_time}s: {e}")
                        await asyncio.sleep(wait_time)
                
            except DatabaseError:
                raise    
            except Exception as e:
                logger.error(f"Failed to add chunk to document store: {e}")
                # raise
                raise DatabaseError(f"Unexpected database chunk write error: {e}")


    def _add_single_chunk_op(
        self,
        collection,
        document_id: str,
        chunk: str,
        embedding: List[float],
        document_metadata: Dict[str, Any],
        partition_key: str
    ) -> None:
        """Sync add operation"""
        timestamp = int(time.time() * 1_000_000)
        chunk_id = f"{document_id}_chunk_{timestamp}"
        
        chunk_metadata = {
            **document_metadata,
            "chunk_id": chunk_id,
            "chunk_length": len(chunk),
            "partition": partition_key,
        }
        
        collection.add( # add always creates new entries, throws error if ID already exists
            documents=[chunk],
            embeddings=[embedding],
            ids=[chunk_id],
            metadatas=[chunk_metadata]
        )
        logger.debug(f"Added chunk {chunk_id} to partition {partition_key}")


    async def add_chunks_batch(
        self, 
        document_id: str, 
        chunks: List[str],
        document_metadata: Dict[str, Any], 
        batch_size: Optional[int] = None
    ) -> int:
        """Optimized batch insertion with dynamic batch sizing"""
        if not chunks:
            return 0

        try:
            # Dynamic batch sizing based on memory pressure
            if batch_size is None:
                memory_stats = search_service.get_memory_stats()
                memory_pressure = memory_stats["system_memory"]["percent_used"]
                # Smaller batches under memory pressure and 
                # Larger batches when memory is available
                batch_size = 10 if memory_pressure > 80 else (15 if memory_pressure > 60 else 20)
            
            partition_key = self._get_partition_key(document_metadata)
            collection = await self._ensure_collection(partition_key)
            
            total_added = 0
            timestamp = int(time.time() * 1_000_000) # microsecond precision to ensure uniqueness 
            
            for i in range(0, len(chunks), batch_size):
                
                batch = chunks[i:i + batch_size]

                # prepare batch data
                batch_data = []
                
                # filter valid chunks
                valid_chunks = [c for c in batch if c and c.strip()]
                
                if not valid_chunks:
                    continue
                
                # batch embedding generation (runs in thread pool)
                # esnure using separate pool than db to prevent thread 
                # pool starvation blocking (timeout/cancellation cascade)
                batch_embeddings = await async_bridge.run_in_emb_thread(
                    search_service.get_embeddings_batch,
                    valid_chunks
                )

                for idx, (chunk, embedding) in enumerate(zip(valid_chunks, batch_embeddings)):
                    chunk_id = f"{document_id}_chunk_{timestamp}_{i}_{idx}"
                    chunk_pos = i + idx

                    batch_data.append({
                        'document': chunk,
                        'embedding': embedding,
                        'id': chunk_id,
                        'metadata': {
                            **document_metadata,
                            "chunk_id": chunk_id,
                            "chunk_length": len(chunk),
                            "chunk_position": chunk_pos,
                            "partition": partition_key,
                        }
                    })
                
                if batch_data:
                    # retry Logic handles transient failures(temporary, short-lived faults, 
                    # such as a momentary loss of network connectivity, a brief service timeout, 
                    # or a short database lock). The assumption is that the operation will succeed 
                    # if attempted again after a short delay (often with exponential backoff) with
                    # limitations when faced with a persistent long-lasting failure of a service, as repeated excessive retries 
                    # will not succeed and just worsen the problem, overwhelming the failing service further and potentially 
                    # causing a self-inflicted Denial of Service (DoS) attack or cascading failures across the app.
                    # Circuit breaker handles persistent failures and prevents cascading problems (prevent app from 
                    # repeatedly trying to execute an operation that is likely to fail). After a predefined threshold of failures is reached, 
                    # the circuit "opens," and subsequent requests are immediately blocked or redirected to a fallback mechanism,
                    # without even attempting to call the failing service.
                    max_retries = 3
                    for attempt in range(max_retries):
                        try:
                            await cdb_cb.execute(
                                async_bridge.run_in_db_thread(
                                    lambda bd=batch_data, c=collection: self._add_batch_op(c, bd)
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
                
                # Allow brief pause between batches to prevent overwhelming the system
                if i + batch_size < len(chunks):
                    # time.sleep(0.01)
                    await asyncio.sleep(0.01)
            
            logger.info(f"Added {total_added} chunks to partition {partition_key}")
            return total_added
        
        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to add chunks to document store: {e}")
            # raise
            raise DatabaseError(f"Unexpected database chunks write error: {e}")

    
    def _add_batch_op(self, collection, batch_data: List[Dict]) -> None:
        """Sync batch add operation"""
        collection.add(
            documents=[item['document'] for item in batch_data],
            embeddings=[item['embedding'] for item in batch_data],
            ids=[item['id'] for item in batch_data],
            metadatas=[item['metadata'] for item in batch_data]
        )


    async def delete_document(self, document_id: str):
        """Delete document with improved error handling"""
        deleted_chunks = 0
        
        for collection_name, collection in self.collections.items():
            try:
                deleted = await cdb_cb.execute(
                    async_bridge.run_in_db_thread(
                        lambda c=collection: self._delete_document_op(c, document_id)
                    )
                )
                deleted_chunks += deleted
                
                if deleted > 0:
                    logger.debug(f"Deleted {deleted} chunks from {collection_name}")
            
            except DatabaseError:
                raise
            except Exception as e:
                logger.warning(f"Failed to delete from collection {collection_name}: {e}")
                continue
        
        if deleted_chunks > 0:
            logger.info(f"Deleted document {document_id} with {deleted_chunks} total chunks")
        else:
            logger.warning(f"No chunks found for document {document_id}")

    
    def _delete_document_op(self, collection, document_id: str) -> int:
        """Sync delete operation"""
        results = collection.get(
            where={"document_id": document_id},
            include=["metadatas"]
        )
        
        if results["ids"]:
            collection.delete(ids=results["ids"])
            return len(results["ids"])

        return 0


    async def get_collection_stats(self) -> Dict[str, Any]:
        """Get comprehensive statistics with performance metrics"""
        try:   
            total_chunks = 0
            partition_stats = {}
    
            # Get ALL collections from ChromaDB (not just cached ones)
            all_collections = await async_bridge.run_in_db_thread(
                lambda: self.client.list_collections()
            )
            
            # TODO: filter to only document collections (in case there are other collections)

            # for collection_name, collection in self.collections.items():
            for collection in all_collections:
                try:
                    count = await async_bridge.run_in_db_thread(
                        lambda c=collection: c.count()
                        )
                    
                    total_chunks += count

                    # Extract partition key from collection name
                    partition_key = collection.name.split(f"{settings.database.DOC_COLLECTION_NAME}_")[-1]
                    partition_stats[partition_key] = count
                except Exception as e:
                    logger.warning(f"Failed to get stats for {collection.name}: {e}")
                    partition_stats[collection.name] = 0
            
            # Include search service stats
            search_stats = search_service.get_memory_stats()
            
            return {
                "total_chunks": total_chunks,
                "partitions": partition_stats,
                "active_collections": len(self.collections), # Cached collections
                "total_collections": len(all_collections),    # All collections
                "search_type": "hybrid",
                "partition_strategy": getattr(self, '_current_strategy', self.partition_strategy),
                "search_service": search_stats,
                "circuit_breaker": {
                    "failures": cdb_cb.failures,
                    "is_open": cdb_cb.is_open()
                },
                "database_type": "ChromaDB"
            }
            
        except Exception as e:
            logger.error(f"Failed to get collection stats: {e}")
            # return {"total_chunks": 0, "partitions": {}, "error": str(e)}
            raise DatabaseError(f"Unexpected database stats error: {e}")

    
    async def optimize_collections(self):
        """Enhanced collection optimization with memory management"""
        try:
            logger.info("Starting collection optimization...")
            await async_bridge.run_in_db_thread(self._opti_col_op)
        
        except Exception as e:
            logger.error(f"Collection optimization failed: {e}")
            raise DatabaseError(f"Unexpected database collection optimization error: {e}")
    
    def _opti_col_op(self):
        """wrapping sync operations for unification"""

        # Get memory stats before optimization
        before_stats = search_service.get_memory_stats()
        
        # Check cache performance and adjust if needed
        cache_stats = before_stats["cache"]
        if cache_stats["hit_ratio"] < search_service.config.cache_hit_ratio_threshold:
            logger.warning(f"Low cache hit ratio: {cache_stats['hit_ratio']:.2f}")
            # Consider increasing cache size if memory allows
            if before_stats["system_memory"]["percent_used"] < 70:
                new_limit = min(search_service.config.memory_limit_mb * 1.5, 200)
                search_service.update_config(memory_limit_mb=new_limit)
                logger.info(f"Increased cache limit to {new_limit}MB due to low hit ratio")
        
        # Get stats after optimization
        after_stats = search_service.get_memory_stats()
        memory_freed = (before_stats["system_memory"]["percent_used"] - 
                        after_stats["system_memory"]["percent_used"])
        
        logger.info(f"Optimization completed - Memory freed: {memory_freed:.1f}%")


    async def health_check(self) -> Dict[str, Any]:
        """Comprehensive health check with performance monitoring"""
        try:
            if not self._initialized:
                return {"status": "unhealthy", "error": "Not initialized"}
            
            accessible_collections = 0
            total_collections = len(self.collections)
            collection_health = {}
            
            for collection_name, collection in self.collections.items():
                try:
                    count = await async_bridge.run_in_db_thread(
                        lambda c=collection: c.count()
                        )
                    
                    accessible_collections += 1
                    collection_health[collection_name] = {"status": "healthy", "count": count}
                except Exception as e:
                    collection_health[collection_name] = {"status": "error", "error": str(e)}
            
            # Check search service health
            memory_stats = search_service.get_memory_stats()
            memory_healthy = memory_stats["cache"]["memory_usage_percent"] < 90
            
            # Determine overall status
            if accessible_collections == 0:
                status = "unhealthy"
                error = "No collections accessible"
            elif accessible_collections < total_collections:
                status = "degraded"
                error = "Inaccessible collection"
            elif not memory_healthy:
                status = "degraded"
                error = "Memory pressure"  
            else:
                status = "healthy"
                error = None
            
            health_info = {
                "status": status,
                "database_type": "ChromaDB",
                "accessible_collections": accessible_collections,
                "total_collections": total_collections,
                "collection_health": collection_health,
                "memory_stats": memory_stats,
                "partition_strategy": self.partition_strategy,
                "performance_metrics": {
                    "lru_cache_status": memory_stats["cache"]["status"],
                    "cache_hit_ratio": memory_stats["cache"]["hit_ratio"],
                    "cache_memory_usage_mb": memory_stats["cache"]["memory_mb"],
                    "cache_memory_utilization_percent": memory_stats["cache"]["memory_usage_percent"]
                },
                "circuit_breaker_status": "open" if cdb_cb.is_open() else "closed"
            }
            
            if error:
                health_info["error"] = error
                
            return health_info
                
        except Exception as e:
            logger.error(f"Failed to get doc stats: {e}")
            return {'status': 'unhealthy', 'error': str(e)}


    async def get_search_debug_info(self, query: str, category: Optional[str] = None) -> Dict[str, Any]:
        """Debug information with performance metrics"""
        try:
            # using enhanced query for complete view if original 
            # results were not from enhanced version (fallbacks)
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
            
            # Get comprehensive stats
            search_stats = search_service.get_memory_stats()
            
            # Execute all counts concurrently
            counts = await asyncio.gather(*( # passing without list uses a generator expression, more memory-efficient
                async_bridge.run_in_db_thread(
                    lambda c=collection: c.count()
                    )
                for collection in self.collections.values()
            ))

            return {
                "original_query": query,
                "enhanced_query": enhanced_query,
                "extracted_keywords": keywords,
                "embedding_stats": embedding_stats,
                "search_results_enhanced_query": {
                    "semantic_count": len(semantic_results),
                    "semantic_distances": [r[2] for r in semantic_results[:5]]
                },
                "distance_interpretation": "Lower distances = better matches (0.0-0.4: excellent, 0.4-0.6: good, 0.6-0.8: acceptable)",
                "total_documents_in_db": sum(counts),
                "performance_stats": search_stats,
                "partition_strategy": getattr(self, '_current_strategy', self.partition_strategy),
                "config": {
                    "distance_threshold": search_service.config.distance_threshold,
                    "adaptive_threshold": search_service.config.enable_adaptive_threshold,
                    "keyword_fallback": search_service.config.enable_keyword_fallback
                }
            }
            
        except Exception as e:
            logger.error(f"Debug info generation failed: {e}")
            # return {"error": str(e)}
            raise DatabaseError(f"Unexpected database debug info generation error: {e}")


    async def close(self):
        """Cleanup resources"""
        with self._lock:
            try:
                if self.client is not None:
                    self.client = None
                    self.collections.clear()
                    self._initialized = False
                    
                # Cleanup search service
                search_service.cleanup()
                
                # logger.info("document store cleaned up")
            except Exception as e:
                logger.error(f"Error closing document store: {e}")
                raise DatabaseError(f"Unexpected database closing error: {e}")