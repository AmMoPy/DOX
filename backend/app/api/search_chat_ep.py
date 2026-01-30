import hashlib
import time
import logging
from uuid import UUID
from fastapi import APIRouter, HTTPException, Depends, Request
from app.models.base_models import (
    SearchQuery, AIQuery, AIResponse, User 
)
from app.config.setting import settings
from app.val.file_val import text_validator
from app.core.llm_client import llm_client
from app.core.rate_limiter import rate_limiter
from app.utils.result_formatter import formatter
from app.db.db_factory import doc_store, query_store
from app.db.utils_db.services_cache import QueryLRUCache
from app.auth.compliance.sec_audit_log import audit_logger
from app.auth.dependencies import get_current_user

logger = logging.getLogger(__name__)

# Shared Instances
router = APIRouter(prefix="/query", tags=["search & chat"])

query_memory_cache = QueryLRUCache(
    max_memory_mb=settings.database.QUERY_CACHE_MEMORY_MB,
    )


@router.post("/search")
async def search(
    query: SearchQuery,
    current_user: User = Depends(get_current_user), # All authenticated users
    request: Request = None
    ):
    """Search Docs"""

    clean_user_id = current_user.user_id # UUID
    ip_address = request.client.host if request else None
    user_agent = request.headers.get("User-Agent") if request else None
    
    async with rate_limiter.limit(
        clean_user_id,
        request_metadata={
            'action': 'search',
            'endpoint': '/query/search',
            'ip_address': ip_address,
            'user_agent': user_agent
        }
    ) as (allowed, reason):
        if not allowed:
            logger.warning(f"Search rate limited for user {clean_user_id}")

            # log for user stats tracking
            await audit_logger.log_event(
                event_type="search",
                user_id=clean_user_id,
                email=current_user.email,
                ip_address=ip_address,
                success=False,
                details={"reason": "rate limited"}
            )

            raise HTTPException(status_code=429, detail=reason)

        try:
            # Input validation and sanitization
            clean_query = text_validator.validate_text(query.query, "query")
            clean_category = text_validator.validate_text(query.category, "category") if query.category else None
        except HTTPException as e:
            logger.warning(f"Search query validation failed for user {clean_user_id}: {e.detail}")
            raise

        try:

            logger.debug(f"Search query: {query.query}, limit: {query.limit}")
            search_start = time.time()
            
            # Validate search parameters
            if len(clean_query.strip()) < 3:
                # report failure
                await rate_limiter.report_operation_result(clean_user_id, success=False)
                
                raise HTTPException(status_code=400, detail="Query too short (minimum 3 characters)")
            
            # Frontend needs to control how many results to DISPLAY
            # Backend needs to control how many results to RETRIEVE & PROCESS
            if query.limit > settings.processing.VECTOR_SEARCH_LIMIT:
                logger.warning(f"Search limit capped: requested={query.limit}, max={settings.processing.VECTOR_SEARCH_LIMIT}")
                query.limit = settings.processing.VECTOR_SEARCH_LIMIT # Enforce limit

            if query.category:
                logger.debug(f"Category filter: {clean_category}")
            
            # Use optimized search
            results = await doc_store.search( 
                query=clean_query,
                limit=query.limit,
                category=clean_category
                )
            
            search_time = time.time() - search_start
            result_count = len(results.get('documents', [[]])[0])
            
            # Add debug info
            debug_info = await doc_store.get_search_debug_info(clean_query, clean_category)
            logger.debug(f"Search debug: {debug_info}")

            # Security: Limit response size
            max_results = min(result_count, 50)  # Cap at 50 results. TODO: should match query limit?

            # report success
            await rate_limiter.report_operation_result(clean_user_id, success=True)

            logger.info(f"Search completed: {result_count} results in {search_time:.3f}s")
            
            # log for user stats tracking
            await audit_logger.log_event(
                event_type="search",
                user_id=clean_user_id,
                email=current_user.email,
                ip_address=ip_address,
                success=True,
                details={"query": clean_query[:200]} # for frontend display
            )

            formatted_results = formatter.format_search_results(results, max_results)

            return {
                "query": clean_query,
                "results": formatted_results,
                "search_time_ms": int(search_time * 1000),
                "total_results": min(result_count, max_results),
                "capped": result_count > max_results
            }

        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Search failed: {e}")
            raise HTTPException(status_code=500, detail=f"Search failed: {str(e)}")


@router.post("/ask", response_model=AIResponse)
async def ask(
    query: AIQuery, 
    current_user: User = Depends(get_current_user),
    request: Request = None
    ):
    """
    LLM chat handling with layered query cache matching
    
    Cache Strategy:
    1. Exact match in memory cache
    2. Semantic similarity match in database cache
    3. Generate new response from LLM
    """
    request_start_time = time.time()
    clean_user_id = current_user.user_id
    ip_address = request.client.host if request else None
    user_agent = request.headers.get("User-Agent") if request else None

    async with rate_limiter.limit(
        clean_user_id,
        request_metadata={
            'action': 'ai_query',
            'endpoint': '/query/ask',
            'ip_address': ip_address,
            'user_agent': user_agent
        }
    ) as (allowed, reason):
        if not allowed:
            logger.warning(f"AI query rate limited for user {clean_user_id}")

            # log for user stats tracking
            await audit_logger.log_event(
                event_type="ai_query",
                user_id=clean_user_id,
                email=current_user.email,
                ip_address=ip_address,
                success=False,
                details={"reason": "rate limited"}
            )

            raise HTTPException(status_code=429, detail=reason)
    
        # Input validation and sanitization
        try:
            clean_question = text_validator.validate_text(query.question, "llm")

            # Optionally audit log potential attacks
            if clean_question != query.question:

                # log event 
                await audit_logger.log_event(
                    event_type="suspicious_llm_input",
                    user_id=clean_user_id,
                    email=current_user.email,
                    ip_address=ip_address,
                    success=False,
                    details={
                        "original_sample": query.question[:200],
                        "sanitized_sample": clean_question[:200]
                    }
                )

        except HTTPException as e:
            logger.warning(f"AI query validation failed for user {clean_user_id}: {e.detail}")
            raise # TODO: raise or empty response?
        
        try:
            logger.info(f"AI question from {clean_user_id}: {clean_question[:100]}...")
            
            # Additional question validation
            if len(clean_question.strip()) < 5:
                # report failure
                await rate_limiter.report_operation_result(clean_user_id, success=False)
                
                return AIResponse(
                    answer="Question too short (use minimum 5 characters)",
                    sources=[],
                    from_cache=False,
                    response_time_ms=int((time.time() - request_start_time) * 1000),
                    provider_used="none"
                )

            if len(clean_question) > 1000:  # Reasonable limit
                logger.warning(f"Long question truncated for user {clean_user_id}")
                clean_question = clean_question[:1000] + "..."

            if settings.cache.ENABLE_QUERY_CACHE:

                # memory cache
                ttl_hours = settings.cache.CACHE_DEFAULT_TTL_HOURS

                # unique query ID for cache and DB storage
                cache_key = hashlib.sha256(clean_question.encode()).hexdigest()

                try:
                    # check memory cache (fastest for exact matches)
                    # purpose: Burst traffic, exact duplicates
                    # may have low hit rate is but impact is high when it hits (no db/LLM call)
                    cached_data = query_memory_cache.get(cache_key)

                    if cached_data:
                        total_time_ms = int((time.time() - request_start_time) * 1000)

                        logger.info(f"Memory cache hit for {clean_question[:100]}... ({total_time_ms}ms)")

                        # report success
                        await rate_limiter.report_operation_result(clean_user_id, success=True)

                        # log for user stats tracking
                        await audit_logger.log_event(
                            event_type="ai_query",
                            user_id=clean_user_id,
                            email=current_user.email,
                            ip_address=ip_address,
                            success=True,
                            details={"response source": "memory cache hit"}
                        )

                        return AIResponse(
                            answer=cached_data['response_text'],
                            sources=[],
                            provider_used=cached_data['provider_used'],
                            from_cache=True,
                            cache_level="memory",
                            response_time_ms=total_time_ms,
                            match_type="exact"
                        )

                    # semantic similarity search
                    semantic_results = await query_store.search(clean_question, cache_key, clean_user_id)
                    
                    if semantic_results:                    
                        total_time_ms = int((time.time() - request_start_time) * 1000)
                        response_text = semantic_results['response_text']
                        provider_used = semantic_results['provider_used']
                                          
                        # Warm memory cache
                        cache_data = {
                            "response_text": response_text,
                            "provider_used": provider_used,
                            "question_text": semantic_results['question_text'][:500]
                        }

                        query_memory_cache.put(cache_key, cache_data, ttl_seconds=min(ttl_hours * 3600, 3600))  # 60 min minimum TTL, independent of db ttl (shorter)

                        # report success
                        await rate_limiter.report_operation_result(clean_user_id, success=True)

                        # log for user stats tracking
                        await audit_logger.log_event(
                            event_type="ai_query",
                            user_id=clean_user_id,
                            email=current_user.email,
                            ip_address=ip_address,
                            success=True,
                            details={"response source": "database"}
                        )

                        return AIResponse(
                            answer=response_text,
                            sources=[],
                            provider_used=provider_used,
                            from_cache=True,
                            cache_level="vector_semantic",
                            response_time_ms=total_time_ms,
                            match_type="semantic",
                            similarity_score=semantic_results['similarity_score']
                        )
                
                except Exception as e:
                    logger.warning(f"Cached query search failed: {e}")

            # search documents (for LLM context)
            # redundant embedding API calls saved by caching layer  
            search_results = await doc_store.search( 
                query=clean_question,
                limit=settings.processing.VECTOR_SEARCH_LIMIT,
                category=None  # Search all document partitions
            )
            
            contexts = search_results.get('documents', [[]])[0]
            
            if not contexts:
                logger.info("No relevant context found for AI query")

                # report failure
                await rate_limiter.report_operation_result(clean_user_id, success=False)
                
                # log for user stats tracking
                await audit_logger.log_event(
                    event_type="ai_query",
                    user_id=clean_user_id,
                    email=current_user.email,
                    ip_address=ip_address,
                    success=False,
                    details={"rason": "No relevant context"}
                )

                return AIResponse(
                    answer="I couldn't find any relevant policies to answer your question.",
                    sources=[],
                    from_cache=False,
                    response_time_ms=int((time.time() - request_start_time) * 1000),
                    provider_used="none"
                )
            
            logger.debug(f"Found {len(contexts)} context chunks for AI query")

            # generate new response from LLM
            ctx_limit = settings.models.MAX_CHAT_CONTEXT

            combined_context = "\n\n".join(contexts[:ctx_limit])  # Limit context size, use top 3 results
            llm_start = time.time()
            
            try:
                answer, provider, response_metadata = await llm_client.query_with_context( 
                    clean_question, 
                    combined_context, 
                    clean_user_id
                )

                if not response_metadata:
                    return AIResponse(
                        answer=answer,
                        sources=[],
                        from_cache=False,
                        response_time_ms=int((time.time() - request_start_time) * 1000),
                        provider_used="none"
                    )

            except Exception as e:
                logger.error(f"LLM query failed for user {clean_user_id}: {e}")
                raise HTTPException(status_code=503, detail="AI service temporarily unavailable")

            llm_time = int((time.time() - llm_start) * 1000)
            
            # cache the response in BOTH systems (DB, Memory)
            # TODO: edge case storing valid LLM response but wrong context from poor search results
            if settings.cache.ENABLE_QUERY_CACHE and answer:
                try:
                    # cache in memory
                    cache_data = {
                        "response_text": answer,
                        "provider_used": provider.name,
                        "question_text": clean_question,
                    }

                    query_memory_cache.put(cache_key, cache_data, ttl_seconds=min(ttl_hours * 3600, 3600))

                    # Store question and metadata
                    await query_store.store_response(
                        question=clean_question,
                        cache_key=cache_key,
                        response=answer,
                        provider_used=provider.name,
                        user_id=clean_user_id,
                        tokens_used=response_metadata.get('tokens_used', 0),
                        response_time_ms=llm_time,
                    )

                    logger.info(f"Cached response for question: {clean_question[:16]}...")

                except Exception as e:
                    logger.warning(f"Failed to cache response: {e}")
            
            # Return New Response
            sources = formatter.format_ai_sources(
                contexts[:ctx_limit],
                search_results.get('metadatas', [[]])[0][:ctx_limit],
                search_results.get('distances', [[]])[0][:ctx_limit]
            )

            total_time_ms = int((time.time() - request_start_time) * 1000)
            logger.info(f"Generated AI response in {total_time_ms}ms (LLM: {llm_time}ms)")
            
            # report success
            await rate_limiter.report_operation_result(clean_user_id, success=True)

            # log for user stats tracking
            await audit_logger.log_event(
                event_type="ai_query",
                user_id=clean_user_id,
                email=current_user.email,
                ip_address=ip_address,
                success=True,
                details={"response source": "AI Generated"}
            )

            return AIResponse(
                answer=answer,
                sources=sources,
                provider_used=provider.name,
                from_cache=False,
                response_time_ms=total_time_ms,
                match_type="new"
            )

        except HTTPException:
            raise
        
        except Exception as e:
            logger.error(f"Failed to generate answer: {e}")
            raise HTTPException(status_code=500, detail=f"Failed to generate answer: {str(e)}")