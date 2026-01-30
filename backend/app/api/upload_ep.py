import traceback
import logging
import time
import asyncio
import gc
from uuid import uuid4
from pathlib import Path
from typing import Optional
from datetime import datetime, timedelta, UTC
from fastapi import APIRouter, UploadFile, File, Form, HTTPException, Depends, Request, Response
from app.models.base_models import UploadResponse, SSETokenResponse
from app.db.db_factory import doc_store, hash_store
from app.db.utils_db.circuit_breaker import DatabaseError
from app.core.rate_limiter import rate_limiter
from app.val.file_val import file_validator, text_validator
from app.auth.auth_mngr import auth_mgr
from app.auth.dependencies import require_admin
from app.auth.compliance.sec_audit_log import audit_logger
from app.config.setting import settings
from app.utils.file_processor_utils import (
    ContextAwareChunker, 
    TextNormalizer, 
    ContentDeduplicator, 
    HeaderFooterDetector,
    StringCache,
    FuzzyMatcher
    )
from app.utils.lsh import LSHIndexer
from app.utils.prog_trac import progress_tracker
from app.utils.mem_mngr import AdaptiveMemoryManager
from app.utils.file_processor import create_streaming_processor
from app.utils.file_prechunked_processor import PreChunkedProcessor, generate_template_docx

logger = logging.getLogger(__name__)


# Shared Instances
# could either be flat structure:
# 1. No prefix with clear endpoint paths: /endpoint_path
# 2. Prefixed routers: /prefix/endpoint_path
router = APIRouter(prefix="/docs", tags=["upload"], dependencies=[Depends(require_admin)])

# File upload
@router.post("/upload", response_model=UploadResponse)
async def upload(
    request: Request,
    file: UploadFile = File(...),
    title: str = Form(""),
    category: str = Form(""), # "" optional
    upload_id: str = Form(...), # ... required
    verbose: bool = Form(True, description="Show detailed progress")
    ):
    """
    Security-hardened and Memory-optimized upload with real-time progress tracking
    """
    clean_user_id = request.state.current_user.user_id # UUID 
    clean_user_email = request.state.current_user.email
    ip_address = request.client.host
    user_agent = request.headers.get("User-Agent")
    temp_file_path = None
    document_id = None
    file_hash = None
    binary_hash_stored = False
    chunks_processed = 0
    progress = None
    
    # Input validation and sanitization
    try:
        clean_title = text_validator.validate_text(title, "title")
        clean_category = text_validator.validate_text(category, "category")
    except HTTPException as e:
        logger.warning(f"Input validation failed for user {clean_user_id}: {e.detail}")
        raise

    try:
        logger.info(f"Starting optimized upload for user {clean_user_id}: {file.filename}")
        start_time = time.time()
        
        # Step 1: Security-focused file validation
        try:
            file_validation = await file_validator.initial_file_validation(file)
            logger.debug("Initial file validation passed")

            # Progress tracker already created by frontend 
            # calling /sse-token Just verify it exists
            progress = await progress_tracker.get(upload_id)

            if not progress:
                logger.warning(f"Upload attempted without progress tracker: upload_id={upload_id}")
                raise HTTPException(400, "Invalid upload session")

            # Check if already cancelled (SSE rejected due to limit)
            if progress["status"] == "cancelled":
                logger.info(
                    f"Upload rejected - already cancelled: upload_id={upload_id}, "
                    f"user={clean_user_id}, stage={progress['stage']}"
                )
                
                # Clean up immediately
                await progress_tracker.remove(upload_id)
                
                raise HTTPException(
                    status_code=409,  # Conflict - resource state doesn't allow operation
                    detail=progress["stage"]  # "Upload cancelled" or specific reason
                )

            # Update tracker with real filename and size
            await progress_tracker.update_metadata(
                upload_id,
                file_validation['safe_filename'],
                file_validation.get('declared_size', 0)
            )

        except HTTPException as e:
            # await progress_tracker.fail(upload_id, str(e.detail))
            logger.warning(f"File validation failed: {e.detail}")
            raise
        
        # Step 2: Create temporary file with proper cleanup
        # create temporary file
        temp_dir = settings.paths.UPLOAD_DIR / "temp"
        temp_dir.mkdir(parents=True, exist_ok=True, mode=0o700) # Owner only
        # TODO: better be passed around as UUID?
        document_id = str(uuid4())
        
        # Step 3: Secure file saving with streaming validation and progress tracking
        try:
            temp_file_path, actual_size, file_hash = await file_validator.secure_save_with_validation(
                file=file,
                temp_dir=temp_dir,
                max_size=settings.processing.MAX_FILE_SIZE,
                expected_size=file_validation.get('declared_size', 0),
                expected_extension=file_validation.get('extension'),
                progress_callback=lambda bytes_written: asyncio.create_task(
                    progress_tracker.update_upload(upload_id, bytes_written)
                )  # Upload progress callback
            )
            logger.debug(f"File saved securely: {actual_size} bytes")
        except HTTPException as e:
            logger.warning(f"Secure file save failed: {e.detail}")
            raise
        
        # Step 4: Rate limiting check
        async with rate_limiter.limit( # file validator rejects oversized files so no wasted resources before rate limiting
            clean_user_id,
            file_size_bytes=actual_size, # cannot be spoofed
            request_metadata={
                'action': 'upload',
                'endpoint': '/docs/upload',
                'ip_address': ip_address,
                'user_agent': user_agent,
                'filename': file_validation['safe_filename'],
                'file_size': actual_size,
                'upload_id': upload_id
            }
        ) as (allowed, reason):
            if not allowed:
                raise HTTPException(status_code=429, detail=reason)

            # Step 5: Initialize metadata     
            document_metadata = {
                "document_id": document_id,
                "title": clean_title or Path(file_validation['safe_filename']).stem,
                "category": clean_category or "uncategorized", 
                "filename": file_validation['safe_filename'],  # Use sanitized filename
                "original_filename": file_validation['original_filename'],
                "timestamp": int(datetime.now(UTC).timestamp()), # ensure UTC if needed later
                "user_id": str(clean_user_id), # UUID -> STR
                "file_size": actual_size,
                "file_hash": file_hash, # binary
                "validation_passed": True
            }
            
            # Step 6: Binary deduplication check (early exit optimization)
            try:
                existing_file = await hash_store.check_file_hash_exists(file_hash)
                if existing_file:
                    error_msg = f"File duplicate detected: {existing_file['filename']}"
                    logger.warning(f"{error_msg} (user: {clean_user_id})")
    
                    raise HTTPException(status_code=409, detail=error_msg)

            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"File deduplication check failed: {e}")
                raise
                # TODO: Continue processing - deduplication failure shouldn't stop upload?

            # Step 7: Store binary hash early for tracking
            try:
                await hash_store.store_file_hash(
                    file_hash, 
                    document_id, 
                    file_validation['safe_filename'],
                    clean_user_id,
                    actual_size
                )

                binary_hash_stored = True
                
                logger.debug("Binary hash stored")
            except Exception as hash_error:
                error_msg = "Failed to store binary hash"
                logger.error(f"{error_msg}: {hash_error}")
                
                raise HTTPException(status_code=500, detail=error_msg)

            # Step 8: Process file content with configurable adaptive components and security monitoring

            # Mark processing started
            await progress_tracker.start_processing(upload_id, detailed=verbose)

            # Check if pre-chunked (from frontend signal) - addon
            is_prechunked = request.headers.get('X-Pre-Chunked') == 'true'
            
            # Validate pre-chunked claim
            if is_prechunked:
                logger.info(f"Pre-chunked document claimed for {file_validation['safe_filename']}")
                                 
                processor = PreChunkedProcessor()

                # ensure template usage and return full text
                is_valid, full_text = await processor.validate_format(
                    temp_file_path,
                    file_validation['safe_filename']
                )

                if not is_valid:
                    raise HTTPException(
                        status_code=400,
                        detail="Document does not follow pre-chunked template format"
                    )

                # prepare caller input
                call_args = {
                    'text': full_text,
                    'upload_id': upload_id,
                    'progress_callback': _p_cb
                }

                logger.info(
                    f"Pre-chunked format validated: {len(full_text) / 1024:.1f}KB, "
                    f"using template processor"
                )
            else: 
                # Standard processing path - core feature
                logger.info(f"Standard document: {file_validation['safe_filename']}")

                # # Configure for optimal RAG performance - experiment with different configurations
                # chunker_configs = { 
                #     # For broader context (fewer, larger chunks) 
                #     'target_chunk_size': settings.processing.TARGET_CHUNK_SIZE,
                #     'max_chunk_size': settings.processing.MAX_CHUNK_SIZE
                #     }

                # hf_detector_configs = { 
                #     'sample_size': settings.processing.HF_PAGE_SAMPLES,
                #     'min_repetition': settings.processing.MIN_REPETITION,
                #     'skip_patterns': settings.processing.SKIP_PATTERNS,
                #     'max_header_lines': settings.processing.MAX_HEADER_LINES,
                #     'max_footer_lines': settings.processing.MAX_FOOTER_LINES
                #     }

                # dedup_configs = {              
                #     'doc_similarity_threshold': settings.processing.DOC_SIMILARITY_THRESHOLD,
                #     }
        
                # composition instances (request-specific)
                # pass config dicts here if needed
                chunker = ContextAwareChunker() 
                normalizer = TextNormalizer()
                deduplicator = ContentDeduplicator(LSHIndexer) # Indexer class not an instance
                fuzzy_matcher = FuzzyMatcher(deduplicator)
                mem_mngr = AdaptiveMemoryManager()
                hf_detector = HeaderFooterDetector()
                str_cache = StringCache()

                # main processor instance
                processor = create_streaming_processor(
                    chunker, normalizer, deduplicator, fuzzy_matcher, 
                    mem_mngr, clean_user_id, document_id, upload_id, 
                    hf_detector, str_cache, _p_cb
                    )

                # prepare caller input
                call_args ={
                    'file_path': temp_file_path, 
                    'filename': file_validation['safe_filename']
                }
                
            chunk_buffer = []
            buffer_size = 0
            # db batch_size should generally be larger than N chunks that fit in max_buffer_size
            # but never exceed the maximum allowable based on your buffer constraints which could cause memory overflow
            # currently the target_chunk_size is 300-600 so using a conservative estimate of 1k characters, 
            # then 20KB buffer / 1k characters = 20 max chunks
            # use this calculation to update target_chunk_size in chunkers and dynamic batch_size in vector databases
            max_buffer_size = 20000 # 20KB buffer smaller for better responsiveness, focus: Client-side memory pressure
            
            try:
                async for text_chunk, is_complete in processor.process_file(**call_args):
                    # Check for cancellation
                    if await progress_tracker.is_cancelled(upload_id): # user cancellation
                        logger.info(f"Upload {upload_id} cancelled by user")
                        raise HTTPException(status_code=499, detail="Upload cancelled by user")
 
                    if await request.is_disconnected(): # HTTP disconnect (request aborted)
                        logger.info(f"Upload {upload_id} client disconnected")
                        raise HTTPException(status_code=499, detail="Client disconnected")
               
                    # Security: Monitor processing time to prevent DoS
                    if time.time() - start_time > 300:  # 5 minute timeout
                        logger.warning(f"Processing timeout for {file_validation['safe_filename']}")
                        raise HTTPException(status_code=408, detail="Processing timeout")
     
                    # Buffer chunks for efficient DB writes
                    if text_chunk and text_chunk.strip():
                        chunk_buffer.append(text_chunk)
                        buffer_size += len(text_chunk)
                        
                        # Process buffer when full or complete
                        if buffer_size >= max_buffer_size or is_complete:
                            await doc_store.add_chunks_batch(
                                document_id, 
                                chunk_buffer, 
                                document_metadata
                            )

                            chunks_processed += len(chunk_buffer)

                            # Clear buffer and manage memory
                            chunk_buffer.clear()
                            buffer_size = 0
                            
                            # Frequent garbage collection for memory efficiency
                            if chunks_processed % 20 == 0:
                                gc.collect()
                                await asyncio.sleep(0.001)
                    
                    # Progress logging with security context
                    if chunks_processed % 20 == 0 and chunks_processed > 0:
                        logger.debug(f"Processed {chunks_processed} chunks for {file_validation['safe_filename']} (user: {clean_user_id})")
            
            except HTTPException:
                raise # just re-raise, details are captured at each checkpoint
            except DatabaseError as e:
                logger.error(f"Database error: {e}")
                # wrap in HTTPException for specificity
                raise HTTPException(status_code=500, detail="Database error")
            except Exception as e:
                logger.error(f"Content processing error: {e}")
                raise HTTPException(status_code=500, detail="Content processing failed")

            finally: # processing success
                chunk_buffer.clear()
                buffer_size = 0
                processor.cleanup()
            
            # Step 9: Final validation
            if chunks_processed == 0:
                error_msg = "No processable content found"
                await progress_tracker.fail(upload_id, error_msg)
                logger.warning(f"{error_msg}: {file_validation['safe_filename']}")
                raise HTTPException(status_code=400, detail=error_msg)

            # Step 10: Finalize processing
            await hash_store.mark_processing_complete(document_id)

            # report success
            await rate_limiter.report_operation_result(clean_user_id, success=True)

            # update progress
            await progress_tracker.complete(upload_id, chunks_processed)

            processing_time = time.time() - start_time

            logger.info(
                f"Upload {upload_id} completed: {chunks_processed} chunks "
                f"in {processing_time:.2f}s for {file_validation['safe_filename']} (user: {clean_user_id})"
            )
            
            # Audit log
            await audit_logger.log_event(
                event_type="upload_success",
                user_id=clean_user_id,
                email=clean_user_email,
                ip_address=ip_address,
                success=True
            )

            return UploadResponse(
                message="Document uploaded and processed successfully",
                document_id=document_id,
                upload_id=upload_id,
                filename=file_validation['safe_filename'],
                chunks_processed=chunks_processed
            )
    
    # re-raise all errors at each checkpoint
    # and handle cleanup at outer except blocks
    except HTTPException as e:
        event_type = "upload_fail"

        # update progress
        if e.status_code == 499:  # Cancellation
            event_type = "upload_cancelled"
            await progress_tracker.cancel(upload_id)
            logger.info(f"Upload {upload_id} cancelled")
        else:
            if progress: # edge case at initial upload check, dont report if not found
                await progress_tracker.fail(upload_id, str(e.detail))
            logger.error(f"Upload {upload_id} failed: {e.detail}")
        
        # report failure
        await rate_limiter.report_operation_result(clean_user_id, success=False)

        # Audit log
        await audit_logger.log_event(
            event_type=event_type,
            user_id=clean_user_id,
            email=clean_user_email,
            ip_address=ip_address,
            success=False,
            details={
                'error':str(e.detail),
                'type': type(e).__name__
            }
        )

        # cleanup
        await _cleanup_failed_upload(
            upload_id=upload_id,
            document_id=document_id,
            chunks_processed=chunks_processed,
            file_hash=file_hash,
            binary_hash_stored=binary_hash_stored
        )

        raise
    
    except Exception as e:
        await progress_tracker.fail(upload_id, "Unexpected upload error")
        logger.error(f"Unexpected upload error: {e}")
        logger.error(traceback.format_exc())

        # report failure
        await rate_limiter.report_operation_result(clean_user_id, success=False)

        # Audit log
        await audit_logger.log_event(
            event_type="upload_fail",
            user_id=clean_user_id,
            email=clean_user_email,
            ip_address=ip_address,
            success=False,
            details={
                'error':str(e)
            }
        )
        
        # cleanup
        await _cleanup_failed_upload(
            upload_id=upload_id,
            document_id=document_id,
            chunks_processed=chunks_processed,
            file_hash=file_hash,
            binary_hash_stored=binary_hash_stored
        )

        # Return generic error message for security
        raise HTTPException(status_code=500, detail="Upload processing failed")
    
    finally:
        # finally block runs on ALL exits (success + failure), this
        # ensures temp file removal and memory management for large uploads
        if temp_file_path and temp_file_path.exists():
            try:
                temp_file_path.unlink()
                logger.info("Temporary file cleaned up")
            except Exception as e:
                logger.warning(f"Failed to cleanup temporary file: {e}")
        
        # Memory cleanup for large uploads
        if chunks_processed > 100:
            gc.collect()


@router.post("/sse-token", response_model=SSETokenResponse)
# async def create_sse_token(upload_id: str, request: Request):
async def create_sse_token(request: Request):
    """
    Create temporary token for SSE progress streaming, Authentication 
    via normal header
    
    Token characteristics:
    - Short-lived (30 seconds) just enough to open the stream
    - Single-purpose (only for this upload_id)
    - Non-refreshable
    
    Args:
        upload_id: Upload ID to authorize access for
        current_user: Authenticated admin user
        
    Returns:
        Temporary SSE token and a unique upload request ID
    
    Why? EventSource doesnt support custom header so:
        Minimal Attack Vector: If the token is logged, it expires very quickly.
        Security Hygiene: It adheres to the principle of least privilege.
        Keeps Main Token Safe: The main session token is never used in the URL.
    """
    try:
        # Note: We don't check user_id ownership here because:
        # 1. Upload was just created by this authenticated user
        # 2. upload_id is a fresh UUID that only this user knows
        
        # Create temporary session (30s expiration)
        admin_user = request.state.current_user
        td = timedelta(seconds=30)

        temp_session = await auth_mgr.create_session(
            user_id=admin_user.user_id,
            timedelta=td
            )

        # unique request ID for tracking
        upload_id = str(uuid4())

        # Initialize progress tracker immediately
        await progress_tracker.create(
            upload_id,
            "Preparing upload...",  # Placeholder filename
            0  # Size unknown yet
        )

        logger.info(f"Created SSE token and tracker for upload {upload_id} (user: {admin_user.email})")

        # Audit log
        await audit_logger.log_event(
            event_type="sse_token_generated",
            user_id=admin_user.user_id,
            email=admin_user.email,
            success=True
        )
        
        return SSETokenResponse(
            sse_token=temp_session['access_token'],
            upload_id=upload_id,
            expires_at=temp_session['expires_at'], # ISO
            expires_in=td.seconds
        )
        
    except Exception as e:
        logger.error(f"Failed to create SSE token: {e}")
        raise HTTPException(
            status_code=500,
            detail="Failed to create progress token"
        )


@router.post("/cancel/{upload_id}")
async def cancel_upload(upload_id: str):
    """Request upload cancellation"""
    progress = await progress_tracker.get(upload_id)
    
    if not progress:
        raise HTTPException(status_code=404, detail="Upload not found")
    
    if progress["status"] in ("complete", "failed", "cancelled"):
        raise HTTPException(status_code=400, detail="Upload already finished")
    
    await progress_tracker.cancel(upload_id)
    
    return {"message": "Cancellation requested", "upload_id": upload_id}


@router.get("/stats")
async def get_progress_stats():
    """Get progress tracker statistics (admin only)"""
    return await progress_tracker.get_stats()


@router.get("/template/download")
async def download_template():
    """Download pre-chunk template (DOCX only)"""
    try:
        docx_bytes = generate_template_docx()
        filename = "prechunk_template.docx"

        return Response(
            content=docx_bytes,
            media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            headers={
                "Content-Disposition": f"attachment; filename={filename}"
            }
        )
    except Exception as e:
        logger.error(f"Template generation failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate template")


# Helper functions

async def _p_cb(current: int, total: int, message: str, upload_id: str):
    """Progress callback wrapper routing progress updates based on processing stage"""

    # Check for cancellation
    if await progress_tracker.is_cancelled(upload_id): # upload_id from outer scope
        raise HTTPException(status_code=499, detail="Upload cancelled by user")
    
    # Update based on message type
    pdf_or_docx = message.lower().split()[-1] # consistent message pattern

    if pdf_or_docx in ["page", "element"]:
        await progress_tracker.update_extraction(upload_id, current, total, pdf_or_docx)
    else: # chunks
        await progress_tracker.update_chunking(upload_id, current)


# TODO: context manager pattern for maximum elegance
async def _cleanup_failed_upload(
    upload_id: str,
    document_id: Optional[str] = None,
    chunks_processed: int = 0,
    file_hash: Optional[str] = None,
    binary_hash_stored: bool = False,
    temp_file_path: Optional[Path] = None
):
    """
    Centralized cleanup for failed/cancelled uploads
    
    Removes all traces:
    - Partial chunks from vector store
    - Binary hash entries
    - Progress tracker
    """
    cleanup_tasks = []
    
    # 1. Vector store cleanup
    if document_id and chunks_processed > 0:
        logger.debug(f"Scheduling vector store cleanup for {document_id}")
        cleanup_tasks.append(
            doc_store.delete_document(document_id)
        )
    
    # 2. Binary hash cleanup
    if binary_hash_stored and file_hash:
        logger.debug(f"Scheduling hash cleanup for {file_hash[:16]}...")
        cleanup_tasks.append(
            hash_store.remove_file_hash(file_hash)
        )
    
    # 3. Execute cleanup concurrently
    if cleanup_tasks:
        logger.info(f"Running {len(cleanup_tasks)} cleanup tasks for upload {upload_id}")
        cleanup_results = await asyncio.gather(*cleanup_tasks, return_exceptions=True)
        
        for i, result in enumerate(cleanup_results):
            if isinstance(result, Exception):
                logger.error(f"Cleanup task {i} failed: {result}")
    
    # 4. Cleanup temporary file
    if temp_file_path and temp_file_path.exists():
        try:
            temp_file_path.unlink()
            logger.debug(f"Removed temporary file: {temp_file_path.name}")
        except Exception as e:
            logger.warning(f"Failed to remove temp file: {e}")
    
    # 5. Remove progress tracker
    try:
        await progress_tracker.remove(upload_id)
        logger.debug(f"Removed progress tracker for {upload_id}")
    except Exception as e:
        logger.warning(f"Failed to remove progress tracker: {e}")
    
    # # 6. Memory cleanup
    # if chunks_processed > 100:
    #     gc.collect()
    #     logger.debug("Performed garbage collection after cleanup")