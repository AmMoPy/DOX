"""
Server-Sent Events (SSE) endpoint for real-time upload progress
Uses separate /sse prefix to bypass axios token refresh interceptor
"""

import json
import asyncio
import logging
from collections import defaultdict
from app.config.setting import settings
from app.auth.dependencies import require_admin
from app.utils.prog_trac import progress_tracker
from sse_starlette.sse import EventSourceResponse
from fastapi import APIRouter, HTTPException, Depends, Request

logger = logging.getLogger(__name__)


# Shared Instances
router = APIRouter(
    prefix="/sse", 
    tags=["events_steam"], 
    dependencies=[Depends(require_admin)] # Validates token via query URL
)

# Track connections per user
active_connections = defaultdict(int)

@router.get("/stream/{upload_id}")
async def stream_progress(
    upload_id: str, 
    request: Request
    ):
    """
    Server-Sent Events (SSE) endpoint for real-time 
    progress updates, Authentication via query parameter 
    (EventSource limitation), token is validated and revoked
    immediately.
    
    Args:
        upload_id: Unique identifier for the upload to track
        
    Returns:
        EventSourceResponse with progress stream
    """    
    admin_user = request.state.current_user
    user_id = str(admin_user.user_id) # UUID -> STR

    # Check connection limit (slowloris attack on SSE)
    if active_connections[user_id] >= settings.processing.MAX_CONCURRENT_UPLOADS: # IMP NOTE: MAX_CONCURRENT_UPLOADS gets adjusted at app start
        logger.warning(
            f"SSE connection rejected: user={user_id}, "
            f"active={active_connections[user_id]}, max={settings.processing.MAX_CONCURRENT_UPLOADS}, "
            f"upload_id={upload_id}"
        )
        
        # Mark as cancelled (keeps entry for upload endpoint to detect)
        await progress_tracker.cancel(upload_id) 

        raise HTTPException(
            status_code=429,
            detail=f"Too many concurrent SSE connections ({active_connections[user_id]}/{settings.processing.MAX_CONCURRENT_UPLOADS})"
        )

    # Track connection
    active_connections[user_id] += 1

    logger.info(
        f"Starting SSE stream for upload {upload_id} "
        f"(user: {user_id}) (available connections: {active_connections[user_id]}/{settings.processing.MAX_CONCURRENT_UPLOADS})"
    )
    
    try:
        # starts generator, connection stays open until completion/error
        return EventSourceResponse(_p_gen(upload_id, user_id))
    except Exception as e:
        # Cleanup immediately on failed EventSourceResponse start
        active_connections[user_id] -= 1
        logger.error(f"SSE connection failed: {e}")
        raise


# Helper Functions

async def _p_gen(upload_id: str, user_id: str):
    """
    Progress generator for SSE events

    Events:
    - progress: Regular progress updates
    - done: Upload completed/failed/cancelled
    - error: Upload not found or other errors
    """
    last_update = None
    poll_interval = 0.3  # 300ms polling
    update_count = 0
    max_wait_time = 10  # Wait up to 10 seconds for upload to start
    wait_time = 0
    
    try:
        # Wait for progress tracker to be initialized
        logger.info(f"SSE waiting for upload {upload_id} to initialize...")
        
        progress = None
        while not progress and wait_time < max_wait_time:
            progress = await progress_tracker.get(upload_id)
            
            if not progress:
                await asyncio.sleep(0.5)
                wait_time += 0.5
                logger.debug(f"Waiting for tracker... {wait_time}s/{max_wait_time}s")
        
        if not progress:
            logger.error(f"Upload {upload_id} never started after {max_wait_time}s")
            yield {
                "event": "error",
                "data": json.dumps({"error": "Upload initialization timeout"})
            }
            return
        
        logger.info(f"SSE stream started for upload {upload_id}")

        # Main streaming loop
        while True:
            progress = await progress_tracker.get(upload_id)
            
            if not progress:
                logger.warning(f"Progress tracker lost for {upload_id}")
                yield {
                    "event": "error",
                    "data": json.dumps({"error": "Upload tracking lost"})
                }
                break
            
            # Only send updates when data changes
            current_data = json.dumps(progress, default=str)
            if current_data != last_update:

                update_count += 1

                # debugging logs
                logger.info(
                    f"SSE update #{update_count} for {upload_id}: "
                    f"status={progress['status']}, "
                    f"stage={progress['stage']}, "
                    f"upload progress={progress['upload_percent']}%, "
                    f"chunks={progress['chunks_processed']}, "
                    f"pages={progress['pages_processed']}/{progress.get('total_pages', '?')}, "
                    f"elements={progress['elements_processed']}/{progress.get('total_elements', '?')}, "
                    f"bytes={progress['uploaded_bytes']}/{progress['total_size']}"
                )

                yield {
                    "event": "progress",
                    "data": current_data
                }
                last_update = current_data
            
            # Terminal states - send done event and stop
            if progress["status"] in ("complete", "failed", "cancelled"):
                logger.info(f"SSE stream ending for {upload_id}: {progress['status']}")
                yield {
                    "event": "done",
                    "data": current_data
                }
                
                # Clean up immediately after completion
                await progress_tracker.remove(upload_id)
                logger.info(f"SSE stream ended for upload {upload_id} after {update_count} updates")
                break
            
            await asyncio.sleep(poll_interval)
            
    except Exception as e:
        logger.error(f"SSE stream error for upload {upload_id}: {e}", exc_info=True)
        yield {
            "event": "error",
            "data": json.dumps({"error": str(e)})
        }
    finally:
        # Cleanup when generator ends
        active_connections[user_id] -= 1
        if active_connections[user_id] == 0:
            del active_connections[user_id]
        logger.info(f"SSE connection closed: {user_id} (remaining: {active_connections[user_id]})")