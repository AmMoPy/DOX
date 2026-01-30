import asyncio
import logging
from datetime import datetime, UTC
from typing import Dict, Optional, Literal

logger = logging.getLogger(__name__)


ProgressStatus = Literal["uploading", "processing", "complete", "failed", "cancelled"]


class PTracker:
    """Thread-safe in-memory progress tracking"""
    
    def __init__(self):
        self._progress: Dict[str, Dict] = {}
        self._lock = asyncio.Lock()
        self._cancellation_flags: Dict[str, bool] = {}  # Track cancel requests
        self._cleanup_task = None
    
    async def create(self, upload_id: str, filename: str, total_size: int):
        """Initialize progress entry"""
        async with self._lock:
            self._progress[upload_id] = {
                "filename": filename,
                "total_size": total_size,
                "uploaded_bytes": 0,
                "status": "uploading",
                "stage": "Uploading file...",
                "upload_percent": 0,
                "chunks_processed": 0,
                "pages_processed": 0,    # pages for PDF
                "total_pages": None,
                "elements_processed": 0, # elements for DOCX
                "total_elements": None,
                "created_at": datetime.now(UTC),
                "updated_at": datetime.now(UTC),
                "detailed": True  # Flag for detailed (verbose) vs generic progress
            }
            self._cancellation_flags[upload_id] = False
            logger.info(f"Progress tracker created for upload {upload_id}")
    

    async def update_upload(self, upload_id: str, uploaded_bytes: int):
        """Update upload progress"""
        async with self._lock:
            if upload_id in self._progress:
                entry = self._progress[upload_id]
                entry["uploaded_bytes"] = uploaded_bytes
                entry["upload_percent"] = min(99, int((uploaded_bytes / entry["total_size"]) * 100))
                entry["updated_at"] = datetime.now(UTC)
    

    async def start_processing(self, upload_id: str, detailed: bool = True):
        """Mark processing started"""
        async with self._lock:
            if upload_id in self._progress:
                stage = "Processing document..." if not detailed else "Extracting text..."
                self._progress[upload_id].update({
                    "status": "processing",
                    "stage": stage,
                    "upload_percent": 100,  # Upload complete
                    "updated_at": datetime.now(UTC),
                    "detailed": detailed
                })
                logger.info(f"Processing started for upload {upload_id} (detailed={detailed})")
    

    async def update_extraction(self, upload_id: str, items_processed: int, total_items: int, item_type: str):
        """Update text extraction progress (detailed mode)"""
        async with self._lock:
            if upload_id in self._progress:
                entry = self._progress[upload_id]
                if entry.get("detailed", False):
                    entry.update({
                        f"{item_type}s_processed": items_processed,
                        f"total_{item_type}s": total_items,
                        "stage": f"Extracting text ({items_processed}/{total_items} {item_type}s)..."
                    })
                else:
                    entry["stage"] = "Extracting text..."
                
                entry["updated_at"] = datetime.now(UTC)
    

    async def update_chunking(self, upload_id: str, chunks_processed: int):
        """Update chunk processing progress (detailed mode)"""
        async with self._lock:
            if upload_id in self._progress:
                entry = self._progress[upload_id]
                entry["chunks_processed"] = chunks_processed
                
                if entry.get("detailed", False):
                    entry["stage"] = f"Extracting and chunking ({chunks_processed} chunks)..."
                else:
                    entry["stage"] = "Processing..."
                
                entry["updated_at"] = datetime.now(UTC)
    

    async def update_metadata(self, upload_id: str, filename: str, total_size: int):
        """Update metadata after initial creation"""
        async with self._lock:
            if upload_id in self._progress:
                self._progress[upload_id].update({
                    "filename": filename,
                    "total_size": total_size,
                    "stage": "Uploading file...",
                    "updated_at": datetime.now(UTC)
                })
                logger.info(f"Updated metadata for upload {upload_id}")


    async def complete(self, upload_id: str, total_chunks: int):
        """Mark upload complete"""
        async with self._lock:
            if upload_id in self._progress:
                self._progress[upload_id].update({
                    "status": "complete",
                    "stage": "Processing complete!",
                    "chunks_processed": total_chunks,
                    "updated_at": datetime.now(UTC)
                })
                logger.info(f"Upload {upload_id} completed with {total_chunks} chunks")
    

    async def fail(self, upload_id: str, error: str):
        """Mark upload failed"""
        async with self._lock:
            if upload_id in self._progress:
                self._progress[upload_id].update({
                    "status": "failed",
                    "stage": f"Error: {error}",
                    "updated_at": datetime.now(UTC)
                })
                logger.error(f"Upload {upload_id} failed: {error}")
    

    async def cancel(self, upload_id: str):
        """Request cancellation"""
        async with self._lock:
            if upload_id in self._cancellation_flags:
                self._cancellation_flags[upload_id] = True
                logger.info(f"Cancellation requested for upload {upload_id}")
            
            if upload_id in self._progress:
                self._progress[upload_id].update({
                    "status": "cancelled",
                    "stage": "Upload cancelled",
                    "updated_at": datetime.now(UTC)
                })
    

    async def is_cancelled(self, upload_id: str) -> bool:
        """Check if upload was cancelled"""
        async with self._lock:
            return self._cancellation_flags.get(upload_id, False)
    

    async def get(self, upload_id: str) -> Optional[Dict]:
        """Get progress entry"""
        async with self._lock:
            return self._progress.get(upload_id)
    

    async def remove(self, upload_id: str):
        """Remove progress entry immediately"""
        async with self._lock:
            if upload_id in self._progress:
                del self._progress[upload_id]
                logger.debug(f"Progress entry removed for upload {upload_id}")
            
            if upload_id in self._cancellation_flags:
                del self._cancellation_flags[upload_id]
    

    async def get_stats(self) -> Dict:
        """Get tracker statistics"""
        async with self._lock:
            return {
                "active_uploads": len(self._progress),
                "by_status": {
                    status: sum(1 for p in self._progress.values() if p["status"] == status)
                    for status in ["uploading", "processing", "complete", "failed", "cancelled"]
                }
            }


    async def start_cleanup_task(self, minutes: int = 60):
        """Start background cleanup task"""
        if self._cleanup_task is None:
            self._cleanup_task = asyncio.create_task(self._periodic_cleanup(minutes))
            logger.info("Progress tracker cleanup task started")

    
    async def _periodic_cleanup(self, minutes: int = 60):
        """Clean up old entries"""
        while True:
            try:
                await asyncio.sleep(minutes * 60)
                
                async with self._lock:
                    now = datetime.now(UTC)
                    to_remove = []
                    
                    for upload_id, entry in self._progress.items():
                        # Remove entries older than 5 minutes in terminal states
                        if entry["status"] in ("complete", "failed", "cancelled"):
                            age = (now - entry["updated_at"]).total_seconds()
                            if age > 300:  # 5 minutes
                                to_remove.append(upload_id)
                    
                    for upload_id in to_remove:
                        del self._progress[upload_id]
                        if upload_id in self._cancellation_flags:
                            del self._cancellation_flags[upload_id]
                    
                    if to_remove:
                        logger.info(f"Cleaned up {len(to_remove)} old progress entries")
            
            except Exception as e:
                logger.error(f"Cleanup task error: {e}")


# Global instance (singleton)
progress_tracker = PTracker()