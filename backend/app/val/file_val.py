import re
import time
import magic
import bleach
import hashlib
import asyncio
import logging
import tempfile
import aiofiles
import unicodedata
from pathlib import Path
from fastapi import HTTPException, UploadFile
from typing import Dict, Any, Optional, Tuple, Set, Callable
from app.config.setting import settings

logger = logging.getLogger(__name__)


class SecurityError(Exception):
    """Base exception for security-related errors"""
    pass


class FileSizeError(SecurityError):
    """File size exceeds limits"""
    pass


class FileTypeError(SecurityError):
    """Invalid or suspicious file type"""
    pass


class FilenameError(SecurityError):
    """Invalid or malicious filename"""
    pass


class ContentError(SecurityError):
    """Suspicious file content"""
    pass


class FileValidator:
    """Security-focused file validator with efficient processing"""
    
    def __init__(self):
        # Track validation metrics
        self.validation_stats = {
            'total_validations': 0,
            'rejected_files': 0,
            'suspicious_files': 0,
            'last_reset': time.time()
        }
    

    def sanitize_filename(self, filename: str) -> str:
        """Safely sanitize filename with aggressive cleaning"""
        if not filename or not isinstance(filename, str):
            raise FilenameError("Empty or invalid filename")

        original_filename = filename

        # Basic cleaning
        filename = filename.strip()
        # allows basic ASCII characters, restricting unicode attacks
        filename = unicodedata.normalize('NFKD', filename).encode('ascii', 'ignore').decode('ascii')

        # Normalize path to prevent traversal
        try:
            clean_path = Path(filename).name
            if clean_path != filename:
                raise FilenameError("Filename contains path traversal attempts")
        except Exception as e:
            raise FilenameError(f"Invalid filename format: {str(e)}")
        
        # More restrictive whitelist: alphanumeric, underscore, hyphen, single dot, space
        # Prevents names like "file..txt", ".", " "
        if not re.match(r'^[a-zA-Z0-9_\-][a-zA-Z0-9_\-\. ]*[a-zA-Z0-9_\-]$', filename):
            raise FilenameError("Filename contains invalid characters")

        # Check for any remaining sneaky patterns
        for pattern in settings.val.SUSPICIOUS_PATTERNS:
            if re.search(pattern, filename):
                raise FilenameError("Filename contains suspicious patterns")
        
        # Limit length
        if len(filename) > settings.val.MAX_FILENAME_LENGTH:
            name_part, ext_part = Path(filename).stem, Path(filename).suffix
            max_name_len = settings.val.MAX_FILENAME_LENGTH - len(ext_part) - 1
            if max_name_len <= 0:
                raise FilenameError("Filename too long")
            filename = name_part[:max_name_len] + ext_part
        
        # Log suspicious patterns
        if filename != original_filename:
            logger.warning(f"Filename sanitized: '{original_filename}' -> '{filename}'")
            self.validation_stats['suspicious_files'] += 1
        
        return filename
    

    def validate_extension(self, filename: str) -> str:
        """Validate file extension against whitelist and blacklist"""
        file_path = Path(filename)
        extension = file_path.suffix.lower()
        
        if not extension:
            raise FileTypeError("File must have an extension")
        
        # Check against allowed extensions
        allowed_extensions = set(settings.val.ALLOWED_EXTENSIONS)
        if extension not in allowed_extensions:
            raise FileTypeError(f"File type not allowed: {extension}")
        
        return extension
    

    def validate_file_size_from_headers(self, file: UploadFile) -> Optional[int]:
        """Extract and validate file size from headers/attributes"""
        file_size = None
        
        # Try multiple ways to get file size
        size_sources = [
            getattr(file, 'size', None),
            getattr(file, 'content_length', None),
            getattr(file, 'headers', {}).get('content-length', None) if hasattr(file, 'headers') else None
        ]
        
        for size_source in size_sources:
            if size_source is not None:
                try:
                    file_size = int(size_source)
                    break
                except (ValueError, TypeError):
                    continue
        
        # Validate size if we got it
        if file_size is not None:
            if file_size <= 0:
                raise FileSizeError("File cannot be empty")
            
            if file_size > settings.processing.MAX_FILE_SIZE:
                max_mb = settings.processing.MAX_FILE_SIZE / (1024 * 1024)
                raise FileSizeError(f"File too large: {file_size / (1024*1024):.1f}MB > {max_mb:.0f}MB")
        
        return file_size
    

    def validate_mime_type(self, header_buffer: bytes, expected_extension: str) -> None:
        """
        File content validation using magic bytes"""

        try:
            # LAYER 1: Fast and simple executable signature check
            for signature, description in settings.val.executable_signatures.items():
                if header_buffer.startswith(signature):
                    raise ContentError(f"Executable file detected: {description}")

            # Additional check: encrypted/compressed executable
            if len(header_buffer) > 100:
                unique_bytes = len(set(header_buffer))
                entropy_ratio = unique_bytes / len(header_buffer)

                # Very high entropy might indicate encrypted content
                if entropy_ratio > 0.8 and len(header_buffer) > 1000:
                    logger.debug(f"High entropy content detected: {entropy_ratio:.2f}")
                    # Don't reject, just log - this could be legitimate compressed files
            
            # LAYER 2: Comprehensive MIME check
            mime = magic.Magic(mime=True)
            actual_mime_type = mime.from_buffer(header_buffer)

            # This result comes from complex pattern matching, not just the first few bytes
            if any(actual_mime_type.startswith(prefix) for prefix in settings.val.EXECUTABLE_PREFIXES):
                raise ContentError(f"Executable file detected: {actual_mime_type}")            

            # Get expected MIME types for the given extension
            expected_mime_types = settings.val.MIME_MAPPINGS.get(expected_extension.lower())
            
            if not expected_mime_types:
                raise FileTypeError( # Fail closed, block if not allowed
                    f"Cannot validate file type: "
                    f"No MIME mapping defined for extension '{expected_extension}'. "
                    f"Actual File content type: {actual_mime_type}"
                )
            
            # Check if actual MIME type matches any expected type
            if actual_mime_type not in expected_mime_types:
                raise FileTypeError(
                    f"File type mismatch. Possible file spoofing attempt. "
                    f"Expected Extension: {expected_extension}, "
                    f"Actual content: {actual_mime_type}"
                )
                
            logger.debug(f"MIME validation passed: {expected_extension} -> {actual_mime_type}")

        except ContentError:
            raise
        except FileTypeError:
            raise
        except Exception as e:
            logger.error(f"MIME validation failed: {e}")
            raise FileTypeError(f"MIME validation failed: {str(e)}")


    async def initial_file_validation(self, file: UploadFile) -> Dict[str, Any]:
        """Initial fast validation before processing"""
        self.validation_stats['total_validations'] += 1
        
        try:
            # 1. Validate and sanitize filename
            if not file.filename:
                raise FilenameError("No filename provided")
            
            safe_filename = self.sanitize_filename(file.filename)
            
            # 2. Validate extension
            extension = self.validate_extension(safe_filename)
            
            # 3. Validate size from headers
            declared_size = self.validate_file_size_from_headers(file)
            
            return {
                "original_filename": file.filename,
                "safe_filename": safe_filename,
                "extension": extension,
                "declared_size": declared_size,
                "validation_passed": True
            }
       
        # error mapping
        except FilenameError as e:
            self.validation_stats['rejected_files'] += 1
            logger.warning(f"File name validation failed: {e}")
            raise HTTPException(status_code=400, detail=str(e))  
        except FileTypeError as e:
            self.validation_stats['rejected_files'] += 1
            logger.warning(f"File type validation failed: {e}")
            raise HTTPException(status_code=400, detail=str(e))  
        except FileSizeError as e:
            self.validation_stats['rejected_files'] += 1
            logger.warning(f"File size validation failed: {e}")
            raise HTTPException(status_code=400, detail=str(e))
        except Exception as e:
            self.validation_stats['rejected_files'] += 1
            logger.error(f"Unexpected validation error: {e}")
            raise HTTPException(status_code=500, detail="File validation failed")
    

    async def secure_save_with_validation(
        self, 
        file: UploadFile, 
        temp_dir: Path,
        max_size: int,
        expected_size: Optional[int] = None,
        expected_extension: Optional[str] = None,
        progress_callback: Optional[Callable[[int], None]] = None
    ) -> Tuple[Path, int, str]:
        """
        Securely save file with streaming validation
        checking against:
            - Windows/Linux/macOS executables
            - Script files with shebangs
            - File extension spoofing attacks
            - Basic obfuscation attempts
        """
        
        # Create secure temporary file
        temp_file = tempfile.NamedTemporaryFile(
            dir=temp_dir,
            prefix="upload_",
            suffix=".tmp",  # Always use .tmp to prevent execution
            delete=False
        )
        temp_path = Path(temp_file.name)
        temp_file.close()
        
        # Security: Set restrictive permissions
        temp_path.chmod(0o600)  # Owner read/write only
        
        chunk_size = min(8192, settings.processing.STREAM_CHUNK_SIZE)  # Smaller chunks for security
        total_size = 0
        hash_obj = hashlib.sha256()
        
        # Buffer for early MIME type and executable detection
        header_buffer = b''
        header_captured = False

        try:
            async with aiofiles.open(temp_path, 'wb') as f:
                chunk_count = 0
                
                while True:
                    try:
                        chunk = await asyncio.wait_for(
                            file.read(chunk_size), 
                            timeout=30  # 30 second timeout per chunk
                        )
                    except asyncio.TimeoutError:
                        raise HTTPException(status_code=408, detail="Upload timeout")
                    
                    if not chunk:
                        break
                    
                    chunk_count += 1
                    total_size += len(chunk)
                    
                    # Size validation during streaming
                    # aborts early if file exceeds declared size
                    # enables rate limiting checks with actual file size AFTER I/O without wasting resources
                    if total_size > max_size:
                        raise FileSizeError(f"File exceeds maximum size: {max_size / (1024*1024):.0f}MB")

                    # Report progress
                    if progress_callback:
                        try:
                            # Call callback directly no await (it's already an async task creator)
                            progress_callback(total_size)
                        except Exception as e:
                            logger.warning(f"Progress callback failed: {e}")
                    
                    # Binary validation on first few chunks
                    if not header_captured:
                        header_buffer += chunk
                        # first 4KB is enough for both checks we only using PDF and DOCX files
                        # Stop buffering after 32KB even if no header found because 
                        # its either A headerless file type (like text), or
                        # A malicious file trying to evade detection
                        stop_buffering = (
                            len(header_buffer) >= 4096 or # We have plenty for validation
                            total_size > 32768 or         # We've buffered too much already  
                            not chunk                     # End of file
                        )

                        if stop_buffering:
                            # Only validate if we have enough data
                            header_captured = True
                            self.validate_mime_type(header_buffer, expected_extension)
                    
                    # Hash calculation
                    hash_obj.update(chunk)
                    
                    # Write chunk
                    await f.write(chunk)
                    
                    # Yield control and prevent DoS
                    if chunk_count % 100 == 0:
                        await asyncio.sleep(0.001)
                    
            # Final validations
            if total_size == 0:
                raise FileSizeError("File is empty")
            
            # Check size consistency
            if expected_size is not None and abs(total_size - expected_size) > 1024:
                logger.warning(f"Size mismatch: declared={expected_size}, actual={total_size}")
            
            file_hash = hash_obj.hexdigest()
            logger.debug(f"File saved securely: {total_size} bytes, hash: {file_hash[:16]}...")
            
            return temp_path, total_size, file_hash

        except HTTPException:
            raise    
        except ContentError:
            raise HTTPException(status_code=400, detail="File content error") 
        except FileTypeError:
            raise HTTPException(status_code=400, detail="File type error") 
        except FileSizeError:
            raise HTTPException(status_code=400, detail="File size error")
        except Exception as e:
            logger.error(f"Secure save failed: {e}")
            raise HTTPException(status_code=500, detail="File save failed")


    def get_validation_stats(self) -> Dict[str, Any]:
        """Get validation statistics"""
        current_time = time.time()
        uptime = current_time - self.validation_stats['last_reset']
        
        return {
            "total_validations": self.validation_stats['total_validations'],
            "rejected_files": self.validation_stats['rejected_files'],
            "suspicious_files": self.validation_stats['suspicious_files'],
            "rejection_rate": (
                self.validation_stats['rejected_files'] / 
                max(1, self.validation_stats['total_validations'])
            ) * 100,
            "uptime_seconds": int(uptime),
            "validations_per_minute": (
                self.validation_stats['total_validations'] / max(1, uptime / 60)
            )
        }
    

    def reset_stats(self):
        """Reset validation statistics"""
        self.validation_stats = {
            'total_validations': 0,
            'rejected_files': 0,
            'suspicious_files': 0,
            'last_reset': time.time()
        }
        logger.debug("Validation statistics reset")


class TextValidator:
    """Text security validator with aggressive cleaning for user input and API responses"""

    # Class-level constants (shared across all instances)
    # Define allowed tags/attributes for HTML sanitization (strip everything)
    ALLOWED_TAGS = []  # Strip ALL HTML tags, # ALLOWED_TAGS = ['code', 'pre'] Allow code blocks, not needed for this RAG system
    ALLOWED_ATTRIBUTES = {}  # Strip ALL attributes

    @staticmethod # Static methods are slightly faster than class methods
    def sanitize_text(text: str, field_name: str) -> str:
        """Robust sanitization using Bleach allowlist approach."""
        if not text:
            return ""

        # Bleach cleans HTML/JS injections via an ALLOWLIST
        sanitized_text = bleach.clean(
            text,
            tags=TextValidator.ALLOWED_TAGS, # Access class attributes directly
            attributes=TextValidator.ALLOWED_ATTRIBUTES,
            strip=True,
            strip_comments=True
        )

        # Remove null bytes and other control characters
        sanitized_text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', sanitized_text)
        
        if field_name == "llm":    
            # Remove potential role markers
            # TODO: EXCESIVE LOOKUPS, OPTIMIZE?
            sus_patterns = [
                r'\[INST\]', r'\[/INST\]',  # Llama format
                r'<\|im_start\|>', r'<\|im_end\|>',  # ChatML format
                r'###\s*(System|Assistant|User):', # Generic formats
                r'<\|system\|>', r'<\|assistant\|>', r'<\|user\|>',
                r'SYSTEM:', r'ASSISTANT:', r'USER:',
            ]

            for pattern in sus_patterns:
                sanitized_text = re.sub(pattern, '', sanitized_text, flags=re.IGNORECASE)

            # Remove excessive newlines (can be used for injection)
            sanitized_text = re.sub(r'\n{3,}', '\n\n', sanitized_text)

        return sanitized_text


    def validate_text(self, text: str, field_name: str = "query") -> str:
        """dynamic text validation"""
        if not text:
            return ""

        # Map field names to their specific setting
        length_limits = {
            'query': settings.val.MAX_QUERY_LENGTH,
            'llm': settings.val.MAX_QUERY_LENGTH, # for triggering LLM-specific input sanitization 
            'title': settings.val.MAX_TITLE_LENGTH, 
            'category': settings.val.MAX_CATEGORY_LENGTH
        }
        
        if field_name not in list(length_limits.keys()):
            raise HTTPException(status_code=400, detail=f"Unsupported field name: {field_name}")

        # Length check early exit
        max_length = length_limits.get(field_name)
        if len(text) > max_length:
            # TODO: RAISE OR TRUNCATE?
            # text = text[:max_length] + "... [truncated]"
            raise HTTPException(
                status_code=400, 
                detail=f"{field_name.title()} too long (max {max_length} characters)"
            )

        # check against allowed list
        sanitized = TextValidator.sanitize_text(text, field_name)
        
        # Normalize whitespace
        sanitized = re.sub(r'\s+', ' ', sanitized).strip()
        
        # Just log, if sanitization changed anything (potential attack)
        # Injections and XSS are addressed by parameterized querie and HTML sanitization
        if sanitized != text:
            logger.warning(
                f"Input sanitization triggered in {field_name}",
                extra={
                    "original_sample": text[:200],
                    "sanitized_sample": sanitized[:200],
                    "field_name": field_name
                }
            )

        return sanitized
    

# Global instance
file_validator = FileValidator()
text_validator = TextValidator()