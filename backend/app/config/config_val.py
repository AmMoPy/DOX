import psutil
import logging
from typing import List
from app.config.setting import AppSettings

logger = logging.getLogger(__name__)

class ConfigValidator:
    """Handles configuration validation logic"""
    
    def __init__(self, settings: AppSettings): # Dependency Injection: passing class instance in another class constructor (init)
        # this Store REFERENCE (not a copy) to the original "settings" instance that can be called/modified latter inside ConfigValidator
        # where modifications applies to the original "settings" instance not the ConfigValidator instance as in Composition where the 
        # class itself is passed and instantiated inside ConfigValidator.  
        # __init__ signature uses concrete (The type hint is a specific implementation class) instead of 
        # abstract (The type hint is an interface/abstract class) because AppSettings is stable and not likely to change
        self.settings = settings
    
    def validate_all(self) -> List[str]:
        """Run all validations and return list of issues fixed"""
        issues_fixed = []
        
        issues_fixed.extend(self._validate_file_limits())
        issues_fixed.extend(self._validate_concurrency())
        issues_fixed.extend(self._validate_database_config())
        
        return issues_fixed
    
    def _validate_file_limits(self) -> List[str]:
        """Validate and fix file size limits"""
        issues_fixed = []
        
        if self.settings.processing.MAX_FILE_SIZE > 100 * 1024 * 1024: # 100MB hard limit!
            self.settings.processing.MAX_FILE_SIZE = 100 * 1024 * 1024
            issues_fixed.append("Reduced MAX_FILE_SIZE to 100MB")
        
        return issues_fixed
    
    def _validate_concurrency(self) -> List[str]:
        """
        Validate concurrency settings based on system resources, 
        prevents OOM kills in containers with limited resources 
        (e.g., 1 CPU container) and auto-scales based on deployment 
        environment
        """
        issues_fixed = []
        
        try:
            # check resources
            cpu_count = psutil.cpu_count(logical=False) or 1 # Physical cores, never 0 
            available_memory_gb = psutil.virtual_memory().available / (1024**3)

            # Conservative estimate: 1 upload per 120MB RAM (100MB file + 20MB overhead) + 1 CPU core
            memory_based = max(1, int(available_memory_gb / 0.12)) # 0.12 roughly 120MB
            cpu_based = max(1, cpu_count) # 0 cores!

            # Minimum 1, maximum 10 (prevent excessive resource usage)
            max_safe_uploads = min(
                memory_based,
                cpu_based,
                10  # hard cap to prevent runaway concurrency
            )

            # adjust concurrency based on resources
            if (self.settings.processing.MAX_CONCURRENT_UPLOADS > max_safe_uploads or 
                self.settings.processing.MAX_CONCURRENT_UPLOADS < 1):
                # either max or ensure none 0
                threshold = max(1, max_safe_uploads) 
                self.settings.processing.MAX_CONCURRENT_UPLOADS = threshold
                issues_fixed.append(
                    f"Adjusted MAX_CONCURRENT_UPLOADS to {threshold} "
                    f"(CPUs: {cpu_count}, Available RAM: {available_memory_gb:.1f}GB)"
                    )
        except Exception as e:
            logger.warning(f"Could not detect system resources: {e}")
            # Fallback to safe default
            self.settings.processing.MAX_CONCURRENT_UPLOADS = max(1, self.settings.processing.MAX_CONCURRENT_UPLOADS)
        
        return issues_fixed
    
    def _validate_database_config(self) -> List[str]:
        """Validate database configuration"""
        # issues_fixed = []
        
        if self.settings.USE_POSTGRES: # cached property
            if not self._has_valid_postgres_config():
                raise ValueError("PostgreSQL enabled but missing configuration(s)") # fail fast, its gonna break anyways
        # return issues_fixed
        return []

    def _has_valid_postgres_config(self) -> bool:
        """Check if PostgreSQL configuration is valid"""
        db_config = self.settings.database
        return bool(
            db_config.PG_DATABASE_URL or 
            (db_config.PG_HOST and db_config.PG_PORT and db_config.PG_USER and db_config.PG_PASSWORD)
        )