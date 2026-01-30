import os
import logging
from typing import List
from app.config.setting import PathConfig

logger = logging.getLogger(__name__)

class DirectoryManager:
    """Handles directory creation and management"""
    
    def __init__(self, paths: PathConfig):
        self.paths = paths
    
    def create_directories(self) -> List[str]:
        """Create all necessary directories"""
        created = []
        
        for directory in self.paths.required_directories:
            try:
                if not directory.exists():
                    directory.mkdir(parents=True, exist_ok=True)
                    if hasattr(os, 'chmod'):
                        directory.chmod(0o700)
                    created.append(str(directory))
            except Exception as e:
                logger.warning(f"Failed to create directory {directory}: {e}")
        
        return created