import gc
import time
import psutil
import logging

logger = logging.getLogger(__name__)


class AdaptiveMemoryManager:
    """
    Hybrid GC strategy: Let Python work, intervene when needed
    """
    
    def __init__(self):
        # GC settings
        self.gc_frequency = 200          # Start conservative
        self.min_gc_frequency = 50       # Don't go below this
        self.max_gc_frequency = 1000     # Don't go above this
        
        # Memory thresholds
        self.warning_threshold = 75.0
        self.critical_threshold = 85.0
        
        # Performance tracking
        self.last_gc_time = time.time()
        self.gc_count = 0
        self.total_gc_time = 0.0
    

    def should_gc(self, element_count: int, force: bool = False) -> bool:
        """
        Decide if GC should run
        
        Strategy:
        1. Normal: Let Python handle it (no manual GC)
        2. Warning: Manual GC at adaptive frequency
        3. Critical: Force immediate GC
        """
        # Critical: Always GC
        if force:
            return True
        
        # Check memory pressure
        mem_pct = psutil.virtual_memory().percent
        
        # Critical: Force GC regardless of frequency
        if mem_pct >= self.critical_threshold:
            logger.warning(f"Critical memory: {mem_pct:.1f}% - forcing GC")
            self.gc_frequency = max(self.min_gc_frequency, self.gc_frequency // 2)
            return True
        
        # Warning: Use adaptive frequency
        if mem_pct >= self.warning_threshold:
            if element_count % self.gc_frequency == 0:
                # Adjust frequency based on memory
                if mem_pct > 80:
                    self.gc_frequency = max(self.min_gc_frequency, self.gc_frequency - 20)
                return True
        
        # Normal: Let Python handle it (return False)
        else:
            # Memory is fine - reduce manual GC frequency
            if element_count % 500 == 0:  # Check occasionally
                self.gc_frequency = min(self.max_gc_frequency, self.gc_frequency + 50)
            
            return False  # Let Python's automatic GC work
    

    def collect_with_timing(self) -> float:
        """
        Run GC and track timing
        """
        start = time.time()
        gc.collect()
        duration = time.time() - start
        
        self.gc_count += 1
        self.total_gc_time += duration
        self.last_gc_time = time.time()
        
        return duration
    
    
    def get_gc_stats(self) -> dict:
        """Get GC performance statistics"""
        avg_gc_time = self.total_gc_time / self.gc_count if self.gc_count > 0 else 0
        
        return {
            'gc_count': self.gc_count,
            'total_gc_time': self.total_gc_time,
            'avg_gc_time': avg_gc_time,
            'current_frequency': self.gc_frequency
        }