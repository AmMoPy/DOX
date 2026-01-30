import re
import logging
import psutil
from dataclasses import dataclass
from typing import List, Dict, Any, Tuple
from app.config.setting import settings
from app.db.utils_db.services_cache import VectorLRUCache

logger = logging.getLogger(__name__)


@dataclass
class SearchConfig:
    """
    Runtime configurable search parameters
    For Document Search only
    """
    # Initially reads settings and later
    # updatable at database initialization
    # act as a mutable subset of main settings
    distance_threshold: float = settings.processing.DOC_DISTANCE_THRESHOLD
    enable_adaptive_threshold: bool = settings.processing.ENABLE_ADAPTIVE_THRESHOLD
    enable_query_enhancement: bool = settings.processing.ENABLE_QUERY_ENHANCEMENT
    enable_keyword_fallback: bool = settings.processing.ENABLE_KEYWORD_FALLBACK
    enable_search_fallback: bool = settings.processing.ENABLE_SEARCH_FALLBACK
    memory_limit_mb: int = settings.processing.MEMORY_LIMIT_MB
    cache_hit_ratio_threshold: float = settings.processing.CACHE_HIT_RATIO_THRESHOLD
    max_search_keyword: int = settings.processing.MAX_SEARCH_KEYWORD


class SearchService:
    """Centralized vector search enhancement with memory management"""
    
    def __init__(self, config: SearchConfig):
        self.config = config
        self.embedding_cache = VectorLRUCache(self.config.memory_limit_mb)
        self._init_query_components()

        # Performance tracking
        self._query_count = 0
        self._total_response_time = 0.0
        self._semantic_hits = 0
        self._exact_hits = 0
    

    def _init_query_components(self):
        """Initialize query enhancement dictionaries"""

        # These are just examples from test 
        # document for demo - adjust as needed
        self.abbreviations = {
            "PTO": "paid time off vacation leave",
            "HR": "human resources personnel", 
            "KYC": "know your customer identification",
            "AML": "anti money laundering compliance",
            "CDD": "customer due diligence verification",
            "STR": "suspicious transaction reporting",
            "PEP": "politically exposed person",
            "PMLA": "prevention money laundering act",
            "FIU": "financial intelligence unit",
            "CCR": "counterfeit currency report",
            "CIP": "customer identification program",
            "UNSCR": "united nations security council resolution",
            "NRFSI": "nissan renault financial services india",
            "RBI": "reserve bank india",
            "NBFC": "non banking financial company",
            "GM": "general manager"
        }
        
        self.synonyms = {
            "policy": ["guideline", "procedure", "rule", "regulation"],
            "customer": ["client", "account holder", "borrower", "applicant"],
            "verification": ["validation", "confirmation", "check"],
            "document": ["form", "paper", "record", "file"],
            "approval": ["authorization", "permission", "consent"],
            "requirement": ["condition", "criteria", "prerequisite"],
            "process": ["procedure", "workflow", "method"],
            "compliance": ["adherence", "conformity", "observance"],
            "risk": ["danger", "threat", "hazard", "exposure"],
            "assessment": ["evaluation", "review", "analysis"],
            "monitoring": ["tracking", "surveillance", "oversight"],
            "report": ["statement", "summary", "document"],
            "transaction": ["deal", "exchange", "transfer"],
            "account": ["profile", "record", "file"],
            "identity": ["identification", "credentials", "details"]
        }
        
        self.stop_words = {
            "the", "is", "are", "was", "were", "be", "been", "being", "have", 
            "has", "had", "do", "does", "did", "will", 'shall', 'what', 'who', 
            'which', 'whose', 'whom', "would", "could", "should", "may", "might", 
            "must", "can", "of", "in", "on", "at", "to", "for", "with", "by", "from", 
            "about", "into", "through", "during", "before", "after", "above", "below", 
            "up", "down", "out", "off", "over", "under", "again", "further", "then", 
            "once", "here", "there", "when", "where", "why", "how", "all", 
            "any", "both", "each", "few", "more", "most", "other", "some", 
            "such", "no", "nor", "not", "only", "own", "same", "so", "than", 
            "too", "very", "just", "now", "also", "however", "as", 
            "if", "or", "and", "but", 'please', 'tell', 'show', 'give', 'explain', 
            'describe', 'provide', 'know', 'want', 'need', 'like', 'get', 'find', 'help', 
            'let', 'make'
        }
    

    def get_embedding(self, text: str) -> List[float]:
        """
        Get embedding with optimized caching
        Will be called via async_bridge.run_in_executor()
        """
        # Try cache first
        embedding = self.embedding_cache.get(text)
        if embedding is not None:
            return embedding
        
        # Generate new embedding
        from app.core.embedding_client import embedding_client
        embedding = embedding_client.get_embedding(text) # synchronous blocking call
     
        # Validate embedding
        if all(x == 0.0 for x in embedding):
            logger.warning(f"Zero embedding generated for text: {text[:50]}...")
            return embedding
        
        # Cache the result
        self.embedding_cache.put(text, embedding)
        return embedding


    def get_embeddings_batch(self, texts: List[str]) -> List[List[float]]:
        """
        Batch embedding generation with caching

        This is intentionally synchronous because:
        1. Model inference is CPU-bound (not I/O)
        2. Will be called via async_bridge.run_in_executor()
        3. Sentence-transformers' encode() is sync

        Args:
            texts: List of text strings to embed
            
        Returns:
            List of embedding vectors (same order as input)
        """
        if not texts:
            return []
        
        # Check cache first - build results with placeholders
        embeddings = []
        uncached_texts = []
        uncached_indices = []
        
        for idx, text in enumerate(texts):
            cached = self.embedding_cache.get(text)
            
            if cached is not None:
                embeddings.append(cached)
            else:
                embeddings.append(None)  # Placeholder
                uncached_texts.append(text)
                uncached_indices.append(idx)
        
        # Batch encode uncached texts using existing embedding_client method
        if uncached_texts:
            from app.core.embedding_client import embedding_client
            
            batch_embeddings = embedding_client.get_embeddings(
                uncached_texts
                # batch_size=8 by default - safe for CPU
            )
            
            # Fill in results and cache
            for idx, emb in zip(uncached_indices, batch_embeddings):
                embeddings[idx] = emb
                
                # Cache for future use
                self.embedding_cache.put(texts[idx], emb)
        
        return embeddings


    def enhance_query(self, query: str) -> Tuple[str, List[str]]:
        """Enhanced query processing with abbreviation expansion"""
        original_query = query.strip()
        
        # Expand abbreviations
        enhanced_query = self._expand_abbreviations(original_query)

        # Extract keywords
        keywords = self._extract_keywords(original_query)
        
        logger.debug(f"Query enhancement: '{original_query}' -> '{enhanced_query}' | Keywords: {keywords}")
        return enhanced_query, keywords
    

    def _expand_abbreviations(self, query: str) -> str:
        """Expand domain-specific abbreviations"""
        enhanced_query = query
        
        for abbr, expansion in self.abbreviations.items():
            pattern = r'\b' + re.escape(abbr) + r'\b'
            replacement = f"{abbr} {expansion}"
            enhanced_query = re.sub(pattern, replacement, enhanced_query, flags=re.IGNORECASE)
        
        return enhanced_query
    

    def _extract_keywords(self, query: str) -> List[str]:
        """Extract important keywords for hybrid search"""
        words = re.findall(r'\b\w+\b', query.lower())
        
        keywords = [
            word for word in words 
            if word not in self.stop_words 
            and len(word) > 2
            and not word.isdigit()
        ]
        
        # Return top 5 unique keywords
        return list(dict.fromkeys(keywords))[:5]
    

    def apply_distance_filter(self, results: List[Tuple[str, Dict, float]]) -> List[Tuple[str, Dict, float]]:
        """
        Apply configurable DISTANCE threshold filtering

        Quality gate (reject bad matches), After sort (heapq/ORDER BY)
        returns top N, distance filter removes bad matches below
        threshold so we dont send garbage to LLM. Example output 
        (distances): [0.12, 0.15, 0.18, 0.45, 0.72], result #4 and #5 
        might be poor matches so filter by distance threshold
        """
        if not results:
            return results
        
        threshold = self.config.distance_threshold
        
        # Apply adaptive threshold if enabled
        if self.config.enable_adaptive_threshold and len(results) >= 3:
            distances = [r[2] for r in results]
            median_dist = sorted(distances)[len(distances) // 2] # Sort ascending (best first)
            
            # Use median-based adaptive threshold, but keep within bounds
            # For cosine distance: threshold should be LOW (keep similar results)
            # adaptive_threshold = min(0.25, max(0.15, median_dist + 0.1)) # don't go below 0.15 or above 0.25, adjust if overly aggressive (lower = tighter filtering)
            adaptive_threshold = min(0.8, max(0.4, median_dist + 0.1)) # adjust if overly permissive (higher = poor filtering)
            threshold = min(threshold, adaptive_threshold)
        
        filtered = [result for result in results if result[2] <= threshold] # distance filter
        
        logger.debug(f"Distance filtering: {len(results)} -> {len(filtered)} results (threshold: {threshold:.3f})")
        return filtered
    

    def get_memory_stats(self) -> Dict[str, Any]:
        """Get comprehensive memory and performance statistics"""
        cache_stats = self.embedding_cache.get_stats()
        
        # System memory info
        memory = psutil.virtual_memory()
        
        return {
            "cache": cache_stats,
            "system_memory": {
                "available_mb": memory.available / (1024 * 1024),
                "percent_used": memory.percent
            },
            "config": {
                "distance_threshold": self.config.distance_threshold,
                "memory_limit_mb": self.config.memory_limit_mb,
                "adaptive_threshold_enabled": self.config.enable_adaptive_threshold
            }
        }
    

    def update_config(self, **kwargs):
        """Update search configuration at runtime"""
        for key, value in kwargs.items():
            if hasattr(self.config, key):
                setattr(self.config, key, value)
                logger.info(f"Updated search config: {key} = {value}")
            else:
                logger.warning(f"Unknown config parameter: {key}")
    
    
    def cleanup(self):
        """Clean up resources"""
        self.embedding_cache.clear()
        logger.debug("Search enhancement service cleaned up")


# Global search service instance
config = SearchConfig()
search_service = SearchService(config)