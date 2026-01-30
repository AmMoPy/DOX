import re
import time
import logging
import hashlib
import asyncio
import unicodedata
from sys import intern
from collections import Counter
from abc import ABC, abstractmethod
from typing import List, Dict, Tuple, Set, AsyncGenerator, Optional, Any, Union
from app.config.setting import settings
from app.utils.lsh import LSHFingerprint, LSHIndexer
from app.db.utils_db.async_bridge import async_bridge

logger = logging.getLogger(__name__)


# Abstract Interfaces
class BaseNormalizer(ABC):
    @abstractmethod
    def clean_text_structured(
        self, 
        text: str,
        level: int
        ) -> str:
        pass


class BaseHFdetector(ABC):
    @abstractmethod
    def detect_patterns(
        self, 
        pages: List[str]
        ) -> Tuple[Set[str], Set[str]]:
        pass

    @abstractmethod
    def remove_hf(
        self,
        page_text: str,
        header_patterns: Set[str],
        footer_patterns: Set[str]
        ) -> str:
        pass


class BaseDeduplicator(ABC):
    @abstractmethod
    def generate_fingerprint(
        self, 
        normalized: str, 
        mode: str = "doc"
        ) -> Optional[LSHFingerprint]:
        pass

    @abstractmethod
    def get_fingerprint_hash(
        self, 
        fingerprint: LSHFingerprint
        ) -> str: 
        pass

    @abstractmethod
    def is_duplicate(
        self, 
        fp1: LSHFingerprint,
        fp2: LSHFingerprint,
        mode: str = "doc"
        ) -> Tuple[bool, float, Dict]:
        pass


class BaseFuzzyMatcher(ABC):
    @abstractmethod
    async def find_best_match(
        self, 
        fp: LSHFingerprint,
        candidates: List[Dict],
        threshold: Optional[float] = None,
        mode: str = "doc"
        ) -> Optional[Dict]:
        pass


class BaseStringCache(ABC):
    @abstractmethod
    def get_or_intern(
        self, 
        text: str
        ) -> str:
        pass


class BaseChunker(ABC):
    @abstractmethod
    async def chunk_text_streaming(
        self, 
        text: str
        ) -> AsyncGenerator[str, None]:
        pass


# Concrete Implementations 
class TextNormalizer(BaseNormalizer):
    """
    Single-pass text normalization pipeline with multi level
    processing for validation/deduplication
    """
    
    def __init__(self):
        # Compile patterns once for performance
        self.whitespace_pattern = re.compile(r'\s+')
        self.special_chars_pattern = re.compile(r'[^\w\s\.\,\;\:\!\?\-\(\)\/\&\']')
        self.page_markers_pattern = re.compile(
            r'(?:page\s+\d+|^\d+$|^page\s*$)',
            re.IGNORECASE | re.MULTILINE
        )
        
        # Common header/footer patterns (domain-agnostic)
        # examples from test documents - adjust as needed
        self.header_footer_patterns = [
            # Matches: "Proprietary Document", "CONFIDENTIAL - DO NOT DISTRIBUTE"
            re.compile(r'^(?:proprietary|confidential|internal use only).*', re.IGNORECASE),
            # Matches: "Version 2.0", "  Copyright 2023", "Dated: Jan 1 2024"
            re.compile(r'^\s*(?:version|dated?|copyright|©).*', re.IGNORECASE),
             # Matches: "Page 1", "page 2 of 10", "  PAGE   5  "
            re.compile(r'^\s*page\s+\d+(?:\s+of\s+\d+)?\s*$', re.IGNORECASE),
            # Matches: "1", "  23  ", "005"
            re.compile(r'^\s*\d+\s*$'),  # Standalone page numbers
            # Exact department name
            # Matches: "Risk Management" but NOT "Risk Management Department"
            re.compile(r'^Risk Management$', re.IGNORECASE),
            # Company acronym at end of line
            # Matches: "NRFSI", "Document NRFSI", "Approved by NRFSI   "
            re.compile(r'NRFSI\s*$', re.IGNORECASE),
            # Policy title pattern
            # Matches: "POLICY GUIDELINES ON RISK MEASURES"
            re.compile(r'^POLICY GUIDELINES ON.*MEASURES$', re.IGNORECASE),
            # Company name anywhere in line
            # Matches: "Nissan Renault Financial Services", "Approved by Nissan Renault Financial"
            re.compile(r'Nissan Renault Financial', re.IGNORECASE),
            # Subsidiary name anywhere in line  
            # Matches: "Nissan Renault Financial Services India Pt Ltd"
            re.compile(r'Services India Pt Ltd', re.IGNORECASE),  
        ]
        
        # Structural noise for deduplication
        self.structural_noise = [
            re.compile(r'^\d+[\.\)]\s*'),  # List numbering: "1. " or "1) "
            re.compile(r'^[a-z][\.\)]\s*', re.IGNORECASE),  # Letter lists: "a. "
            re.compile(r'^[ivxlcdm]+[\.\)]\s*', re.IGNORECASE),  # Roman numerals
            re.compile(r'^\s*[-•*]\s*'),  # Bullet points
        ]
    

    def clean_text_structured(
        self, 
        text: str, 
        level: int
    ) -> str:
        """
        Unified normalization with single pass through text
        
        Args:
            text: Raw text input
            level: Aggressiveness of normalization [1,2,3]
        
        Returns:
            Normalized text appropriate for use case
        """
        if not text:
            return ""
        
        lines = text.split('\n')
        processed_lines = []
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # Level 1: Always remove page markers
            if self.page_markers_pattern.search(line):
                continue
            
            # Level 2+: Remove headers/footers
            if level >= 2:
                if any(pattern.match(line) for pattern in self.header_footer_patterns):
                    continue
            
            # Level 3: Remove structural formatting
            if level == 3:
                for pattern in self.structural_noise:
                    line = pattern.sub('', line)
                
                # Aggressive character removal
                line = self.special_chars_pattern.sub(' ', line)
                line = self.whitespace_pattern.sub(' ', line)
                line = line.lower()
                
                # Unicode normalization (handles accents, ligatures)
                line = unicodedata.normalize('NFKD', line)
                line = line.encode('ascii', 'ignore').decode('ascii')
            
            else:
                # Moderate cleaning
                line = self.special_chars_pattern.sub(' ', line)
                line = self.whitespace_pattern.sub(' ', line)
            
            line = line.strip()
            if len(line) > 2:  # Skip very short lines
                processed_lines.append(line)
        
        # Rebuild text
        if level == 3:
            return ' '.join(processed_lines)  # Flatten for comparison
        else:
            return '\n'.join(processed_lines)  # Preserve structure


class HeaderFooterDetector(BaseHFdetector):
    """
    Adaptive header/footer detection using statistical analysis
    Works for structured PDF documents
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):

        # Adjust based on document structure
        default_config = {              
            'sample_size': 5,           # Pages to analyze
            'min_repetition': 0.6,      # % of pages must have pattern
            'skip_patterns': 5,         # Skip very short patterns
            'max_header_lines': 10,     # Max lines to serach for header patterns 
            'max_footer_lines': 10,     # Max lines to serach for footer patterns
        }

        self.config = {**default_config, **(config or {})}


    def _find_repeated_patterns(self, candidates: List[List[str]]) -> Set[str]:

        """Identify lines that appear consistently across pages"""
        if not candidates:
            return set()
        
        # Count occurrences of each line (normalized)
        line_counts = Counter()
        total_pages = len(candidates)
        
        for lines in candidates:
            for line in lines:
                # Normalize for comparison
                normalized = re.sub(r'\d+', 'N', line)  # Replace numbers with N
                normalized = re.sub(r'\s+', ' ', normalized).strip().lower()
                line_counts[normalized] += 1
        
        # Keep patterns that appear in majority of pages
        threshold = total_pages * self.config['min_repetition']
        repeated_patterns = {
            pattern for pattern, count in line_counts.items()
            if count >= threshold and len(pattern) > self.config['skip_patterns']
        }
        
        return repeated_patterns
    

    def detect_patterns(self, pages: List[str]) -> Tuple[Set[str], Set[str]]:
        """
        Analyze multiple pages to identify repeated header/footer patterns
        
        Returns:
            (header_patterns, footer_patterns)
        """
        if len(pages) < 2:
            return set(), set()
        
        # Sample pages for analysis
        sample_pages = pages[:min(self.config['sample_size'], len(pages))]
        
        # Extract first/last N lines from each page
        headers_candidate = []
        footers_candidate = []
        
        for page in sample_pages:
            lines = [l.strip() for l in page.split('\n') if l.strip()]
            if len(lines) >= 3:
                headers_candidate.append(lines[:self.config['max_header_lines']])   # First 10 lines
                footers_candidate.append(lines[-self.config['max_footer_lines']:])  # Last 10 lines
        
        # Find patterns that repeat across pages
        header_patterns = self._find_repeated_patterns(headers_candidate)
        footer_patterns = self._find_repeated_patterns(footers_candidate)
        
        return header_patterns, footer_patterns
        

    def remove_hf(
        self,
        page_text: str,
        header_patterns: Set[str],
        footer_patterns: Set[str]
    ) -> str:
        """Remove detected headers/footers from page"""
        lines = [l.strip() for l in page_text.split('\n') if l.strip()]
        cleaned_lines = []
        
        for line in lines:
            # Normalize for comparison
            normalized = re.sub(r'\d+', 'N', line)
            normalized = re.sub(r'\s+', ' ', normalized).strip().lower()
            
            # Skip if matches header/footer pattern
            if normalized in header_patterns or normalized in footer_patterns:
                continue
            
            cleaned_lines.append(line)
        
        return '\n'.join(cleaned_lines)


class ContentDeduplicator(BaseDeduplicator):
    """
    Unified semantic similarity detector for both documents 
    and queries handles formatting differences while detecting 
    duplicates with LSH for efficient database candidate retrieval
    """
    
    def __init__(self, lsh_indexer: LSHIndexer, config: Optional[Dict[str, Any]] = None):
        """
        Args:
            lsh_indexer: Indexer class not an instance
            config: deduplicator and Indexer configurations
        """
        
        # Configuration
        default_config = {
            # Document fingerprinting
            'doc_min_word_length': 3,                  
            'top_n_words': 150,
            'doc_similarity_threshold': 0.85,
            'doc_min_words': 50,
            'doc_shingle_size': 3,                 # 3-word shingles (good balance)
            
            # Query fingerprinting
            'query_min_word_length': 2,            # Shorter words acceptable for queries
            'query_use_all_words': True,           # Don't limit to top N
            'query_similarity_threshold': 0.90,    # Stricter matching
            'query_min_words': 3,                  # Minimum query length
            'query_adaptive_shingles': True,       # Adjust shingle size based on length
            
            # Similarity weights
            'doc_JAC_W': 0.7,
            'doc_FREQ_W': 0.2,
            'doc_STRUCT_W': 0.1,
            'query_JAC_W': 0.75,
            'query_FREQ_W': 0.15,
            'query_STRUCT_W': 0.05,
            'query_LEN_W': 0.05,
            
            # LSH parameters
            'num_hashes': 128,
            'num_bands': 16, # 32
            'rows_per_band': 8, # 4
        }

        self.config = {**default_config, **(config or {})}

        # typically this should be class instance (DI) not class itself (composition) 
        # and passed as Type[LSHIndexer] in the signature, just a reminder that Python
        # allows it because it doesn't enforce types during runtime and the fact that class is 
        # an instance of its metaclass (usually type), so technically the class LSHIndexer  
        # is an instance of type, which makes the type hint LSHIndexer somewhat ambiguous 
        # but functionally acceptable
        self.lsh_indexer = lsh_indexer( # internal initialization with runtime configs
            num_hashes=self.config['num_hashes'],
            num_bands=self.config['num_bands'],
            rows_per_band=self.config['rows_per_band']
        )
    

    def generate_fingerprint(self, normalized: str, mode: str = "doc") -> Optional[LSHFingerprint]:
        """
        Unified fingerprinting with mode selection
        
        Args:
            normalized: Pre-normalized text
            mode: "doc" or "query"
        
        Returns:
            LSHFingerprint or None if text too short
        """

        if mode == "doc":
            return self._generate_document_fingerprint(normalized)
        else:
            return self._generate_query_fingerprint(normalized)


    def _generate_document_fingerprint(self, normalized: str) -> Optional[LSHFingerprint]:
        """Query-specific fingerprinting for long-form content (50+ words)"""
        if not normalized:
            return None
                
        words = [w for w in normalized.split() 
                if len(w) >= self.config['doc_min_word_length']]
        
        # word count
        n_words = len(words)

        if n_words < self.config['doc_min_words']: # Too short for reliable comparison
            return None
        
        # 1. Word frequency-weighted signature
        word_freq = Counter(words)
        top_words = word_freq.most_common(self.config['top_n_words'])
        
        signature_parts = [] # Format: word1^freq1|word2^freq2|...
        for word, freq in sorted(top_words, key=lambda x: (-x[1], x[0])): # Sort by freq DESC, then alpha
            # Normalize frequency to reduce sensitivity
            norm_freq = min(freq, 10)  # Cap at 10 to reduce outlier impact
            signature_parts.append(f"{word}^{norm_freq}")
        
        word_signature = '|'.join(signature_parts)
        
        # 2. LSH signatures for indexing
        # Convert text into overlapping word sequences (shingles)
        # of shingle_size words, example:
        # 'what is customer acceptance policy' ->
        # {'what customer', 'acceptance policy', 'customer acceptance'}   
        word_shingles = self._generate_word_shingles(
            words,
            n_words,
            shingle_size=self.config['doc_shingle_size'],
        )

        # Convert shingles into a fixed-size signature that preserves similarity
        # Similar texts -> Similar shingles -> Similar signatures
        lsh_signatures = self.lsh_indexer.generate_lsh_signatures(word_shingles)
        
        # 3. Structural features
        structural = {
            'word_count': n_words,
            'unique_words': len(set(words)),
            'avg_word_length': sum(len(w) for w in words) / n_words
        }
        
        # 4. Store small sample for verification
        txt = normalized[:500] # First 500 chars
        
        return LSHFingerprint(
            # content_hash=content_hash,
            word_signature=word_signature,
            lsh_signatures=lsh_signatures,
            structural_features=structural,
            txt=txt
        )
    

    def _generate_query_fingerprint(self, normalized: str) -> Optional[LSHFingerprint]:
        """
        Query-specific fingerprinting for short text (5-50 words)
        
        Key differences from document fingerprinting:
        - Lower minimum word length (2 vs 3)
        - Use ALL words (not just top 150)
        - Adaptive shingle size based on query length
        - More aggressive normalization tolerance
        """
        if not normalized:
            return None
        
        # Use lower word length threshold for queries
        words = [w for w in normalized.split() 
                if len(w) >= self.config['query_min_word_length']]
        
        # word count
        n_words = len(words)

        if n_words < self.config['query_min_words']:
            return None

        # 1. Word frequency signature - USE ALL WORDS for queries
        word_freq = Counter(words)
        
        if self.config['query_use_all_words']:
            # For queries, every word matters
            top_words = word_freq.most_common()  # All words, sorted by frequency
        else:
            # Fallback to limited words
            top_words = word_freq.most_common(self.config['top_n_words'])
        
        signature_parts = []
        for word, freq in sorted(top_words, key=lambda x: (-x[1], x[0])):
            # For short queries, don't cap frequency as aggressively
            norm_freq = min(freq, 5)  # Lower cap for queries
            signature_parts.append(f"{word}^{norm_freq}")
        
        word_signature = '|'.join(signature_parts)
        
        # 2. Adaptive shingle size for short text
        query_cat = self._categorize_query_length(n_words)

        # Dynamic shingle size based on query length
        if self.config['query_adaptive_shingles']:
            shingle_size = query_cat["shingle_size"]
        else:
            shingle_size = 3
        
        word_shingles = self._generate_word_shingles(
            words,
            n_words,
            shingle_size=shingle_size
        )
        
        lsh_signatures = self.lsh_indexer.generate_lsh_signatures(word_shingles)
        
        # 3. Structural features
        structural = {
            'word_count': n_words,
            'unique_words': len(set(words)),
            'avg_word_length': sum(len(w) for w in words) / n_words,
            'query_length_category': query_cat["category"]
        }
        
        # 4. Store full query for verification (queries are short)
        txt = normalized  # Store entire query
        
        return LSHFingerprint(
            # content_hash=content_hash,
            word_signature=word_signature,
            lsh_signatures=lsh_signatures,
            structural_features=structural,
            txt=txt
        )
    

    def _generate_word_shingles(
        self, 
        words: List[str],
        n_words: int,
        shingle_size: int
        ) -> Set[str]:
        """
        Generate word-level shingles for LSH
        More robust than character n-grams for LSH
        """

        if n_words < shingle_size:
            # If text too short for requested shingle size, use what we have
            shingle_size = max(1, n_words)
        
        shingles = set()
        
        for i in range(n_words - shingle_size + 1):
            shingle = ' '.join(words[i:i + shingle_size])
            shingles.add(shingle)
        
        return shingles

    def _categorize_query_length(self, word_count: int) -> str:
        """Categorize query by length for better comparison"""

        # Short (5-10 words): bigrams (2-word shingles)
        # Medium (11-20 words): trigrams (3-word shingles)
        # Long (21+ words): 3-4 word shingles
        if word_count <= 10:
            return {
                "category": "short",
                "shingle_size": 2
                }
        elif word_count <= 20:
            return {
                "category": "medium",
                "shingle_size": 3
                }
        else:
            return {
                "category": "long",
                "shingle_size": min(4, word_count // 5)
                }
    

    def is_duplicate(
        self,
        fp1: LSHFingerprint,
        fp2: LSHFingerprint,
        mode: str = "doc",
        threshold: Optional[float] = None
    ) -> Tuple[bool, float, Dict]:
        """
        Check duplication with full similarity
        
        Args:
            fp1: First fingerprint
            fp2: Second fingerprint
            threshold: Custom threshold (optional)
            mode: "doc" or "query" (affects weight distribution)
        """
        if mode not in ["doc","query"]:
            raise ValueError("'mode' parameter must be one of the following arguments: 'doc' or 'query' "
                             f"however, '{mode}' was received!")

        if mode == "doc":
            threshold = threshold or self.config['doc_similarity_threshold']
        else:
            threshold = threshold or self.config['query_similarity_threshold']
        
        similarity, breakdown = self._calculate_full_similarity(fp1, fp2, mode)
             
        return similarity >= threshold, similarity, breakdown


    def _calculate_full_similarity(
        self,
        fp1: LSHFingerprint,
        fp2: LSHFingerprint,
        mode: str
    ) -> Tuple[float, Dict[str, float]]:
        """
        Full similarity computation (should be only called on limited N candidates)
        """
        if not fp1 or not fp2:
            return 0.0, {}
        
        # score map
        breakdown = {}
        
        # 1. Word signature similarity (handles reordering better)
        words1 = {p.split('^')[0]: int(p.split('^')[1]) 
                  for p in fp1.word_signature.split('|') if '^' in p}
        words2 = {p.split('^')[0]: int(p.split('^')[1]) 
                  for p in fp2.word_signature.split('|') if '^' in p}
        
        common_words = set(words1.keys()) & set(words2.keys())
        all_words = set(words1.keys()) | set(words2.keys())
        
        if all_words:
            jaccard = len(common_words) / len(all_words)
            breakdown['word_jaccard'] = jaccard
            
            if common_words:
                freq_sim = sum(
                    min(words1[w], words2[w]) for w in common_words
                ) / sum(max(words1.get(w, 0), words2.get(w, 0)) for w in all_words)
                breakdown['frequency'] = freq_sim
            else:
                breakdown['frequency'] = 0.0
        else:
            breakdown['word_jaccard'] = 0.0
            breakdown['frequency'] = 0.0
        
        # 2. Structural similarity
        s1 = fp1.structural_features
        s2 = fp2.structural_features
        word_ratio = min(s1['word_count'], s2['word_count']) / max(s1['word_count'], s2['word_count'])
        breakdown['structural'] = word_ratio
        
        # 3. Query-specific: Check length category match
        if mode != "doc":
            # Penalize if queries are in very different length categories
            if s1['query_length_category'] == s2['query_length_category']:
                breakdown['length_match'] = 1.0
            else:
                breakdown['length_match'] = 0.7

        # Weighted combination
        if mode == "doc":
            overall = (
                breakdown['word_jaccard'] * self.config['doc_JAC_W'] +   # Primary: robust to reordering
                breakdown['frequency'] * self.config['doc_FREQ_W'] +     # Secondary: captures frequency
                breakdown['structural'] * self.config['doc_STRUCT_W']    # Tertiary: sanity check
            )
        else:
            # For queries, word content matters more than structure
            overall = (
                breakdown['word_jaccard'] * self.config['query_JAC_W'] +   # Higher weight on word overlap
                breakdown['frequency'] * self.config['query_FREQ_W'] +     # Moderate weight on frequency
                breakdown['structural'] * self.config['query_STRUCT_W'] +  # Lower weight on structure
                breakdown['length_match'] * self.config['query_LEN_W']     # Minor length category bonus
            )
        
        return overall, breakdown


    def get_fingerprint_hash(self, fingerprint: LSHFingerprint) -> str: 
        """
        Primary exact-match (deterministic) hash for database lookup
        Uses word signature for similarity tolerance
        """
        return hashlib.sha256(fingerprint.word_signature.encode()).hexdigest()
    

    def get_lsh_bucket_ids(self, fingerprint: LSHFingerprint) -> List[str]:
        """Get LSH bucket IDs for indexing"""
        return fingerprint.lsh_signatures


class FuzzyMatcher(BaseFuzzyMatcher):
    """
    Unified service for fuzzy similarity matching
    Supports both document deduplication and query cache matching
    """
    
    def __init__(self, deduplicator: BaseDeduplicator):
        # LSH-based deduplicator
        self.deduplicator = deduplicator
                
        # Performance tracking (separated by type)
        self._query_match_count = 0
        self._query_total_similarity = 0.0
        self._query_total_time = 0.0
        
        self._doc_match_count = 0
        self._doc_total_similarity = 0.0
        self._doc_total_time = 0.0
    

    async def find_best_match(
        self,
        fp: LSHFingerprint,
        candidates: List[Dict],
        threshold: float,
        mode: str = "doc"
    ) -> Optional[Dict]:
        """
        Find best matching candidate using full similarity computation
        
        This is CPU-intensive and runs in thread pool via async_bridge
        
        Args:
            fp: Fingerprint of incoming query/document
            candidates: List of candidate entries from database
            threshold: Custom similarity threshold
            mode: "query" or "doc"
        
        Returns:
            Best matching candidate or None
        """
        if not candidates:
            return None
        
        try:
            # Run CPU-intensive work in thread pool
            return await async_bridge.run_in_io_thread(
                self._find_best_match_sync,
                fp,
                candidates,
                threshold,
                mode
            )
        except Exception as e:
            logger.error(f"Fuzzy match computation failed: {e}")
            return None
    

    def _find_best_match_sync(
        self,
        fp: LSHFingerprint,
        candidates: List[Dict],
        threshold: float,
        mode: str
    ) -> Optional[Dict]:
        """
        Synchronous best match finder (runs in thread pool)
        
        This method does the actual CPU-intensive similarity computation
        """
        start_time = time.time()
           
        best_match = None
        best_score = 0.0
        
        logger.debug(f"Starting {mode} similarity check on {len(candidates)} candidates")
        
        for candidate in candidates:
            # Reconstruct fingerprint from candidate data
            candidate_fp = self._reconstruct_fingerprint(candidate['fingerprint_data'])
            
            if not candidate_fp:
                logger.warning(
                    f"Could not reconstruct fingerprint for candidate "
                    f"{candidate.get('cache_key', candidate.get('document_id', 'unknown'))[:8]}..." # cache_key for query, document_id for doc
                )
                continue
            
            # CPU-intensive similarity computation
            is_similar, score, breakdown = self.deduplicator.is_duplicate(
                fp,
                candidate_fp,
                threshold=threshold,
                mode=mode
            )
            
            logger.debug(
                f"Candidate {candidate.get('cache_key', candidate.get('filename', 'unknown'))[:8]}... "
                f"score: {score:.2%}, breakdown: {breakdown}"
            )
            
            if is_similar and score > best_score:
                best_score = score
                best_match = {
                    **candidate,
                    'similarity_score': score,
                    'similarity_breakdown': breakdown
                }
                
                # Early exit at first match for docs
                if mode == "doc":
                    logger.debug(f"Early exit: match found (score: {score:.2%})")
                    break

                # Early exit at best score for query
                if score >= settings.cache.QUERY_BEST_MATCH_THRESHOLD:
                    logger.debug(f"Early exit: excellent match (score: {score:.2%})")
                    break
        
        elapsed_time = (time.time() - start_time) * 1000
        
        if best_match:
            self._track_performance(elapsed_time, best_score, mode)
            
            logger.info(
                f"Best {mode} match found: "
                f"'{best_match.get('txt', best_match.get('filename', ''))[:50]}...' " # txt for query, filename for doc
                f"(similarity: {best_score:.2%}, time: {elapsed_time:.1f}ms)"
            )
        else:
            logger.debug(f"No suitable {mode} match found above threshold {threshold:.2%}")
        
        return best_match
    

    def _reconstruct_fingerprint(
        self, 
        fingerprint_data: Optional[Union[Dict, LSHFingerprint]] = None
    ) -> Optional[LSHFingerprint]:
        """
        Reconstruct LSHFingerprint from stored data
        
        Handles both Dict (from JSON) and LSHFingerprint objects
        
        Args:
            fingerprint_data: Dictionary, LSHFingerprint, or None
        
        Returns:
            LSHFingerprint or None
        """
        if not fingerprint_data:
            return None
        
        # If already a fingerprint object, return as-is
        if isinstance(fingerprint_data, LSHFingerprint):
            return fingerprint_data
        
        # Otherwise, reconstruct from dict
        try:
            return LSHFingerprint(
                word_signature=fingerprint_data['word_signature'],
                lsh_signatures=[],  # Not needed for comparison
                structural_features=fingerprint_data['structural_features'],
                txt=fingerprint_data['txt']
            )

        except Exception as e:
            logger.error(f"Failed to reconstruct fingerprint: {e}")
            return None
    

    def _track_performance(
        self, 
        elapsed_time_ms: float, 
        similarity_score: float,
        mode: str
    ):
        """Track fuzzy matching performance metrics by mode"""
        if mode == "doc":
            self._doc_match_count += 1
            self._doc_total_similarity += similarity_score
            self._doc_total_time += elapsed_time_ms
        else: # query              
            self._query_match_count += 1
            self._query_total_similarity += similarity_score
            self._query_total_time += elapsed_time_ms
    

    def get_stats(self, mode: Optional[str] = None) -> Dict:
        """
        Get fuzzy matching statistics
        
        Args:
            mode: "query", "document", or None (returns both)
        
        Returns:
            Statistics dictionary
        """
        if mode == "query":
            avg_similarity = self._query_total_similarity / max(self._query_match_count, 1)
            avg_time = self._query_total_time / max(self._query_match_count, 1)
            
            return {
                "type": "query",
                "total_matches": self._query_match_count,
                "avg_similarity_score": round(avg_similarity, 4),
                "avg_computation_time_ms": round(avg_time, 2)
            }
        elif mode == "doc":
            avg_similarity = self._doc_total_similarity / max(self._doc_match_count, 1)
            avg_time = self._doc_total_time / max(self._doc_match_count, 1)
            
            return {
                "type": "document",
                "total_matches": self._doc_match_count,
                "avg_similarity_score": round(avg_similarity, 4),
                "avg_computation_time_ms": round(avg_time, 2)
            }
        else:
            # Return combined stats
            return {
                "query_matching": self.get_stats("query"),
                "document_deduplication": self.get_stats("document"),
                "total_operations": self._query_match_count + self._doc_match_count
            }


class StringCache(BaseStringCache):
    """
    Cache for string interning to reduce memory for repeated content
    sys.intern() has its own internal cache, but it's optimized for 
    Python identifiers, this cache layer let us control size, 
    track hit rates and prevents intern's cache from growing unbounded
    """
    
    def __init__(self, max_size: int = 1000):
        self.cache = {}
        self.max_size = max_size
        self.hits = 0
        self.misses = 0
    

    def get_or_intern(self, text: str) -> str:
        """
        Return interned string if repeated, otherwise cache and return
        Only caches strings < 500 chars (headers, common phrases)
        """
        # Only cache small strings
        if len(text) > 500:
            return text # Don't cache large strings
        
        # Create hash for lookup
        text_hash = hash(text)
        
        # Check if we've seen this before
        if text_hash in self.cache:
            self.hits += 1
            return self.cache[text_hash] # Return cached version
        
        # New string - intern and cache
        self.misses += 1
        
        # Evict oldest if cache full (simple FIFO)
        if len(self.cache) >= self.max_size:
            # Remove first item
            self.cache.pop(next(iter(self.cache)))
        
        # Use sys.intern for string interning
        interned = intern(text)
        self.cache[text_hash] = interned
        
        return interned
    

    def get_stats(self) -> dict:
        """Get cache statistics"""
        total = self.hits + self.misses
        hit_rate = (self.hits / total * 100) if total > 0 else 0
        
        return {
            'hits': self.hits,
            'misses': self.misses,
            'hit_rate': hit_rate,
            'size': len(self.cache)
        }


# there are multiple versions for chunking implementation, to experiment with.
# the ContextAwareChunker variations are targeting complex docs while basic 
# chunker is, well, for basic docs! I've also introduced template uploads to 
# handover chunking to users. In general, for a low-end RAG with low-quality 
# embeddings, chunk size matters more (less is better)
class ContextAwareChunker(BaseChunker):
    """
    Chunker that detects section continuity across page boundaries

    Scalability Limitations:
        - Pattern matching is regex-based, may miss unconventional formatting
        - Assumes Western document structure (numbered sections, bullet points)
        - May struggle with tables, complex layouts, or non-English documents
        - Hard-coded patterns might not cover all domain-specific formats
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        config: Dict with chunking parameters:
            - skip_size: Minimum chunk skipping size (default: 50 chars)
            - min_chunk_size: Minimum chunk size (default: 200 chars)
            - target_chunk_size: Target chunk size (default: 600 chars)
            - max_chunk_size: Maximum chunk size (default: 1000 chars)
        """

        # Adjust based on document structure
        default_config = {              
            'skip_size': 50,            # Skip very small texts
            'min_chunk_size': 200,      # Allow meaningful small chunks
            'target_chunk_size': 600,   # Optimal for topic-focused search (more chunks)
            'max_chunk_size': 1000,     # Prevent topic mixing
            'max_header_len':50,        # Major headers pre-compile simple checks
            'max_numbered_len':200,     # Numbered items pre-compile simple checks
            'max_subsection_len':100,   # Subsection pre-compile simple checks

        }
        self.config = {**default_config, **(config or {})}

        # Pre-compile regex patterns for optimized checks
        self._patterns = {
            'major_section': re.compile(r'^\d+\.\s*[A-Z\s]+$'),
            'numbered_item': re.compile(r'^\d+\.'),
            'subsection': re.compile(r'^[A-Za-z\s]+:$'),
        }
    

    def _detect_section_continuation(self, text_lines: List[str]) -> List[Dict]:
        """
        Detect where sections continue across boundaries, optimized with early
        exits
        """
        sections = []
        current_section = None
        
        for line in text_lines:
            line = line.strip()
            if not line:
                continue
            
            # Quick length checks before regex
            # only apply regex checks when meaningfull
            line_len = len(line)
            
            # Major headers are typically short
            if line_len < self.config['max_header_len']:  # Quick check
                if self._patterns['major_section'].match(line):
                    # Save previous section
                    if current_section:
                        sections.append(current_section)
                    
                    current_section = {
                        'header': line,
                        'content': [],
                        'type': 'major_section'
                    }
                    continue
            
            # Numbered items are short
            if line_len < self.config['max_numbered_len'] and current_section:
                if self._patterns['numbered_item'].match(line):
                    current_section['content'].append(line)
                    continue
            
            # Subsection markers are short
            if line_len < self.config['max_subsection_len'] and current_section:
                if self._patterns['subsection'].match(line):
                    current_section['content'].append(line)
                    continue
            
            # Regular content - no regex needed
            if current_section:
                current_section['content'].append(line)
            else:
                current_section = {
                    'header': '',
                    'content': [line],
                    'type': 'content'
                }
        
        if current_section:
            sections.append(current_section)
        
        return sections
    

    def _merge_related_sections(self, sections: List[Dict]) -> List[Dict]:
        """
        Merge sections that should be together (like continuation of numbered lists)
        """
        if len(sections) <= 1:
            return sections  # Early exit

        merged = []
        i = 0
        
        while i < len(sections):
            current = sections[i]
            
            # Look ahead for related sections
            if i + 1 < len(sections) and current['type'] != 'major_section': # Only check next section if current is mergeable
                next_section = sections[i + 1]
                
                # Check if next section continues current one
                if self._should_merge_sections(current, next_section): 
                    # Merge sections
                    merged_section = {
                        'header': current['header'],
                        'content': current['content'] + next_section['content'],
                        'type': current['type']
                    }
                    merged.append(merged_section)
                    i += 2  # Skip next section as it's merged
                    continue
            
            merged.append(current)
            i += 1
        
        return merged
    

    def _should_merge_sections(self, section1: Dict, section2: Dict) -> bool:
        """
        Determine if two sections should be merged
        """
        # Don't merge if first section has major header and second also has major header
        if section1['type'] == 'major_section' and section2['type'] == 'major_section':
            return False
        
        # Merge if second section looks like continuation (starts with number)
        if section2['content']:
            # Quick check: starts with digit
            return section2['content'][0][0].isdigit()   
        
        return False
    

    async def chunk_text_streaming(self, text: str) -> AsyncGenerator[str, None]:
        """
        Chunk text while preserving section continuity
        """
        if not text or len(text.strip()) < self.config['skip_size']:
            return
        
        # Split into lines while preserving structure
        lines = [line.strip() for line in text.split('\n') if line.strip()]
        
        # Detect sections and their continuity
        sections = self._detect_section_continuation(lines)
        
        # Merge related sections (this solves your cross-page problem)
        sections = self._merge_related_sections(sections)
        
        # Create chunks from merged sections
        for section in sections:
            if not section['content']:
                continue
            
            # Construct full section text
            section_text = ""
            if section['header']:
                section_text = section['header'] + "\n\n"
            
            section_text += "\n".join(section['content'])
            
            # Check if section fits in one chunk
            if len(section_text) <= self.config['target_chunk_size']:
                if len(section_text) >= self.config['min_chunk_size']:
                    yield section_text
                    await asyncio.sleep(0)
            
            elif len(section_text) <= self.config['max_chunk_size']:
                yield section_text
                await asyncio.sleep(0)
            
            else:
                # Large section - split carefully
                async for chunk in self._split_large_section(section['header'], section['content']):
                    yield chunk
                    await asyncio.sleep(0)
    

    async def _split_large_section(self, header: str, content: List[str]) -> AsyncGenerator[str, None]:
        """
        Split large sections while maintaining context
        """
        current_chunk = header + "\n\n" if header else ""
        
        for line in content:
            test_size = len(current_chunk) + len(line) + 1
            
            if test_size <= self.config['max_chunk_size']:
                current_chunk += line + "\n"
            else:
                if len(current_chunk.strip()) >= self.config['min_chunk_size']:
                    yield current_chunk.strip()
                    await asyncio.sleep(0)
                
                # Start new chunk with header context
                header_context = f"{header} (continued)\n\n" if header else ""
                current_chunk = header_context + line + "\n"
        
        if len(current_chunk.strip()) >= self.config['min_chunk_size']:
            yield current_chunk.strip()


# class ContextAwareChunker(BaseChunker):
#     """
#     Specialized chunker for structured policy/compliance documents
    
#     Key principles:
#     1. Never split a numbered section
#     2. Keep section headers with their content
#     3. Respect semantic boundaries (sections, subsections)
#     4. No artificial "continued" markers
#     """
    
#     def __init__(self, config: Optional[Dict[str, Any]] = None):
#         default_config = {
#             'min_chunk_size': 100,       # Very small chunks OK if semantically complete
#             'target_chunk_size': 800,    # Target size for sections
#             'max_chunk_size': 2000,      # Hard limit (will split large sections)
#             'preserve_tables': True,     # Keep tables intact
#             'merge_short_sections': True # Combine tiny adjacent sections
#         }
        
#         self.config = {**default_config, **(config or {})}
        
#         # Pre-compiled patterns for section detection
#         self._patterns = {
#             # Main sections: "4. CUSTOMER ACCEPTANCE POLICY"
#             'main_section': re.compile(r'^(\d+)\.\s+([A-Z\s]+)$'),
            
#             # Subsections: "4.1 Risk Assessment"
#             'subsection': re.compile(r'^(\d+\.\d+)\s+(.+)$'),
            
#             # Deep subsections: "4.1.2 PEP Screening"
#             'deep_subsection': re.compile(r'^(\d+\.\d+\.\d+)\s+(.+)$'),
            
#             # Numbered lists: "1. Customer must be..."
#             'numbered_list': re.compile(r'^\d+\.\s+.+'),
            
#             # Lettered lists: "a. Risk categorization..."
#             'lettered_list': re.compile(r'^[a-z]\.\s+.+', re.IGNORECASE),
            
#             # Bullet points
#             'bullet': re.compile(r'^\s*[•\-\*]\s+.+'),
            
#             # Key-value pairs: "Version 4.0"
#             'metadata_line': re.compile(r'^[A-Z][a-z\s]+:\s*.+'),
#         }
    
#     async def chunk_text_streaming(self, text: str) -> AsyncGenerator[str, None]:
#         """
#         Chunk text respecting semantic boundaries
#         """
#         if not text or len(text.strip()) < 50:
#             return
        
#         # Parse document into sections
#         sections = self._parse_into_sections(text)
        
#         # Process each section
#         for section in sections:
#             # Skip empty sections
#             if not section['content'].strip():
#                 continue
            
#             section_size = len(section['content'])
            
#             # Small section - yield as-is
#             if section_size <= self.config['target_chunk_size']:
#                 if section_size >= self.config['min_chunk_size']:
#                     yield section['content']
#                     await asyncio.sleep(0)
            
#             # Medium section - yield as-is (acceptable)
#             elif section_size <= self.config['max_chunk_size']:
#                 yield section['content']
#                 await asyncio.sleep(0)
            
#             # Large section - split intelligently
#             else:
#                 async for chunk in self._split_large_section(section):
#                     yield chunk
#                     await asyncio.sleep(0)
    
#     def _parse_into_sections(self, text: str) -> List[Dict[str, Any]]:
#         """
#         Parse document into semantic sections
        
#         Returns:
#             List of sections with metadata:
#             [
#                 {
#                     'type': 'main_section',
#                     'number': '4',
#                     'title': 'CUSTOMER ACCEPTANCE POLICY',
#                     'content': '4. CUSTOMER ACCEPTANCE POLICY\n\n...',
#                     'level': 1
#                 },
#                 ...
#             ]
#         """
#         lines = text.split('\n')
#         sections = []
#         current_section = None
        
#         i = 0
#         while i < len(lines):
#             line = lines[i].strip()
            
#             # Skip empty lines
#             if not line:
#                 i += 1
#                 continue
            
#             # Check if this is a section header
#             section_info = self._detect_section_header(line)
            
#             if section_info:
#                 # Save previous section
#                 if current_section:
#                     sections.append(current_section)
                
#                 # Start new section
#                 current_section = {
#                     'type': section_info['type'],
#                     'number': section_info['number'],
#                     'title': section_info['title'],
#                     'level': section_info['level'],
#                     'content': line + '\n'
#                 }
#             else:
#                 # Add to current section
#                 if current_section:
#                     current_section['content'] += line + '\n'
#                 else:
#                     # Content before first section (metadata, etc.)
#                     current_section = {
#                         'type': 'preamble',
#                         'number': None,
#                         'title': 'Document Metadata',
#                         'level': 0,
#                         'content': line + '\n'
#                     }
            
#             i += 1
        
#         # Add final section
#         if current_section:
#             sections.append(current_section)
        
#         # Optionally merge short adjacent sections
#         if self.config['merge_short_sections']:
#             sections = self._merge_short_sections(sections)
        
#         return sections
    
#     def _detect_section_header(self, line: str) -> Optional[Dict[str, Any]]:
#         """
#         Detect if line is a section header
#         """
#         # Try patterns in order of specificity
        
#         # Deep subsection (most specific)
#         match = self._patterns['deep_subsection'].match(line)
#         if match:
#             return {
#                 'type': 'deep_subsection',
#                 'number': match.group(1),
#                 'title': match.group(2).strip(),
#                 'level': 3
#             }
        
#         # Subsection
#         match = self._patterns['subsection'].match(line)
#         if match:
#             return {
#                 'type': 'subsection',
#                 'number': match.group(1),
#                 'title': match.group(2).strip(),
#                 'level': 2
#             }
        
#         # Main section
#         match = self._patterns['main_section'].match(line)
#         if match:
#             return {
#                 'type': 'main_section',
#                 'number': match.group(1),
#                 'title': match.group(2).strip(),
#                 'level': 1
#             }
        
#         return None
    
#     def _merge_short_sections(
#         self, 
#         sections: List[Dict[str, Any]]
#     ) -> List[Dict[str, Any]]:
#         """
#         Merge adjacent short sections to reduce fragmentation
#         Only merges sections at same hierarchy level
#         """
#         if len(sections) <= 1:
#             return sections
        
#         merged = []
#         i = 0
        
#         while i < len(sections):
#             current = sections[i]
            
#             # Check if current section is short
#             if len(current['content']) < self.config['min_chunk_size']:
#                 # Look ahead for mergeable section
#                 if (i + 1 < len(sections) and 
#                     sections[i + 1]['level'] == current['level'] and
#                     len(current['content']) + len(sections[i + 1]['content']) <= self.config['target_chunk_size']):
                    
#                     # Merge with next section
#                     next_section = sections[i + 1]
#                     merged_section = {
#                         'type': current['type'],
#                         'number': f"{current['number']}-{next_section['number']}",
#                         'title': f"{current['title']} / {next_section['title']}",
#                         'level': current['level'],
#                         'content': current['content'] + '\n' + next_section['content']
#                     }
#                     merged.append(merged_section)
#                     i += 2
#                     continue
            
#             # No merge - add as-is
#             merged.append(current)
#             i += 1
        
#         return merged
    
#     async def _split_large_section(
#         self, 
#         section: Dict[str, Any]
#     ) -> AsyncGenerator[str, None]:
#         """
#         Split large sections intelligently
#         Tries to split at natural boundaries (paragraphs, lists)
#         """
#         content = section['content']
        
#         # Try splitting at paragraph breaks first
#         paragraphs = [p.strip() for p in content.split('\n\n') if p.strip()]
        
#         current_chunk = ""
        
#         for para in paragraphs:
#             test_size = len(current_chunk) + len(para) + 2
            
#             if test_size <= self.config['max_chunk_size']:
#                 current_chunk += para + '\n\n'
#             else:
#                 # Yield current chunk
#                 if current_chunk.strip():
#                     yield current_chunk.strip()
                
#                 # Start new chunk
#                 current_chunk = para + '\n\n'
        
#         # Yield final chunk
#         if current_chunk.strip():
#             yield current_chunk.strip()


class BasicChunker(BaseChunker):
    """
    Basic Chunker for preprocessed documents ready for DB writes
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        config: Dict with chunking parameters:
            - skip_size: Minimum chunk skipping size (default: 50 chars)
            - target_chunk_size: Target chunk size (default: 300 chars)
            - sentence_split: splitting preference sentence vs paragraph (default: False)
            - overlap: context overlap preference keep vs ignore (default: False)
        """

        # Adjust based on document structure
        default_config = {
            'skip_size': 50,             # Skip very small texts
            'target_chunk_size': 300,    # Maximum chunk size (chars) best 300-600 - higher results in larger chunks and wider results
            'sentence_split': False,     # Prefer splitting at sentence boundaries
            'overlap': False             # Optional overlap for context continuity, Trade-offs: larger chunks and content duplication
        }
        
        self.config = {**default_config, **(config or {})}
        
    
    async def chunk_text_streaming(self, text: str) -> AsyncGenerator[str, None]:
        """Memory-efficient text chunking with configurable splitting"""
        if not text or len(text.strip()) < self.config['skip_size']:
            return
        
        # Choose splitting strategy based on config
        if self.config['sentence_split']:
            # Regex for continuous text without paragraph breaks
            splits = re.split(r'(?<=[.!?])\s+(?=[A-Z])', text)  
            separator = ' '
        else:
            # Use paragraph splitting
            # Better for documents with clear structure
            splits = [p for p in text.split('\n\n') if p.strip()]
            separator = '\n\n'
        
        current_chunk = []
        current_length = 0
        
        for split in splits:
            split = split.strip()
            if not split:
                continue
            
            split_length = len(split)
            
            # Check if adding this split would exceed target size
            if (current_chunk and 
                current_length + split_length > self.config['target_chunk_size']):
                
                # Yield current chunk
                chunk_text = separator.join(current_chunk)
                yield chunk_text

                # Optional overlap
                if self.config['overlap']:
                    if self.config['sentence_split']:
                        # Sentence splitting: keep last 1-2 sentences for overlap
                        overlap_sentences = min(2, len(current_chunk)) # Keep [Sent E, Sent F] from [Sent C, Sent D, Sent E, Sent F]
                        if overlap_sentences > 0:
                            current_chunk = current_chunk[-overlap_sentences:]
                            current_length = sum(len(s) for s in current_chunk) + (len(current_chunk) - 1) * len(separator)
                        else:
                            current_chunk = []
                            current_length = 0
                    else:
                        # Paragraph splitting: keep only the last paragraph for overlap
                        if current_chunk:
                            current_chunk = [current_chunk[-1]]  # Keep [Para C] from [Para A, Para B, Para C]
                            current_length = len(current_chunk[0])
                        else:
                            current_chunk = []
                            current_length = 0
                else:
                    # No overlap - start fresh
                    current_chunk = []
                    current_length = 0
            
            current_chunk.append(split)
            current_length += split_length + len(separator)
            
            # Yield control periodically
            if len(current_chunk) % 10 == 0:
                await asyncio.sleep(0)
        
        # Yield final chunk
        if current_chunk:
            chunk_text = separator.join(current_chunk)
            yield chunk_text
