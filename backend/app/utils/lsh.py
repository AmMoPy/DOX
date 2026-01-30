import mmh3  # MurmurHash3 for fast hashing
import struct
import hashlib
from dataclasses import dataclass
from typing import List, Dict, Set


@dataclass
class LSHFingerprint:
    """Fingerprint with LSH signatures for efficient similarity search"""
    word_signature: str         # Frequency-weighted (existing)
    lsh_signatures: List[str]   # Multiple hash buckets for similarity
    structural_features: Dict   # Document characteristics
    txt: str                    # Small sample for final verification


class LSHIndexer:
    """
    Locality-Sensitive Hashing for approximate nearest neighbor search
    Uses MinHash + banding technique
    """
    
    def __init__(
        self, 
        num_hashes: int = 128,      # Number of hash functions
        num_bands: int = 16,        # Trade-off: more bands = higher recall, lower precision
        rows_per_band: int = 8      # num_hashes must equal num_bands * rows_per_band
    ):
        """
        Initialize LSH indexer
        
        num_hashes: Total MinHash signatures (more = better accuracy, slower)
        num_bands: Number of hash buckets (more = more candidates)
        rows_per_band: Hashes per band (fewer = more permissive matching)
        
        Rule of thumb: For 80% similarity threshold, use 16 bands × 8 rows
        """
        assert num_hashes == num_bands * rows_per_band, "num_hashes must equal num_bands * rows_per_band"
        
        self.num_hashes = num_hashes
        self.num_bands = num_bands
        self.rows_per_band = rows_per_band
        
        # Pre-generate hash seeds for reproducibility
        self.hash_seeds = [i * 97 + 31 for i in range(num_hashes)]
    

    def _minhash_signature(self, shingles: Set[str]) -> List[int]:
        """
        Generate MinHash signature from shingles
        
        MinHash property: Pr[h(A) = h(B)] = Jaccard(A, B)
        This means similar sets will have similar signatures
        """
        if not shingles:
            return [0] * self.num_hashes
        
        signature = []
        for seed in self.hash_seeds:
            # Find minimum hash value across all shingles
            min_hash = min(
                mmh3.hash(shingle, seed=seed, signed=False) 
                for shingle in shingles
            )
            signature.append(min_hash)
        
        return signature
    

    def generate_lsh_signatures(self, shingles: Set[str]) -> List[str]:
        """
        Generate LSH band signatures for database indexing
        
        Returns list of signature strings, one per band
        Each signature represents a "bucket" - similar documents hash to same bucket
        """
        # Generate MinHash signature
        minhash_sig = self._minhash_signature(shingles)
        
        # Split into bands and hash each band
        lsh_sigs = []
        for band_idx in range(self.num_bands):
            start = band_idx * self.rows_per_band
            end = start + self.rows_per_band
            band = minhash_sig[start:end]
            
            # Hash the band to create bucket ID
            # Pack integers into bytes for hashing
            band_bytes = struct.pack(f'{self.rows_per_band}I', *band)
            band_hash = hashlib.sha256(band_bytes).hexdigest()[:16]  # 16 chars sufficient
            
            lsh_sigs.append(band_hash)
        
        return lsh_sigs
    
    
    def estimate_similarity_from_bands(self, sigs1: List[str], sigs2: List[str]) -> float:
        """
        Quick similarity estimate from LSH signatures
        Not precise, but useful for candidate filtering
        """
        if not sigs1 or not sigs2:
            return 0.0
        
        # Count matching bands
        matches = sum(1 for s1, s2 in zip(sigs1, sigs2) if s1 == s2)
        
        # Estimate Jaccard similarity from band matches
        # This is approximate - full verification still needed
        return matches / self.num_bands