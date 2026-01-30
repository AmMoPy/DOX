import os
import logging
import threading
import gc
from typing import List
from pathlib import Path
from app.config.setting import settings
from sentence_transformers import SentenceTransformer

logger = logging.getLogger(__name__)


class EmbeddingClient:
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        # singleton pattern
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(EmbeddingClient, cls).__new__(cls)
                cls._instance.model = None
                cls._instance._initialized = False
                cls._instance._warmup_completed = False
        return cls._instance
    
    def initialize(self):
        """Initialize the embedding model with offline support and optional warm-up"""
        with self._lock:
            if self.model is None and not self._initialized:
                try:
                    logger.debug("Loading embedding model...")
                    
                    # Set offline mode
                    os.environ["TRANSFORMERS_OFFLINE"] = "1"
                    os.environ["HF_HUB_OFFLINE"] = "1"
                    
                    # Model loading configuration
                    model_kwargs = {
                        'device': 'cpu',
                        'cache_folder': str(settings.paths.MODEL_DIR / 'cache'),
                        'local_files_only': True,  # Force offline mode
                    }
                    
                    # Check if model files exist
                    cache_dir = Path(settings.paths.MODEL_DIR / 'cache')
                    if not cache_dir.exists() or not list(cache_dir.glob("**/*")):
                        logger.warning("No model files found in cache. Please run setup.py first")
                        raise Exception("Model files not found. Run setup to download models.")
                    
                    self.model = SentenceTransformer(
                        settings.models.EMBEDDING_MODEL,
                        **model_kwargs
                    )
                    
                    # Validate model is working
                    self._validate_model()
                    
                    # Conditional warm-up based on settings
                    if settings.server.ENABLE_MODEL_WARMUP:
                        self._warm_up()
                    else:
                        logger.debug("Model warm-up skipped (disabled in settings)")
                    
                    self._initialized = True
                    logger.debug("Embedding model loaded successfully!")
                    
                except Exception as e:
                    logger.error(f"Failed to load embedding model: {e}")
                    raise
    

    def _validate_model(self):
        """Validate that the model is working properly with minimal test"""
        try:
            # Minimal validation - just check if model can load and produce output
            test_text = "model validation"
            embedding = self.model.encode(test_text, show_progress_bar=False)
            
            if len(embedding) != 384:  # MUST match model dimension, current model is all-MiniLM-L6-v2 
                raise Exception(f"Model validation failed - expected 384 dimensions, got {len(embedding)}")
            
            logger.debug("Model validation passed")
        except Exception as e:
            logger.error(f"Model validation failed: {e}")
            raise
    

    def _warm_up(self):
        """Warm up the model with minimal samples"""
        try:
            # Minimal warm-up with 2 samples
            sample_texts = ["warmup sample one", "warmup sample two"]
            
            logger.debug("Starting model warm-up...")
            
            # Use minimal settings for warm-up
            self.model.encode(
                sample_texts, 
                batch_size=2, 
                show_progress_bar=False,
                convert_to_numpy=True
            )
            
            self._warmup_completed = True
            logger.debug("Model warm-up completed successfully")
            
        except Exception as e:
            # Don't crash initialization if warm-up fails
            logger.warning(f"Model warm-up failed (non-critical): {e}")
            self._warmup_completed = False
        

    def is_warmed_up(self) -> bool:
        """Check if model warm-up has been completed"""
        return self._warmup_completed
    

    def get_embedding(self, text: str) -> List[float]:
        """Get single embedding with memory optimization and validation"""
        if not text or not isinstance(text, str) or not text.strip():
            raise ValueError("Invalid text for embedding")
        
        if self.model is None:
            if not self._initialized:
                self.initialize()
            else:
                # Return zero vector as fallback
                # Zero vectors have identical cosine similarity to everything
                # TODO: better fallback strategy
                logger.warning(f"Using zero vector embeddings")
                return [0.0] * 384
        
        try:
            # Truncate very long texts to prevent memory issues
            truncated_text = text[:settings.processing.MAX_TEXT_LENGTH]

            logger.debug(f"Embedding text (first 100 chars): {truncated_text[:100]}")
            
            with self._lock: # sync blocking code in async context (caller) but ok as this function is called for for a single search/chat query
                # Generate embedding with memory-efficient settings
                embedding = self.model.encode(
                    truncated_text,
                    show_progress_bar=True,
                    convert_to_numpy=True,
                    normalize_embeddings=True,
                    device='cpu'
                )
            
            # Explicit cleanup of intermediate variables
            del truncated_text
            
            # You cannot simply return a PyTorch tensor and expect it  
            # to be inserted into a standard database column without serialization.
            # tolist() works for current vector database selection (chroma/postgres)
            # except that PostgreSQL needs explicit serialization via pgvector to
            # match the binary format that PostgreSQL VECTOR extension expects.
            return embedding.tolist()
            
        except Exception as e:
            logger.error(f"Using zero vector embeddings as single embedding generation failed: {e}")
            # Return zero vector as fallback
            return [0.0] * 384
    

    def get_embeddings(self, texts: List[str], batch_size: int = 16) -> List[List[float]]:
        """Get embeddings in batches with aggressive memory optimization"""
        if self.model is None:
            if not self._initialized:
                self.initialize()
            else:
                # Fallback mode - return zero vectors
                return self._get_fallback_embeddings(texts)
        
        if not texts:
            return []
        
        # Validate and clean input texts
        validated_texts = []
        for text in texts:
            if text and isinstance(text, str) and text.strip():
                # Truncate very long texts to prevent memory issues
                truncated_text = text[:settings.processing.MAX_TEXT_LENGTH]
                validated_texts.append(truncated_text)
        
        if not validated_texts:
            return []
        
        try:
            # SentenceTransformer's internal state is not thread-safe for concurrent encode()
            # which can results in: interleaved batch processing, crashes (CUDA/PyTorch) or wrong embeddings returned (silent failures)
            # using lock guarantees that:
            # 1. only one thread within that Python process can execute the model.encode line at a time
            # 2. the lock is automatically acquired/released before the model is used and after the operation completes (even if an exception is raised)
            # TODO: true parallelism for multiple simultaneous uploads instead of current concurrency prevention lock (requests are queued untill lock is released)
            with self._lock: 
                # Process in smaller batches to reduce memory usage
                all_embeddings = []
                effective_batch_size = min(batch_size, 8)  # Reduced batch size for memory
                
                for i in range(0, len(validated_texts), effective_batch_size):
                    batch_texts = validated_texts[i:i + effective_batch_size]
                    
                    # Generate embeddings for this batch
                    batch_embeddings = self.model.encode(
                        batch_texts,
                        batch_size=effective_batch_size,
                        show_progress_bar=False,
                        convert_to_numpy=True,
                        normalize_embeddings=True,
                        device='cpu'
                    )
                    
                    # Convert to list and add to results
                    all_embeddings.extend(batch_embeddings.tolist())
                    
                    # Explicit cleanup of batch data
                    del batch_texts
                    del batch_embeddings
                    
                    # Force garbage collection after each batch for large files
                    if len(validated_texts) > 50:
                        gc.collect()
            
            # Final cleanup
            del validated_texts
            
            return all_embeddings
            
        except Exception as e:
            logger.error(f"Batch embedding generation failed: {e}")
            # Return fallback embeddings
            return self._get_fallback_embeddings(texts)
    

    def _get_fallback_embeddings(self, texts: List[str]) -> List[List[float]]:
        """Return zero vectors as fallback when model is unavailable"""
        if not texts:
            return []
        
        dimension = 384  # all-MiniLM-L6-v2 dimension
        logger.warning(f"Using zero vector embeddings for {len(texts)} texts")
        return [[0.0] * dimension for _ in texts]
    

    def cleanup(self):
        """Clean up model resources"""
        with self._lock:
            if self.model is not None:
                try:
                    # Clear model from memory
                    del self.model
                    self.model = None
                    self._initialized = False
                    self._warmup_completed = False
                    
                    # Force garbage collection
                    gc.collect()
                    
                    # Clear CUDA cache if available
                    try:
                        import torch
                        if hasattr(torch, 'cuda') and torch.cuda.is_available():
                            torch.cuda.empty_cache()
                    except ImportError:
                        pass
                    
                    logger.debug("Embedding model cleaned up")
                except Exception as e:
                    logger.error(f"Error during model cleanup: {e}")


# Global instance with cleanup handler
embedding_client = EmbeddingClient()