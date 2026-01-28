"""Embedding service using SentenceTransformers"""
import contextlib
import io
import logging
import os
import sys
import warnings
from typing import List, Optional

# Fallback: Ensure HF Hub telemetry is disabled to prevent background thread timeouts.
# Primary fix is in cli.py; this serves as defense-in-depth for direct module imports.
os.environ.setdefault("HF_HUB_DISABLE_TELEMETRY", "1")
os.environ.setdefault("HF_HUB_DISABLE_IMPLICIT_TOKEN", "1")

from sentence_transformers import SentenceTransformer
from ..utils.logger import ThreatForestLogger


@contextlib.contextmanager
def _suppress_model_loading_output():
    """
    Context manager to suppress noisy output during model loading.

    Suppresses:
    - "Loading weights" progress bars from tqdm/mlx
    - "UNEXPECTED" key warnings from safetensors/mlx model loading
    - Various HuggingFace informational messages

    These messages are informational but create visual noise during CLI operation.
    """
    # Suppress tqdm progress bars
    old_tqdm_disable = os.environ.get("TQDM_DISABLE")
    os.environ["TQDM_DISABLE"] = "1"

    # Suppress transformers/mlx logging
    loggers_to_quiet = [
        "transformers",
        "sentence_transformers",
        "mlx",
        "safetensors",
    ]
    old_levels = {}
    for logger_name in loggers_to_quiet:
        logger = logging.getLogger(logger_name)
        old_levels[logger_name] = logger.level
        logger.setLevel(logging.ERROR)

    # Capture stderr to suppress "UNEXPECTED" warnings and progress bars
    old_stderr = sys.stderr
    sys.stderr = io.StringIO()

    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            yield
    finally:
        # Restore stderr
        sys.stderr = old_stderr

        # Restore logger levels
        for logger_name, level in old_levels.items():
            logging.getLogger(logger_name).setLevel(level)

        # Restore tqdm setting
        if old_tqdm_disable is None:
            os.environ.pop("TQDM_DISABLE", None)
        else:
            os.environ["TQDM_DISABLE"] = old_tqdm_disable


class EmbeddingService:
    """Service for generating embeddings using SentenceTransformers"""

    def __init__(self, model_name: str):
        """
        Initialize embedding service with a specific model

        Args:
            model_name: SentenceTransformer model name (e.g., "basel/ATTACK-BERT")
        """
        self.model_name = model_name
        self.model: Optional[SentenceTransformer] = None
        self.logger = ThreatForestLogger.get_logger(self.__class__.__name__)

    def _load_model(self):
        """Lazy load the model (only loads once)"""
        if self.model is None:
            self.logger.info(f"Loading embedding model: {self.model_name}")
            try:
                with _suppress_model_loading_output():
                    self.model = SentenceTransformer(self.model_name, trust_remote_code=True)
                self.logger.info(f"✓ Model loaded successfully")
            except Exception as e:
                self.logger.error(f"Failed to load model {self.model_name}: {e}")
                raise
    
    def get_embedding(self, text: str) -> List[float]:
        """
        Generate embedding for a single text
        
        Args:
            text: Input text to embed
            
        Returns:
            List of floats representing the embedding vector
        """
        if not text:
            return []
        
        self._load_model()
        
        try:
            embedding = self.model.encode(text, convert_to_numpy=True)
            return embedding.tolist()
        except Exception as e:
            self.logger.error(f"Error generating embedding: {e}")
            return []
    
    def get_batch_embeddings(self, texts: List[str], show_progress: bool = True) -> List[List[float]]:
        """
        Generate embeddings for multiple texts (more efficient than one-by-one)
        
        Args:
            texts: List of texts to embed
            show_progress: Whether to show progress bar
            
        Returns:
            List of embedding vectors
        """
        if not texts:
            return []
        
        self._load_model()
        
        try:
            self.logger.info(f"Generating embeddings for {len(texts)} texts...")
            embeddings = self.model.encode(
                texts, 
                convert_to_numpy=True,
                show_progress_bar=show_progress
            )
            return [emb.tolist() for emb in embeddings]
        except Exception as e:
            self.logger.error(f"Error generating batch embeddings: {e}")
            return [[] for _ in texts]
    
    @property
    def embedding_dim(self) -> int:
        """Get the embedding dimension"""
        self._load_model()
        return self.model.get_sentence_embedding_dimension()
