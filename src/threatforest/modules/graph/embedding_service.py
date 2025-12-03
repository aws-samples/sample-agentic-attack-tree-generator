"""Embedding service using SentenceTransformers"""
from typing import List, Optional
from sentence_transformers import SentenceTransformer
from ..utils.logger import ThreatForestLogger


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
