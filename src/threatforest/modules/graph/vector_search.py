"""Vector similarity search using cosine similarity"""
import numpy as np
from typing import List, Dict, Any
from sklearn.metrics.pairwise import cosine_similarity
from .types import MitreAttackGraph, TechniqueNode
from ..utils.logger import ThreatForestLogger


class VectorSearch:
    """In-memory vector similarity search for technique matching"""
    
    def __init__(self, graph: MitreAttackGraph):
        """
        Initialize vector search with a graph
        
        Args:
            graph: MitreAttackGraph containing techniques with embeddings
        """
        self.graph = graph
        self.logger = ThreatForestLogger.get_logger(self.__class__.__name__)
        
        # Pre-compute embedding matrix for efficient search
        self.embedding_matrix = np.array([t.embedding for t in graph.techniques])
        self.logger.info(f"Initialized vector search with {len(graph)} techniques")
    
    def search(
        self,
        query_embedding: List[float],
        top_k: int = 3,
        min_similarity: float = 0.3
    ) -> List[Dict[str, Any]]:
        """
        Find most similar techniques to a query embedding
        
        Args:
            query_embedding: Query vector
            top_k: Number of top results to return
            min_similarity: Minimum cosine similarity threshold (0-1)
            
        Returns:
            List of matches with similarity scores, sorted by similarity descending
        """
        if not query_embedding:
            return []
        
        # Convert to numpy array and reshape for sklearn
        query_vec = np.array(query_embedding).reshape(1, -1)
        
        # Compute cosine similarities
        similarities = cosine_similarity(query_vec, self.embedding_matrix)[0]
        
        # Get top-k indices (sorted descending by similarity)
        top_indices = np.argsort(similarities)[-top_k:][::-1]
        
        # Build results
        results = []
        for idx in top_indices:
            similarity = float(similarities[idx])
            
            # Filter by minimum similarity
            if similarity < min_similarity:
                continue
            
            technique = self.graph.techniques[idx]
            results.append({
                'technique': technique,
                'similarity': similarity,
                'confidence': self._get_confidence_level(similarity)
            })
        
        return results
    
    def search_batch(
        self,
        query_embeddings: List[List[float]],
        top_k: int = 3,
        min_similarity: float = 0.3
    ) -> List[List[Dict[str, Any]]]:
        """
        Find most similar techniques for multiple query embeddings
        
        Args:
            query_embeddings: List of query vectors
            top_k: Number of top results per query
            min_similarity: Minimum cosine similarity threshold
            
        Returns:
            List of result lists (one per query)
        """
        if not query_embeddings:
            return []
        
        # Convert to numpy array
        query_matrix = np.array(query_embeddings)
        
        # Compute all similarities at once
        similarities = cosine_similarity(query_matrix, self.embedding_matrix)
        
        # Process each query
        all_results = []
        for i, query_similarities in enumerate(similarities):
            # Get top-k indices for this query
            top_indices = np.argsort(query_similarities)[-top_k:][::-1]
            
            # Build results for this query
            results = []
            for idx in top_indices:
                similarity = float(query_similarities[idx])
                
                if similarity < min_similarity:
                    continue
                
                technique = self.graph.techniques[idx]
                results.append({
                    'technique': technique,
                    'similarity': similarity,
                    'confidence': self._get_confidence_level(similarity)
                })
            
            all_results.append(results)
        
        return all_results
    
    def _get_confidence_level(self, similarity: float) -> str:
        """
        Determine confidence level from similarity score
        
        Args:
            similarity: Cosine similarity (0-1)
            
        Returns:
            'high', 'medium', or 'low'
        """
        if similarity > 0.7:
            return 'high'
        elif similarity > 0.5:
            return 'medium'
        else:
            return 'low'
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get search engine statistics"""
        return {
            'num_techniques': len(self.graph.techniques),
            'embedding_dim': self.graph.embedding_dim,
            'model': self.graph.embedding_model
        }
