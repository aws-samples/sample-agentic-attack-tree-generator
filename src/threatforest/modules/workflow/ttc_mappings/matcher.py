"""TTC Matcher using local graph-based embeddings"""
import numpy as np
from typing import List, Dict, Any, Optional
from ...utils.logger import ThreatForestLogger
from ...graph import GraphBuilder, EmbeddingService, VectorSearch

AWS_TERMS = ['aws', 's3', 'ec2', 'iam', 'lambda', 'dynamodb', 'rds', 'ecs', 
             'cloudformation', 'cloudwatch', 'sns', 'sqs', 'kinesis', 'athena',
             'glue', 'emr', 'eks', 'fargate', 'bucket', 'instance', 'role',
             'cloudtrail', 'kms', 'secrets', 'parameter', 'api', 'gateway']

class TTCMatcher:
    """Match attack steps to MITRE ATT&CK techniques using local graph"""
    
    def __init__(self, min_similarity: float = 0.3):
        """
        Initialize TTC matcher with local graph
        
        Args:
            min_similarity: Minimum similarity threshold (default 0.3, lowered from 0.35)
        """
        self.min_similarity = min_similarity
        self.logger = ThreatForestLogger.get_logger(self.__class__.__name__)
        
        # Lazy initialization - will be set on first use
        self.graph = None
        self.embedding_service = None
        self.vector_search = None
        
        self.logger.info(f"TTCMatcher initialized (min_similarity={min_similarity})")
    
    def _ensure_initialized(self):
        """Lazy load graph and services on first use"""
        if self.graph is not None:
            return
        
        from threatforest.config import config
        
        self.logger.info("Initializing graph on first use...")
        
        # Get or build graph (will use cached version if available)
        self.graph = GraphBuilder.get_or_build(
            graph_path=str(config.graph_file_path),
            stix_bundle_path=str(config.stix_bundle_path),
            embedding_model=config.embeddings_model,
            force_rebuild=False,
            show_progress=False  # Silent during TTC mapping to avoid console overlap
        )
        
        # Initialize embedding service (reuses same model)
        self.embedding_service = EmbeddingService(config.embeddings_model)
        
        # Initialize vector search
        self.vector_search = VectorSearch(self.graph)
        
        self.logger.info(f"✓ Graph initialized with {len(self.graph)} techniques")
    
    def match_steps(self, attack_steps: List[str], top_k: int = 3) -> List[Dict[str, Any]]:
        """
        Match attack steps to MITRE ATT&CK techniques
        
        Args:
            attack_steps: List of attack step descriptions
            top_k: Number of top matches to return per step
            
        Returns:
            List of matches with confidence levels
        """
        self._ensure_initialized()
        
        self.logger.info(f"🔍 Matching {len(attack_steps)} attack steps to techniques...")
        
        results = []
        matched_count = 0
        
        for step in attack_steps:
            # Generate embedding for attack step
            step_embedding = self.embedding_service.get_embedding(step)
            
            if not step_embedding:
                self.logger.warning(f"Failed to generate embedding for step: {step[:50]}...")
                continue
            
            # Search for similar techniques
            search_results = self.vector_search.search(
                query_embedding=step_embedding,
                top_k=top_k,
                min_similarity=self.min_similarity
            )
            
            # Apply AWS term boosting
            step_lower = step.lower()
            aws_terms_in_step = [term for term in AWS_TERMS if term in step_lower]
            
            matches = []
            for result in search_results:
                technique = result['technique']
                similarity = result['similarity']
                
                # Apply boost if AWS terms match
                if aws_terms_in_step:
                    tech_text = f"{technique.name} {technique.description}".lower()
                    matching_terms = [term for term in aws_terms_in_step if term in tech_text]
                    
                    if matching_terms:
                        boost = 1.0 + (0.1 * len(matching_terms))
                        similarity *= min(boost, 1.5)
                        # Re-filter after boosting
                        if similarity < self.min_similarity:
                            continue
                
                matches.append({
                    'technique_id': technique.primary_technique_id,
                    'name': technique.name,
                    'description': technique.description,
                    'kill_chain_phases': technique.tactics,
                    'similarity': float(similarity),
                    'confidence': self._get_confidence_level(similarity)
                })
            
            if matches:
                matched_count += 1
                results.append({
                    'attack_step': step,
                    'matches': matches
                })
        
        self.logger.info(f"✓ Matched {matched_count} of {len(attack_steps)} steps")
        return results
    
    def _get_confidence_level(self, similarity: float) -> str:
        """Determine confidence level from similarity score"""
        if similarity > 0.7:
            return 'high'
        elif similarity > 0.5:
            return 'medium'
        else:
            return 'low'
