"""TTC Matcher using embeddings with domain weighting"""
import json
import numpy as np
from pathlib import Path
from typing import List, Dict, Any, Optional
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity

AWS_TERMS = ['aws', 's3', 'ec2', 'iam', 'lambda', 'dynamodb', 'rds', 'ecs', 
             'cloudformation', 'cloudwatch', 'sns', 'sqs', 'kinesis', 'athena',
             'glue', 'emr', 'eks', 'fargate', 'bucket', 'instance', 'role',
             'cloudtrail', 'kms', 'secrets', 'parameter', 'api', 'gateway']

class TTCMatcher:
    """Match attack steps to TTC techniques using embeddings"""
    
    def __init__(self, 
                 embeddings_path: Optional[str] = None,
                 model_name: Optional[str] = None,
                 min_similarity: float = 0.35):
        """
        Initialize TTC matcher
        
        Args:
            embeddings_path: Path to pre-generated embeddings JSON
            model_name: Sentence transformer model to use (defaults to config)
            min_similarity: Minimum similarity threshold (default 0.35)
        """
        if model_name is None:
            from ...config import config
            model_name = config.embeddings_model
        self.model_name = model_name
        self.min_similarity = min_similarity
        self.model = None
        self.embeddings_data = None
        
        if embeddings_path:
            self._load_embeddings(embeddings_path)
    
    def _load_embeddings(self, path: str):
        """Load pre-generated embeddings"""
        with open(path, 'r') as f:
            self.embeddings_data = json.load(f)
    
    def _load_model(self):
        """Lazy load the model"""
        if self.model is None:
            self.model = SentenceTransformer(self.model_name)
    
    def create_embeddings(self, stix_bundle_path: str, output_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Create embeddings from STIX bundle
        
        Args:
            stix_bundle_path: Path to STIX bundle JSON
            output_path: Optional path to save embeddings
            
        Returns:
            Embeddings data dictionary
        """
        self._load_model()
        
        with open(stix_bundle_path, 'r') as f:
            bundle = json.load(f)
        
        patterns = []
        texts = []
        
        for obj in bundle.get('objects', []):
            if obj.get('type') == 'attack-pattern':
                text = f"{obj['name']}: {obj.get('description', '')}"
                texts.append(text)
                
                patterns.append({
                    'id': obj['id'],
                    'name': obj['name'],
                    'description': obj.get('description', ''),
                    'technique_id': obj.get('aliases', [None])[0],
                    'kill_chain_phases': obj.get('kill_chain_phases', [])
                })
        
        embeddings = self.model.encode(texts, show_progress_bar=True)
        
        self.embeddings_data = {
            'patterns': patterns,
            'embeddings': embeddings.tolist(),
            'model': self.model_name,
            'embedding_dim': embeddings.shape[1]
        }
        
        if output_path:
            with open(output_path, 'w') as f:
                json.dump(self.embeddings_data, f, indent=2)
        
        return self.embeddings_data
    
    def match_steps(self, attack_steps: List[str], top_k: int = 3) -> List[Dict[str, Any]]:
        """
        Match attack steps to techniques with domain weighting
        
        Args:
            attack_steps: List of attack step descriptions
            top_k: Number of top matches to return per step
            
        Returns:
            List of matches with confidence levels
        """
        if not self.embeddings_data:
            raise ValueError("No embeddings loaded. Call create_embeddings() or load from file.")
        
        self._load_model()
        
        technique_embs = np.array(self.embeddings_data['embeddings'])
        patterns = self.embeddings_data['patterns']
        
        step_embeddings = self.model.encode(attack_steps)
        base_similarities = cosine_similarity(step_embeddings, technique_embs)
        
        results = []
        for i, step in enumerate(attack_steps):
            step_lower = step.lower()
            weighted_scores = []
            
            for j, pattern in enumerate(patterns):
                tech_text = f"{pattern['name']} {pattern['description']}".lower()
                boost = 1.0
                
                for term in AWS_TERMS:
                    if term in step_lower and term in tech_text:
                        boost += 0.1
                
                weighted_scores.append(base_similarities[i][j] * min(boost, 1.5))
            
            top_indices = np.argsort(weighted_scores)[-top_k:][::-1]
            
            matches = []
            for idx in top_indices:
                similarity = weighted_scores[idx]
                if similarity >= self.min_similarity:
                    matches.append({
                        'technique_id': patterns[idx].get('technique_id'),
                        'name': patterns[idx]['name'],
                        'description': patterns[idx]['description'],
                        'kill_chain_phases': patterns[idx].get('kill_chain_phases', []),
                        'similarity': float(similarity),
                        'confidence': self._get_confidence_level(similarity)
                    })
            
            if matches:
                results.append({
                    'attack_step': step,
                    'matches': matches
                })
        
        return results
    
    def _get_confidence_level(self, similarity: float) -> str:
        """Determine confidence level from similarity score"""
        if similarity > 0.7:
            return 'high'
        elif similarity > 0.5:
            return 'medium'
        else:
            return 'low'
