"""TTC Matcher using embeddings with hybrid local/Neptune support"""
import json
import numpy as np
from pathlib import Path
from typing import List, Dict, Any, Optional
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity
from ..utils.logger import ThreatForestLogger

AWS_TERMS = ['aws', 's3', 'ec2', 'iam', 'lambda', 'dynamodb', 'rds', 'ecs', 
             'cloudformation', 'cloudwatch', 'sns', 'sqs', 'kinesis', 'athena',
             'glue', 'emr', 'eks', 'fargate', 'bucket', 'instance', 'role',
             'cloudtrail', 'kms', 'secrets', 'parameter', 'api', 'gateway']

class TTCMatcher:
    """Match attack steps to TTC techniques using embeddings (local or Neptune)"""
    
    def __init__(self, 
                 mode: str = 'local',
                 embeddings_path: Optional[str] = None,
                 model_name: Optional[str] = None,
                 neptune_manager = None,
                 min_similarity: float = 0.35):
        """
        Initialize TTC matcher with hybrid local/Neptune support
        
        Args:
            mode: 'local' or 'neptune'
            embeddings_path: Path to pre-generated embeddings JSON (required for local mode)
            model_name: Sentence transformer model to use (defaults to config)
            neptune_manager: NeptuneGraphManager instance (required for neptune mode)
            min_similarity: Minimum similarity threshold (default 0.35)
        """
        if mode not in ['local', 'neptune']:
            raise ValueError(f"Invalid mode '{mode}'. Must be 'local' or 'neptune'")
        
        self.mode = mode
        self.min_similarity = min_similarity
        self.logger = ThreatForestLogger.get_logger(self.__class__.__name__)
        
        # Mode-specific initialization
        if self.mode == 'local':
            if model_name is None:
                from src.config import config
                model_name = config.embeddings_model
            self.model_name = model_name
            self.model = None
            self.embeddings_data = None
            
            if embeddings_path:
                self._load_embeddings(embeddings_path)
            
        elif self.mode == 'neptune':
            if neptune_manager is None:
                raise ValueError(
                    "Neptune mode requires neptune_manager parameter. "
                    "Initialize with: TTCMatcher(mode='neptune', neptune_manager=your_manager)"
                )
            self.neptune_manager = neptune_manager
            self.logger.info("🌊 Using Neptune graph for technique matching")
    
    def _load_embeddings(self, path: str):
        """Load pre-generated embeddings for local mode"""
        self.logger.info(f"📂 Loading embeddings from {path}")
        with open(path, 'r') as f:
            self.embeddings_data = json.load(f)
    
    def _load_model(self):
        """Lazy load the SentenceTransformer model for local mode"""
        if self.model is None:
            self.logger.info(f"🔧 Loading model: {self.model_name}")
            self.model = SentenceTransformer(self.model_name)
    
    def create_embeddings(self, stix_bundle_path: str, output_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Create embeddings from STIX bundle (local mode only)
        
        Args:
            stix_bundle_path: Path to STIX bundle JSON
            output_path: Optional path to save embeddings
            
        Returns:
            Embeddings data dictionary
        """
        if self.mode != 'local':
            raise RuntimeError("create_embeddings() only available in local mode")
        
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
        
        self.logger.info(f"🔄 Generating embeddings for {len(texts)} techniques...")
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
            self.logger.info(f"💾 Saved embeddings to {output_path}")
        
        return self.embeddings_data
    
    def match_steps(self, attack_steps: List[str], top_k: int = 3) -> List[Dict[str, Any]]:
        """
        Match attack steps to techniques (dispatches to local or Neptune)
        
        Args:
            attack_steps: List of attack step descriptions
            top_k: Number of top matches to return per step
            
        Returns:
            List of matches with confidence levels
        """
        if self.mode == 'local':
            return self._match_steps_local(attack_steps, top_k)
        else:  # neptune
            return self._match_steps_neptune(attack_steps, top_k)
    
    def _match_steps_local(self, attack_steps: List[str], top_k: int = 3) -> List[Dict[str, Any]]:
        """
        Match attack steps to techniques using local embeddings
        
        Args:
            attack_steps: List of attack step descriptions
            top_k: Number of top matches to return per step
            
        Returns:
            List of matches with confidence levels
        """
        if not self.embeddings_data:
            raise ValueError(
                "No embeddings loaded for local mode. "
                "Provide embeddings_path in __init__ or call create_embeddings()"
            )
        
        self.logger.info(f"🔍 [LOCAL] Matching {len(attack_steps)} attack steps to techniques...")
        self._load_model()
        
        technique_embs = np.array(self.embeddings_data['embeddings'])
        patterns = self.embeddings_data['patterns']
        
        step_embeddings = self.model.encode(attack_steps)
        base_similarities = cosine_similarity(step_embeddings, technique_embs)
        
        results = []
        matched_count = 0
        
        for i, step in enumerate(attack_steps):
            step_lower = step.lower()
            weighted_scores = []
            
            # Apply AWS term boosting
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
                matched_count += 1
                results.append({
                    'attack_step': step,
                    'matches': matches
                })
        
        self.logger.info(f"✓ [LOCAL] Matched {matched_count} of {len(attack_steps)} steps")
        return results
    
    def _match_steps_neptune(self, attack_steps: List[str], top_k: int = 3) -> List[Dict[str, Any]]:
        """
        Match attack steps to techniques using Neptune graph
        
        Args:
            attack_steps: List of attack step descriptions
            top_k: Number of top matches to return per step
            
        Returns:
            List of matches with confidence levels
        """
        self.logger.info(f"🌊 [NEPTUNE] Matching {len(attack_steps)} attack steps to techniques...")
        
        results = []
        matched_count = 0
        
        for step in attack_steps:
            try:
                # Generate embedding for the attack step using Neptune
                step_embedding = self.neptune_manager.embedding_ops.get_embedding(step)
                
                # Calculate boost factor for AWS terms
                step_lower = step.lower()
                aws_term_count = sum(1 for term in AWS_TERMS if term in step_lower)
                
                # Query Neptune for similar techniques
                # Note: topKByEmbedding may return distance or similarity depending on Neptune config
                neptune_query = f"""
                CALL neptune.algo.vectors.topKByEmbedding({step_embedding})
                YIELD node, score
                WHERE node:Technique
                RETURN node.stix_id as id, 
                       node.name as name, 
                       node.description as description,
                       node.external_ids as technique_id,
                       node.tactics as kill_chain_phases,
                       node.aws_services as aws_services,
                       score
                LIMIT {top_k * 2}
                """
                
                query_results = self.neptune_manager.query_ops.execute_query(neptune_query)
                
                matches = []
                for result in query_results[:top_k]:
                    # Extract data from Neptune result
                    raw_score = float(result.get('score', 0))
                    
                    # Normalize score to 0-1 range if it appears to be a distance metric
                    # Cosine similarity should be in [-1, 1], typically [0, 1] for similar vectors
                    # If score > 1.5, it's likely a distance metric that needs normalization
                    if raw_score > 1.5:
                        # Treat as Euclidean distance and convert to similarity
                        # Using inverse normalization: similarity = 1 / (1 + distance/100)
                        similarity = 1.0 / (1.0 + raw_score / 100.0)
                        self.logger.warning(
                            f"Normalized Neptune score from {raw_score:.2f} to {similarity:.4f} "
                            f"for step: {step[:50]}..."
                        )
                    else:
                        similarity = raw_score
                    
                    # Apply AWS term boosting if technique has AWS services
                    aws_services = result.get('aws_services', '')
                    if aws_services and aws_term_count > 0:
                        boost = 1.0 + (0.1 * aws_term_count)
                        similarity *= min(boost, 1.5)
                    
                    if similarity >= self.min_similarity:
                        matches.append({
                            'technique_id': result.get('technique_id', ''),
                            'name': result.get('name', ''),
                            'description': result.get('description', ''),
                            'kill_chain_phases': result.get('kill_chain_phases', '').split(',') if result.get('kill_chain_phases') else [],
                            'similarity': similarity,
                            'confidence': self._get_confidence_level(similarity)
                        })
                
                if matches:
                    matched_count += 1
                    results.append({
                        'attack_step': step,
                        'matches': matches
                    })
                    
            except Exception as e:
                self.logger.error(f"❌ Error matching step '{step[:50]}...': {e}")
                continue
        
        self.logger.info(f"✓ [NEPTUNE] Matched {matched_count} of {len(attack_steps)} steps")
        return results
    
    def _get_confidence_level(self, similarity: float) -> str:
        """Determine confidence level from similarity score"""
        if similarity > 0.7:
            return 'high'
        elif similarity > 0.5:
            return 'medium'
        else:
            return 'low'
