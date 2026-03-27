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
    """Match attack steps to threat framework techniques using local graphs.

    Supports multiple frameworks (e.g. ATT&CK + ATLAS) simultaneously.
    Results from all enabled frameworks are merged and ranked by similarity.
    """

    def __init__(self, min_similarity: float = 0.3, frameworks: Optional[List[str]] = None):
        """
        Initialize TTC matcher with local graph(s).

        Args:
            min_similarity: Minimum similarity threshold (default 0.3)
            frameworks: List of framework keys to use (e.g. ["attack", "atlas"]).
                        None means use all frameworks defined in config.
        """
        self.min_similarity = min_similarity
        self.requested_frameworks = frameworks
        self.logger = ThreatForestLogger.get_logger(self.__class__.__name__)

        # Lazy initialization — populated per-framework on first use
        self._graphs: Dict[str, Any] = {}
        self._searches: Dict[str, VectorSearch] = {}
        self._embedding_service: Optional[EmbeddingService] = None
        self._initialized = False

        self.logger.info(f"TTCMatcher initialized (min_similarity={min_similarity}, frameworks={frameworks})")

    def _ensure_initialized(self):
        """Lazy load graph(s) and services on first use."""
        if self._initialized:
            return

        from threatforest.config import config

        all_frameworks = config.frameworks
        fw_keys = self.requested_frameworks or list(all_frameworks.keys())

        self.logger.info(f"Initializing graphs for frameworks: {fw_keys}")

        # Shared embedding service (same model for all frameworks)
        self._embedding_service = EmbeddingService(config.embeddings_model)

        for key in fw_keys:
            fw = all_frameworks.get(key)
            if not fw:
                self.logger.warning(f"Unknown framework '{key}', skipping")
                continue

            graph = GraphBuilder.get_or_build(
                graph_path=str(config.graph_file_path_for(key)),
                stix_bundle_path=str(config.stix_bundle_path_for(key)),
                embedding_model=config.embeddings_model,
                force_rebuild=False,
                show_progress=False,
                source_name=fw.get("source_name", "mitre-attack"),
                kill_chain_name=fw.get("kill_chain_name", "mitre-attack"),
            )
            self._graphs[key] = graph
            self._searches[key] = VectorSearch(graph)
            self.logger.info(f"  {key}: {len(graph)} techniques loaded")

        self._initialized = True
        total = sum(len(g) for g in self._graphs.values())
        self.logger.info(f"Graphs initialized: {total} techniques across {len(self._graphs)} framework(s)")

    def match_steps(self, attack_steps: List[str], top_k: int = 3) -> List[Dict[str, Any]]:
        """
        Match attack steps to techniques across all enabled frameworks.

        Args:
            attack_steps: List of attack step descriptions
            top_k: Number of top matches to return per step (across all frameworks)

        Returns:
            List of matches with confidence levels
        """
        self._ensure_initialized()

        self.logger.info(f"Matching {len(attack_steps)} attack steps across {len(self._graphs)} framework(s)...")

        results = []
        matched_count = 0

        for step in attack_steps:
            step_embedding = self._embedding_service.get_embedding(step)

            if not step_embedding:
                self.logger.warning(f"Failed to generate embedding for step: {step[:50]}...")
                continue

            # Collect candidates from all frameworks
            all_matches = []
            for fw_key, vsearch in self._searches.items():
                search_results = vsearch.search(
                    query_embedding=step_embedding,
                    top_k=top_k,
                    min_similarity=self.min_similarity,
                )

                step_lower = step.lower()
                aws_terms_in_step = [term for term in AWS_TERMS if term in step_lower]

                for result in search_results:
                    technique = result['technique']
                    similarity = result['similarity']

                    # Apply AWS term boost
                    if aws_terms_in_step:
                        tech_text = f"{technique.name} {technique.description}".lower()
                        matching_terms = [term for term in aws_terms_in_step if term in tech_text]
                        if matching_terms:
                            boost = 1.0 + (0.1 * len(matching_terms))
                            similarity *= min(boost, 1.5)
                            if similarity < self.min_similarity:
                                continue

                    all_matches.append({
                        'technique_id': technique.primary_technique_id,
                        'name': technique.name,
                        'description': technique.description,
                        'kill_chain_phases': technique.tactics,
                        'similarity': float(similarity),
                        'confidence': self._get_confidence_level(similarity),
                        'framework': fw_key,
                    })

            # Sort by similarity descending, keep top_k across all frameworks
            all_matches.sort(key=lambda m: m['similarity'], reverse=True)
            top_matches = all_matches[:top_k]

            if top_matches:
                matched_count += 1
                results.append({
                    'attack_step': step,
                    'matches': top_matches,
                })

        self.logger.info(f"Matched {matched_count} of {len(attack_steps)} steps")
        return results

    def _get_confidence_level(self, similarity: float) -> str:
        """Determine confidence level from similarity score"""
        if similarity > 0.7:
            return 'high'
        elif similarity > 0.5:
            return 'medium'
        else:
            return 'low'
