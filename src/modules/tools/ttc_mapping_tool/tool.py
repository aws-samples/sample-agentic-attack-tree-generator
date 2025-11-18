"""Main TTC Mapping Tool - Orchestrates technique mapping"""
from typing import Dict, Any, Optional
from ...utils.logger import ThreatForestLogger
from ...ttc_mappings import TTCMatcher, AttackTreeEnricher
from .matcher_initializer import MatcherInitializer
from .mapping_processor import MappingProcessor


class TTCMappingTool:
    """Tool for mapping attack steps to TTC techniques (SYNCHRONOUS)"""
    
    def __init__(self, threshold: float = 0.8, console=None):
        self.name = "ttc_mapping"
        self.description = "Map attack steps to TTC techniques using embeddings"
        self.logger = ThreatForestLogger.get_logger(self.__class__.__name__)
        self.threshold = threshold
        self.console = console
        self.matcher = None
        self.initializer = MatcherInitializer(self.logger, threshold)
    
    def run(self, attack_trees: Dict[str, Any], bedrock_model: str,
               aaf_bundle_path: str = None, aws_profile: Optional[str] = None) -> Dict[str, Any]:
        """Execute TTC mapping (fully synchronous)"""
        
        trees = attack_trees.get("attack_trees", [])
        self.logger.info(f"🎯 Starting TTC mapping for {len(trees)} attack trees")
        
        # Initialize matcher
        self.matcher = self.initializer.initialize_matcher(aws_profile)
        
        # Initialize enricher and processor
        enricher = AttackTreeEnricher(self.matcher)
        processor = MappingProcessor(self.logger, self.matcher, enricher)
        
        # Process trees
        mapped_trees, total_mappings, successful_mappings = processor.process_trees(
            trees, self.console
        )
        
        self.logger.info(f"✅ TTC Mapping Complete: {total_mappings} total, {successful_mappings} above threshold")
        
        return {
            "ttc_mapped_trees": mapped_trees,
            "mapping_summary": {
                "total_mappings": total_mappings,
                "successful_mappings": successful_mappings,
                "threshold_used": self.threshold,
                "mode": self.matcher.mode if self.matcher else "unknown",
                "model": getattr(self.matcher, 'model_name', "Neptune-native")
            }
        }
