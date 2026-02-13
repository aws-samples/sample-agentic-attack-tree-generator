"""Main TTC Mapping Tool - Orchestrates technique mapping"""
from typing import Dict, Any, Optional, TYPE_CHECKING
from ...utils.logger import ThreatForestLogger
from .matcher import TTCMatcher
from .enricher import AttackTreeEnricher
from .matcher_initializer import MatcherInitializer
from .mapping_processor import MappingProcessor

if TYPE_CHECKING:
    from threatforest.tracing.context import TracingContext


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
    
    def run(
        self,
        attack_trees: Dict[str, Any],
        bedrock_model: str,
        aaf_bundle_path: str = None,
        aws_profile: Optional[str] = None,
        tracing_context: Optional["TracingContext"] = None
    ) -> Dict[str, Any]:
        """Execute TTC mapping (fully synchronous)
        
        Args:
            attack_trees: Dictionary containing attack trees to map
            bedrock_model: Bedrock model identifier
            aaf_bundle_path: Optional path to AAF bundle
            aws_profile: Optional AWS profile name
            tracing_context: Optional TracingContext for granular TTP mapping traces
        """
        
        trees = attack_trees.get("attack_trees", [])
        self.logger.info(f"🎯 Starting TTC mapping for {len(trees)} attack trees")
        
        # Initialize matcher
        self.matcher = self.initializer.initialize_matcher(aws_profile)
        
        # Initialize enricher and processor with tracing context
        enricher = AttackTreeEnricher(self.matcher)
        processor = MappingProcessor(
            self.logger, self.matcher, enricher, tracing_context=tracing_context
        )
        
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
                "model": "local"
            }
        }
