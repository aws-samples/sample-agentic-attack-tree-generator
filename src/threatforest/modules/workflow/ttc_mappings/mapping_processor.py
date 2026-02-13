"""TTC mapping processing logic"""
from typing import Dict, Any, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from threatforest.tracing.context import TracingContext


class MappingProcessor:
    """Processes TTC mappings for attack trees"""
    
    def __init__(self, logger, matcher, enricher, tracing_context: Optional["TracingContext"] = None):
        self.logger = logger
        self.matcher = matcher
        self.enricher = enricher
        self.tracing_context = tracing_context
    
    def process_trees(self, trees: List[Dict], console=None) -> tuple:
        """Process all trees and return mapped trees with statistics
        
        Returns:
            Tuple of (mapped_trees, total_mappings, successful_mappings)
        """
        mapped_trees = []
        total_mappings = 0
        successful_mappings = 0
        threshold = self.matcher.min_similarity if hasattr(self.matcher, 'min_similarity') else 0.8
        
        if console:
            return self._process_with_progress(trees, threshold, console)
        else:
            return self._process_without_progress(trees, threshold)
    
    def _process_with_progress(self, trees, threshold, console):
        """Process with Rich progress bar"""
        from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
        
        mapped_trees = []
        total_mappings = 0
        successful_mappings = 0
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            task = progress.add_task("[cyan]Mapping TTC techniques...", total=len(trees))
            
            for idx, tree in enumerate(trees, 1):
                threat_id = tree.get('threat_id', 'unknown')
                category = tree.get('threat_category', tree.get('category', 'Unknown'))
                # Show friendly name: "Threat X (Category)" instead of UUID
                progress.update(task, description=f"[cyan]Mapping Threat {idx} ({category})...")
                
                mapped_tree, mappings, successful = self._process_single_tree(tree, threshold)
                mapped_trees.append(mapped_tree)
                total_mappings += mappings
                successful_mappings += successful
                
                progress.advance(task)
        
        return mapped_trees, total_mappings, successful_mappings
    
    def _process_without_progress(self, trees, threshold):
        """Process without progress bar"""
        mapped_trees = []
        total_mappings = 0
        successful_mappings = 0
        
        for idx, tree in enumerate(trees, 1):
            threat_id = tree.get('threat_id', 'unknown')
            self.logger.info(f"📊 Processing {idx}/{len(trees)}: {threat_id}")
            
            mapped_tree, mappings, successful = self._process_single_tree(tree, threshold)
            mapped_trees.append(mapped_tree)
            total_mappings += mappings
            successful_mappings += successful
        
        return mapped_trees, total_mappings, successful_mappings
    
    def _process_single_tree(self, tree, threshold):
        """Process a single tree"""
        if "mermaid_code" not in tree:
            return tree, 0, 0
        
        attack_steps = self.enricher.extract_attack_steps(tree["mermaid_code"])
        
        if not attack_steps:
            self.logger.warning(f"No attack steps found")
            return tree, 0, 0
        
        # Get top 3 matches per attack step for granular tracing
        matches = self.matcher.match_steps(attack_steps, top_k=3)
        
        ttc_mappings = []
        threat_id = tree.get('threat_id', 'unknown')
        threat_statement = tree.get('threat_statement', '')
        threat_category = tree.get('threat_category', tree.get('category', 'Unknown'))
        
        for match in matches:
            attack_step = match['attack_step']
            step_matches = match.get('matches', [])
            
            # Create a span for each attack step + TTP combination (top 3)
            for rank, ttp_match in enumerate(step_matches[:3], start=1):
                technique_id = ttp_match['technique_id']
                technique_name = ttp_match['name']
                technique_description = ttp_match.get('description', '')
                similarity = ttp_match['similarity']
                confidence = ttp_match['confidence']
                tactics = [
                    phase.get('phase_name', phase) if isinstance(phase, dict) else phase 
                    for phase in ttp_match.get('kill_chain_phases', [])
                ]
                
                # Create granular span for this attack_step + TTP combination
                if self.tracing_context and self.tracing_context.current_trace:
                    with self.tracing_context.span(
                        name="ttp_mapping_candidate",
                        metadata={
                            "threat_id": threat_id,
                            "rank": rank,
                            "technique_id": technique_id,
                        }
                    ) as span:
                        # Input: attack step with threat context for human reviewer
                        span.set_input({
                            "attack_step": attack_step,
                            "threat_id": threat_id,
                            "threat_statement": threat_statement,
                            "threat_category": threat_category,
                        })
                        # Output: mapped technique with full description for scoring
                        span.set_output({
                            "technique_id": technique_id,
                            "technique_name": technique_name,
                            "technique_description": technique_description,
                            "embedding_similarity": round(similarity, 4),
                            "confidence": confidence,
                            "tactics": tactics,
                            "rank": rank,
                        })
                
                # Only add the best match (rank 1) to the final mappings
                if rank == 1:
                    ttc_mappings.append({
                        "attack_step": attack_step,
                        "technique_id": technique_id,
                        "technique_name": technique_name,
                        "confidence": similarity,
                        "tactics": tactics,
                        "reasoning": f"Embedding similarity: {similarity:.3f}"
                    })
        
        total = len(ttc_mappings)
        successful = len([m for m in ttc_mappings if m.get("confidence", 0) >= threshold])
        
        mapped_tree = tree.copy()
        mapped_tree["ttc_mappings"] = ttc_mappings
        mapped_tree["mapping_count"] = total
        
        self.logger.info(f"   └─ Mapped {total} techniques")
        
        return mapped_tree, total, successful
