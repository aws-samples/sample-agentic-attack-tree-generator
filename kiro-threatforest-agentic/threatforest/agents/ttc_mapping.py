"""
TTC Mapping Agent for ThreatForest.

This agent enhances attack trees with STIX threat intelligence by mapping
attack steps to TTC (Threat Technique Catalog) techniques using semantic
similarity analysis.
"""

import logging
import numpy as np
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass
from datetime import datetime

from ..models import AttackTree, AttackStep, TTCMapping
from ..utils.stix_processor import STIXProcessor, STIXTechnique, STIXSearchResult


logger = logging.getLogger(__name__)


@dataclass
class MappingResult:
    """Result of TTC mapping process."""
    
    enhanced_tree: AttackTree
    applied_mappings: List[TTCMapping]
    rejected_mappings: List[TTCMapping]
    processing_errors: List[str]
    processing_warnings: List[str]
    processing_time_seconds: float
    
    def get_mapping_statistics(self) -> Dict[str, Any]:
        """Get statistics about the mapping results."""
        total_mappings = len(self.applied_mappings) + len(self.rejected_mappings)
        
        return {
            "total_steps_processed": len(self.enhanced_tree.attack_steps),
            "total_mappings_found": total_mappings,
            "applied_mappings": len(self.applied_mappings),
            "rejected_mappings": len(self.rejected_mappings),
            "application_rate": len(self.applied_mappings) / total_mappings if total_mappings > 0 else 0,
            "average_confidence": np.mean([m.alignment_score for m in self.applied_mappings]) if self.applied_mappings else 0,
            "processing_errors": len(self.processing_errors),
            "processing_warnings": len(self.processing_warnings)
        }


class TTCMappingAgent:
    """
    Agent responsible for mapping attack steps to TTC techniques.
    
    Uses semantic similarity analysis to match attack tree steps with
    STIX threat intelligence techniques from the AAF bundle.
    """
    
    def __init__(self, stix_processor: STIXProcessor, alignment_threshold: float = 0.8):
        """
        Initialize the TTC Mapping Agent.
        
        Args:
            stix_processor: STIX processor with loaded AAF bundle
            alignment_threshold: Minimum alignment score for applying mappings
        """
        self.stix_processor = stix_processor
        self.alignment_threshold = alignment_threshold
        self._embeddings_model = None
        
        # Initialize sentence transformer model lazily
        self._model_name = "all-MiniLM-L6-v2"  # Lightweight, good performance
        
        logger.info(f"TTC Mapping Agent initialized with threshold: {alignment_threshold}")
    
    def _get_embeddings_model(self):
        """Lazy initialization of sentence transformer model."""
        if self._embeddings_model is None:
            try:
                from sentence_transformers import SentenceTransformer
                self._embeddings_model = SentenceTransformer(self._model_name)
                logger.info(f"Loaded sentence transformer model: {self._model_name}")
            except ImportError:
                logger.error("sentence-transformers library not available. Install with: pip install sentence-transformers")
                raise ImportError("sentence-transformers library required for semantic similarity")
            except Exception as e:
                logger.error(f"Error loading sentence transformer model: {e}")
                raise
        
        return self._embeddings_model
    
    def enhance_attack_tree(self, attack_tree: AttackTree) -> MappingResult:
        """
        Enhance an attack tree with TTC mappings.
        
        Args:
            attack_tree: Attack tree to enhance
            
        Returns:
            MappingResult with enhanced tree and mapping information
        """
        start_time = datetime.now()
        
        logger.info(f"Enhancing attack tree {attack_tree.threat_id} with TTC mappings")
        
        processing_errors = []
        processing_warnings = []
        applied_mappings = []
        rejected_mappings = []
        
        # Check if STIX processor is loaded
        if not self.stix_processor.loaded:
            error_msg = "STIX processor not loaded - cannot perform TTC mapping"
            logger.error(error_msg)
            processing_errors.append(error_msg)
            
            processing_time = (datetime.now() - start_time).total_seconds()
            return MappingResult(
                enhanced_tree=attack_tree,
                applied_mappings=[],
                rejected_mappings=[],
                processing_errors=processing_errors,
                processing_warnings=processing_warnings,
                processing_time_seconds=processing_time
            )
        
        try:
            # Process each attack step
            for step in attack_tree.attack_steps:
                try:
                    # Skip non-attack steps (goals, facts, mitigations handled differently)
                    if step.step_type.value != "attack":
                        logger.debug(f"Skipping non-attack step: {step.id}")
                        continue
                    
                    # Find potential TTC mappings
                    mappings = self._find_ttc_mappings(step)
                    
                    # Apply mappings above threshold
                    for mapping in mappings:
                        if mapping.is_strong_alignment(self.alignment_threshold):
                            applied_mappings.append(mapping)
                            attack_tree.add_ttc_mapping(mapping)
                            mapping.applied = True
                            logger.debug(f"Applied TTC mapping for step {step.id}: {mapping.ttc_technique_id} (score: {mapping.alignment_score:.3f})")
                        else:
                            rejected_mappings.append(mapping)
                            logger.debug(f"Rejected TTC mapping for step {step.id}: {mapping.ttc_technique_id} (score: {mapping.alignment_score:.3f})")
                
                except Exception as e:
                    error_msg = f"Error processing step {step.id}: {e}"
                    logger.warning(error_msg)
                    processing_warnings.append(error_msg)
                    continue
            
            # Update attack tree with TTC information in Mermaid content
            if applied_mappings:
                attack_tree.mermaid_content = self._update_mermaid_with_ttc(
                    attack_tree.mermaid_content, applied_mappings
                )
            
            processing_time = (datetime.now() - start_time).total_seconds()
            
            logger.info(f"TTC mapping complete: {len(applied_mappings)} applied, {len(rejected_mappings)} rejected")
            
            return MappingResult(
                enhanced_tree=attack_tree,
                applied_mappings=applied_mappings,
                rejected_mappings=rejected_mappings,
                processing_errors=processing_errors,
                processing_warnings=processing_warnings,
                processing_time_seconds=processing_time
            )
            
        except Exception as e:
            error_msg = f"Error during TTC mapping: {e}"
            logger.error(error_msg)
            processing_errors.append(error_msg)
            
            processing_time = (datetime.now() - start_time).total_seconds()
            
            return MappingResult(
                enhanced_tree=attack_tree,
                applied_mappings=applied_mappings,
                rejected_mappings=rejected_mappings,
                processing_errors=processing_errors,
                processing_warnings=processing_warnings,
                processing_time_seconds=processing_time
            )
    
    def _find_ttc_mappings(self, attack_step: AttackStep) -> List[TTCMapping]:
        """
        Find potential TTC mappings for an attack step.
        
        Args:
            attack_step: Attack step to map
            
        Returns:
            List of potential TTCMapping objects
        """
        mappings = []
        
        try:
            # Search for relevant STIX techniques
            search_results = self.stix_processor.search_techniques(
                query=attack_step.description,
                max_results=5,  # Limit to top 5 candidates
                min_score=0.1   # Low threshold for initial search
            )
            
            if not search_results:
                logger.debug(f"No STIX techniques found for step: {attack_step.id}")
                return mappings
            
            # Calculate semantic similarity for each candidate
            for search_result in search_results:
                try:
                    alignment_score = self._calculate_semantic_similarity(
                        attack_step.description,
                        search_result.technique
                    )
                    
                    # Create TTC mapping
                    mapping = TTCMapping(
                        attack_step_id=attack_step.id,
                        ttc_technique_id=search_result.technique.id,
                        ttc_technique_name=search_result.technique.name,
                        alignment_score=alignment_score,
                        stix_data=search_result.technique.raw_data,
                        applied=False
                    )
                    
                    mappings.append(mapping)
                    
                except Exception as e:
                    logger.warning(f"Error calculating similarity for technique {search_result.technique.id}: {e}")
                    continue
            
            # Sort by alignment score (highest first)
            mappings.sort(key=lambda m: m.alignment_score, reverse=True)
            
        except Exception as e:
            logger.error(f"Error finding TTC mappings for step {attack_step.id}: {e}")
        
        return mappings
    
    def _calculate_semantic_similarity(
        self,
        attack_description: str,
        stix_technique: STIXTechnique
    ) -> float:
        """
        Calculate semantic similarity between attack step and STIX technique.
        
        Args:
            attack_description: Description of the attack step
            stix_technique: STIX technique to compare against
            
        Returns:
            Similarity score between 0.0 and 1.0
        """
        try:
            model = self._get_embeddings_model()
            
            # Prepare texts for comparison
            attack_text = attack_description.strip()
            
            # Combine technique name and description for better matching
            technique_text = f"{stix_technique.name}. {stix_technique.description}".strip()
            
            # Generate embeddings
            embeddings = model.encode([attack_text, technique_text])
            
            # Calculate cosine similarity
            similarity = self._cosine_similarity(embeddings[0], embeddings[1])
            
            # Apply additional scoring factors
            bonus_score = self._calculate_bonus_score(attack_description, stix_technique)
            
            # Combine base similarity with bonus (capped at 1.0)
            final_score = min(1.0, similarity + bonus_score)
            
            return float(final_score)
            
        except Exception as e:
            logger.warning(f"Error calculating semantic similarity: {e}")
            return 0.0
    
    def _cosine_similarity(self, vec1: np.ndarray, vec2: np.ndarray) -> float:
        """Calculate cosine similarity between two vectors."""
        try:
            # Normalize vectors
            vec1_norm = vec1 / np.linalg.norm(vec1)
            vec2_norm = vec2 / np.linalg.norm(vec2)
            
            # Calculate cosine similarity
            similarity = np.dot(vec1_norm, vec2_norm)
            
            # Ensure result is in [0, 1] range
            return max(0.0, min(1.0, float(similarity)))
            
        except Exception as e:
            logger.warning(f"Error calculating cosine similarity: {e}")
            return 0.0
    
    def _calculate_bonus_score(
        self,
        attack_description: str,
        stix_technique: STIXTechnique
    ) -> float:
        """
        Calculate bonus score based on specific matching criteria.
        
        Args:
            attack_description: Attack step description
            stix_technique: STIX technique
            
        Returns:
            Bonus score (typically 0.0 to 0.2)
        """
        bonus = 0.0
        
        attack_lower = attack_description.lower()
        technique_name_lower = stix_technique.name.lower()
        technique_desc_lower = stix_technique.description.lower()
        
        # Bonus for exact technique name matches
        technique_words = set(technique_name_lower.split())
        attack_words = set(attack_lower.split())
        
        if technique_words.intersection(attack_words):
            bonus += 0.1
        
        # Bonus for MITRE ID mentions
        mitre_id = stix_technique.get_mitre_id()
        if mitre_id and mitre_id.lower() in attack_lower:
            bonus += 0.15
        
        # Bonus for specific keyword matches
        high_value_keywords = {
            'injection', 'exploit', 'vulnerability', 'credential', 'privilege',
            'escalation', 'persistence', 'lateral', 'movement', 'exfiltration'
        }
        
        attack_keywords = set(attack_lower.split())
        technique_keywords = set(technique_desc_lower.split())
        
        keyword_matches = high_value_keywords.intersection(
            attack_keywords.union(technique_keywords)
        )
        
        if keyword_matches:
            bonus += 0.05 * len(keyword_matches)
        
        return min(0.2, bonus)  # Cap bonus at 0.2
    
    def _update_mermaid_with_ttc(
        self,
        mermaid_content: str,
        applied_mappings: List[TTCMapping]
    ) -> str:
        """
        Update Mermaid diagram content to include TTC information.
        
        Args:
            mermaid_content: Original Mermaid content
            applied_mappings: List of applied TTC mappings
            
        Returns:
            Updated Mermaid content with TTC information
        """
        if not applied_mappings:
            return mermaid_content
        
        lines = mermaid_content.split('\n')
        updated_lines = []
        
        # Create mapping lookup
        step_to_mapping = {mapping.attack_step_id: mapping for mapping in applied_mappings}
        
        for line in lines:
            updated_lines.append(line)
            
            # Look for step definitions and add TTC info
            for step_id, mapping in step_to_mapping.items():
                if step_id in line and '[' in line and ']' in line:
                    # Extract current description
                    start_idx = line.find('[') + 1
                    end_idx = line.find(']')
                    
                    if start_idx > 0 and end_idx > start_idx:
                        current_desc = line[start_idx:end_idx].strip('"')
                        
                        # Add TTC information
                        mitre_id = ""
                        technique = self.stix_processor.get_technique_by_id(mapping.ttc_technique_id)
                        if technique:
                            mitre_id = technique.get_mitre_id() or ""
                        
                        if mitre_id:
                            enhanced_desc = f"{current_desc}<br/><small>TTC: {mitre_id}</small>"
                            updated_line = line.replace(f'["{current_desc}"]', f'["{enhanced_desc}"]')
                            updated_line = updated_line.replace(f'[{current_desc}]', f'["{enhanced_desc}"]')
                            updated_lines[-1] = updated_line
        
        return '\n'.join(updated_lines)
    
    def enhance_multiple_trees(
        self,
        attack_trees: List[AttackTree]
    ) -> List[MappingResult]:
        """
        Enhance multiple attack trees with TTC mappings.
        
        Args:
            attack_trees: List of attack trees to enhance
            
        Returns:
            List of MappingResult objects
        """
        results = []
        
        logger.info(f"Enhancing {len(attack_trees)} attack trees with TTC mappings")
        
        for attack_tree in attack_trees:
            try:
                result = self.enhance_attack_tree(attack_tree)
                results.append(result)
                
                stats = result.get_mapping_statistics()
                logger.info(f"Enhanced tree {attack_tree.threat_id}: {stats['applied_mappings']} mappings applied")
                
            except Exception as e:
                logger.error(f"Error enhancing attack tree {attack_tree.threat_id}: {e}")
                
                # Create error result
                error_result = MappingResult(
                    enhanced_tree=attack_tree,
                    applied_mappings=[],
                    rejected_mappings=[],
                    processing_errors=[f"Enhancement failed: {e}"],
                    processing_warnings=[],
                    processing_time_seconds=0.0
                )
                results.append(error_result)
        
        # Log overall statistics
        total_applied = sum(len(r.applied_mappings) for r in results)
        total_rejected = sum(len(r.rejected_mappings) for r in results)
        total_errors = sum(len(r.processing_errors) for r in results)
        
        logger.info(f"TTC enhancement complete: {total_applied} mappings applied, {total_rejected} rejected, {total_errors} errors")
        
        return results
    
    def get_mapping_confidence_distribution(
        self,
        results: List[MappingResult]
    ) -> Dict[str, Any]:
        """
        Analyze the confidence distribution of TTC mappings.
        
        Args:
            results: List of mapping results
            
        Returns:
            Dictionary with confidence distribution statistics
        """
        all_applied = []
        all_rejected = []
        
        for result in results:
            all_applied.extend(result.applied_mappings)
            all_rejected.extend(result.rejected_mappings)
        
        if not all_applied and not all_rejected:
            return {"total_mappings": 0}
        
        applied_scores = [m.alignment_score for m in all_applied]
        rejected_scores = [m.alignment_score for m in all_rejected]
        all_scores = applied_scores + rejected_scores
        
        return {
            "total_mappings": len(all_scores),
            "applied_mappings": len(applied_scores),
            "rejected_mappings": len(rejected_scores),
            "threshold": self.alignment_threshold,
            "applied_stats": {
                "mean": np.mean(applied_scores) if applied_scores else 0,
                "std": np.std(applied_scores) if applied_scores else 0,
                "min": np.min(applied_scores) if applied_scores else 0,
                "max": np.max(applied_scores) if applied_scores else 0
            },
            "rejected_stats": {
                "mean": np.mean(rejected_scores) if rejected_scores else 0,
                "std": np.std(rejected_scores) if rejected_scores else 0,
                "min": np.min(rejected_scores) if rejected_scores else 0,
                "max": np.max(rejected_scores) if rejected_scores else 0
            },
            "overall_stats": {
                "mean": np.mean(all_scores),
                "std": np.std(all_scores),
                "min": np.min(all_scores),
                "max": np.max(all_scores)
            }
        }
    
    def export_mapping_report(
        self,
        results: List[MappingResult],
        output_path: str
    ) -> str:
        """
        Export a detailed mapping report to a markdown file.
        
        Args:
            results: List of mapping results
            output_path: Directory to save the report
            
        Returns:
            Path to the exported report file
        """
        from pathlib import Path
        
        output_dir = Path(output_path)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        report_file = output_dir / "ttc_mapping_report.md"
        
        # Generate report content
        lines = [
            "# TTC Mapping Report",
            "",
            f"**Generated:** {datetime.now().isoformat()}",
            f"**Alignment Threshold:** {self.alignment_threshold}",
            f"**Trees Processed:** {len(results)}",
            ""
        ]
        
        # Overall statistics
        confidence_dist = self.get_mapping_confidence_distribution(results)
        
        lines.extend([
            "## Overall Statistics",
            "",
            f"- **Total Mappings Found:** {confidence_dist.get('total_mappings', 0)}",
            f"- **Applied Mappings:** {confidence_dist.get('applied_mappings', 0)}",
            f"- **Rejected Mappings:** {confidence_dist.get('rejected_mappings', 0)}",
            f"- **Application Rate:** {confidence_dist.get('applied_mappings', 0) / max(1, confidence_dist.get('total_mappings', 1)) * 100:.1f}%",
            ""
        ])
        
        # Per-tree results
        lines.extend([
            "## Per-Tree Results",
            ""
        ])
        
        for result in results:
            stats = result.get_mapping_statistics()
            
            lines.extend([
                f"### {result.enhanced_tree.threat_id}",
                "",
                f"- **Steps Processed:** {stats['total_steps_processed']}",
                f"- **Mappings Applied:** {stats['applied_mappings']}",
                f"- **Mappings Rejected:** {stats['rejected_mappings']}",
                f"- **Average Confidence:** {stats['average_confidence']:.3f}",
                f"- **Processing Time:** {result.processing_time_seconds:.2f}s",
                ""
            ])
            
            # List applied mappings
            if result.applied_mappings:
                lines.extend([
                    "#### Applied Mappings",
                    ""
                ])
                
                for mapping in result.applied_mappings:
                    technique = self.stix_processor.get_technique_by_id(mapping.ttc_technique_id)
                    mitre_id = technique.get_mitre_id() if technique else "Unknown"
                    
                    lines.extend([
                        f"- **{mapping.attack_step_id}** → **{mapping.ttc_technique_name}** ({mitre_id})",
                        f"  - Confidence: {mapping.alignment_score:.3f}",
                        ""
                    ])
            
            # List errors and warnings
            if result.processing_errors:
                lines.extend([
                    "#### Errors",
                    "",
                    *[f"- {error}" for error in result.processing_errors],
                    ""
                ])
            
            if result.processing_warnings:
                lines.extend([
                    "#### Warnings",
                    "",
                    *[f"- {warning}" for warning in result.processing_warnings],
                    ""
                ])
        
        # Write report
        try:
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write('\n'.join(lines))
            
            logger.info(f"Exported TTC mapping report to: {report_file}")
            return str(report_file)
            
        except Exception as e:
            logger.error(f"Error exporting mapping report: {e}")
            raise