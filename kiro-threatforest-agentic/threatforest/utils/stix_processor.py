"""
STIX file processing utilities for ThreatForest.

This module provides functionality to parse AAF bundle JSON files containing
STIX-formatted threat intelligence data, extract relevant techniques, and
provide search capabilities for TTC mapping.
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class STIXTechnique:
    """Represents a STIX technique from the AAF bundle."""
    
    id: str
    name: str
    description: str
    technique_type: str
    external_references: List[Dict[str, Any]]
    kill_chain_phases: List[Dict[str, Any]]
    platforms: List[str]
    tactics: List[str]
    raw_data: Dict[str, Any]
    
    def get_mitre_id(self) -> Optional[str]:
        """Extract MITRE ATT&CK ID from external references."""
        for ref in self.external_references:
            if ref.get("source_name") == "mitre-attack":
                return ref.get("external_id")
        return None
    
    def get_description_keywords(self) -> Set[str]:
        """Extract keywords from technique description for search."""
        if not self.description:
            return set()
        
        # Simple keyword extraction - split on common delimiters and filter
        words = self.description.lower().replace(",", " ").replace(".", " ").split()
        
        # Filter out common stop words and short words
        stop_words = {
            "the", "a", "an", "and", "or", "but", "in", "on", "at", "to", "for",
            "of", "with", "by", "is", "are", "was", "were", "be", "been", "have",
            "has", "had", "do", "does", "did", "will", "would", "could", "should",
            "may", "might", "can", "this", "that", "these", "those", "it", "its"
        }
        
        keywords = {
            word.strip("()[]{}\"'.,;:!?") 
            for word in words 
            if len(word) > 2 and word not in stop_words
        }
        
        return keywords
    
    def matches_platform(self, platform: str) -> bool:
        """Check if technique applies to a specific platform."""
        if not self.platforms:
            return True  # No platform restriction
        
        platform_lower = platform.lower()
        return any(
            platform_lower in p.lower() or p.lower() in platform_lower
            for p in self.platforms
        )


@dataclass
class STIXTactic:
    """Represents a STIX tactic from the AAF bundle."""
    
    id: str
    name: str
    description: str
    external_references: List[Dict[str, Any]]
    raw_data: Dict[str, Any]
    
    def get_mitre_id(self) -> Optional[str]:
        """Extract MITRE ATT&CK ID from external references."""
        for ref in self.external_references:
            if ref.get("source_name") == "mitre-attack":
                return ref.get("external_id")
        return None


@dataclass
class STIXSearchResult:
    """Result of searching STIX techniques."""
    
    technique: STIXTechnique
    relevance_score: float
    matching_keywords: Set[str]
    match_reasons: List[str]
    
    def __lt__(self, other):
        """Enable sorting by relevance score."""
        return self.relevance_score < other.relevance_score


class STIXProcessorError(Exception):
    """Custom exception for STIX processing errors."""
    pass


class STIXProcessor:
    """
    Processor for STIX-formatted threat intelligence data.
    
    Handles parsing AAF bundle JSON files, indexing techniques and tactics,
    and providing search functionality for TTC mapping.
    """
    
    def __init__(self, aaf_bundle_path: str):
        """
        Initialize STIX processor with AAF bundle file.
        
        Args:
            aaf_bundle_path: Path to AAF bundle JSON file
        """
        self.aaf_bundle_path = Path(aaf_bundle_path)
        self.techniques: Dict[str, STIXTechnique] = {}
        self.tactics: Dict[str, STIXTactic] = {}
        self.technique_keywords: Dict[str, Set[str]] = {}
        self.loaded = False
        self.load_timestamp: Optional[datetime] = None
        
        # Load the bundle if file exists
        if self.aaf_bundle_path.exists():
            self.load_bundle()
    
    def load_bundle(self) -> None:
        """
        Load and parse the AAF bundle JSON file.
        
        Raises:
            STIXProcessorError: If bundle loading fails
        """
        logger.info(f"Loading STIX bundle from: {self.aaf_bundle_path}")
        
        try:
            with open(self.aaf_bundle_path, 'r', encoding='utf-8') as f:
                bundle_data = json.load(f)
            
            # Validate bundle structure
            if not isinstance(bundle_data, dict):
                raise STIXProcessorError("Bundle file is not a valid JSON object")
            
            if bundle_data.get("type") != "bundle":
                raise STIXProcessorError("File is not a STIX bundle")
            
            objects = bundle_data.get("objects", [])
            if not isinstance(objects, list):
                raise STIXProcessorError("Bundle objects is not a list")
            
            logger.info(f"Processing {len(objects)} STIX objects")
            
            # Process STIX objects
            self._process_stix_objects(objects)
            
            self.loaded = True
            self.load_timestamp = datetime.now()
            
            logger.info(f"Successfully loaded {len(self.techniques)} techniques and {len(self.tactics)} tactics")
            
        except json.JSONDecodeError as e:
            raise STIXProcessorError(f"Invalid JSON in bundle file: {e}")
        except FileNotFoundError:
            raise STIXProcessorError(f"Bundle file not found: {self.aaf_bundle_path}")
        except Exception as e:
            raise STIXProcessorError(f"Error loading bundle: {e}")
    
    def _process_stix_objects(self, objects: List[Dict[str, Any]]) -> None:
        """
        Process STIX objects from the bundle.
        
        Args:
            objects: List of STIX objects to process
        """
        for obj in objects:
            try:
                obj_type = obj.get("type")
                
                if obj_type == "attack-pattern":
                    self._process_technique(obj)
                elif obj_type == "x-mitre-tactic":
                    self._process_tactic(obj)
                # Add other object types as needed
                
            except Exception as e:
                logger.warning(f"Error processing STIX object {obj.get('id', 'unknown')}: {e}")
                continue
    
    def _process_technique(self, obj: Dict[str, Any]) -> None:
        """Process a STIX attack-pattern (technique) object."""
        technique_id = obj.get("id")
        if not technique_id:
            return
        
        # Extract kill chain phases and tactics
        kill_chain_phases = obj.get("kill_chain_phases", [])
        tactics = [phase.get("phase_name", "") for phase in kill_chain_phases]
        
        # Extract platforms
        platforms = obj.get("x_mitre_platforms", [])
        if isinstance(platforms, str):
            platforms = [platforms]
        
        technique = STIXTechnique(
            id=technique_id,
            name=obj.get("name", ""),
            description=obj.get("description", ""),
            technique_type=obj.get("type", "attack-pattern"),
            external_references=obj.get("external_references", []),
            kill_chain_phases=kill_chain_phases,
            platforms=platforms,
            tactics=tactics,
            raw_data=obj
        )
        
        self.techniques[technique_id] = technique
        
        # Index keywords for search
        keywords = technique.get_description_keywords()
        keywords.add(technique.name.lower())
        if technique.get_mitre_id():
            keywords.add(technique.get_mitre_id().lower())
        
        self.technique_keywords[technique_id] = keywords
    
    def _process_tactic(self, obj: Dict[str, Any]) -> None:
        """Process a STIX x-mitre-tactic object."""
        tactic_id = obj.get("id")
        if not tactic_id:
            return
        
        tactic = STIXTactic(
            id=tactic_id,
            name=obj.get("name", ""),
            description=obj.get("description", ""),
            external_references=obj.get("external_references", []),
            raw_data=obj
        )
        
        self.tactics[tactic_id] = tactic
    
    def search_techniques(
        self,
        query: str,
        max_results: int = 10,
        min_score: float = 0.1,
        platform_filter: Optional[str] = None
    ) -> List[STIXSearchResult]:
        """
        Search for techniques matching a query string.
        
        Args:
            query: Search query string
            max_results: Maximum number of results to return
            min_score: Minimum relevance score threshold
            platform_filter: Optional platform to filter by
            
        Returns:
            List of STIXSearchResult objects sorted by relevance
        """
        if not self.loaded:
            logger.warning("STIX bundle not loaded, returning empty results")
            return []
        
        query_keywords = self._extract_query_keywords(query)
        if not query_keywords:
            return []
        
        results = []
        
        for technique_id, technique in self.techniques.items():
            # Apply platform filter if specified
            if platform_filter and not technique.matches_platform(platform_filter):
                continue
            
            # Calculate relevance score
            score, matching_keywords, reasons = self._calculate_relevance_score(
                technique, technique_id, query_keywords
            )
            
            if score >= min_score:
                results.append(STIXSearchResult(
                    technique=technique,
                    relevance_score=score,
                    matching_keywords=matching_keywords,
                    match_reasons=reasons
                ))
        
        # Sort by relevance score (descending) and limit results
        results.sort(key=lambda x: x.relevance_score, reverse=True)
        return results[:max_results]
    
    def _extract_query_keywords(self, query: str) -> Set[str]:
        """Extract keywords from search query."""
        if not query:
            return set()
        
        # Simple keyword extraction
        words = query.lower().replace(",", " ").replace(".", " ").split()
        
        # Filter out very short words and common stop words
        stop_words = {"the", "a", "an", "and", "or", "but", "in", "on", "at", "to", "for", "of", "with", "by"}
        
        keywords = {
            word.strip("()[]{}\"'.,;:!?") 
            for word in words 
            if len(word) > 2 and word not in stop_words
        }
        
        return keywords
    
    def _calculate_relevance_score(
        self,
        technique: STIXTechnique,
        technique_id: str,
        query_keywords: Set[str]
    ) -> Tuple[float, Set[str], List[str]]:
        """
        Calculate relevance score for a technique against query keywords.
        
        Returns:
            Tuple of (score, matching_keywords, match_reasons)
        """
        technique_keywords = self.technique_keywords.get(technique_id, set())
        
        if not technique_keywords:
            return 0.0, set(), []
        
        # Find matching keywords
        matching_keywords = query_keywords.intersection(technique_keywords)
        
        if not matching_keywords:
            return 0.0, set(), []
        
        # Calculate base score based on keyword matches
        match_ratio = len(matching_keywords) / len(query_keywords)
        coverage_ratio = len(matching_keywords) / len(technique_keywords)
        
        # Base score combines match ratio and coverage
        base_score = (match_ratio * 0.7) + (coverage_ratio * 0.3)
        
        # Bonus scoring
        bonus_score = 0.0
        match_reasons = []
        
        # Bonus for exact name matches
        technique_name_words = set(technique.name.lower().split())
        if query_keywords.intersection(technique_name_words):
            bonus_score += 0.2
            match_reasons.append("Name match")
        
        # Bonus for MITRE ID matches
        mitre_id = technique.get_mitre_id()
        if mitre_id and mitre_id.lower() in query_keywords:
            bonus_score += 0.3
            match_reasons.append("MITRE ID match")
        
        # Bonus for multiple keyword matches
        if len(matching_keywords) > 1:
            bonus_score += 0.1 * (len(matching_keywords) - 1)
            match_reasons.append(f"Multiple keyword matches ({len(matching_keywords)})")
        
        final_score = min(1.0, base_score + bonus_score)
        
        if not match_reasons:
            match_reasons.append("Keyword match")
        
        return final_score, matching_keywords, match_reasons
    
    def get_technique_by_id(self, technique_id: str) -> Optional[STIXTechnique]:
        """Get a technique by its STIX ID."""
        return self.techniques.get(technique_id)
    
    def get_technique_by_mitre_id(self, mitre_id: str) -> Optional[STIXTechnique]:
        """Get a technique by its MITRE ATT&CK ID."""
        for technique in self.techniques.values():
            if technique.get_mitre_id() == mitre_id:
                return technique
        return None
    
    def get_techniques_by_tactic(self, tactic_name: str) -> List[STIXTechnique]:
        """Get all techniques associated with a specific tactic."""
        tactic_lower = tactic_name.lower()
        return [
            technique for technique in self.techniques.values()
            if any(tactic_lower in tactic.lower() for tactic in technique.tactics)
        ]
    
    def get_all_tactics(self) -> List[STIXTactic]:
        """Get all available tactics."""
        return list(self.tactics.values())
    
    def get_all_techniques(self) -> List[STIXTechnique]:
        """Get all available techniques."""
        return list(self.techniques.values())
    
    def get_platforms(self) -> Set[str]:
        """Get all unique platforms from techniques."""
        platforms = set()
        for technique in self.techniques.values():
            platforms.update(technique.platforms)
        return platforms
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about the loaded STIX data."""
        if not self.loaded:
            return {"loaded": False}
        
        platforms = self.get_platforms()
        tactic_names = {tactic.name for tactic in self.tactics.values()}
        
        return {
            "loaded": True,
            "load_timestamp": self.load_timestamp.isoformat() if self.load_timestamp else None,
            "bundle_path": str(self.aaf_bundle_path),
            "total_techniques": len(self.techniques),
            "total_tactics": len(self.tactics),
            "unique_platforms": len(platforms),
            "platforms": sorted(list(platforms)),
            "tactic_names": sorted(list(tactic_names)),
            "techniques_with_mitre_ids": sum(
                1 for t in self.techniques.values() if t.get_mitre_id()
            )
        }
    
    def validate_bundle(self) -> Dict[str, Any]:
        """
        Validate the loaded STIX bundle for completeness and consistency.
        
        Returns:
            Dictionary with validation results
        """
        if not self.loaded:
            return {"valid": False, "errors": ["Bundle not loaded"]}
        
        errors = []
        warnings = []
        
        # Check for techniques without descriptions
        techniques_without_desc = [
            t.id for t in self.techniques.values() 
            if not t.description or len(t.description.strip()) < 10
        ]
        if techniques_without_desc:
            warnings.append(f"{len(techniques_without_desc)} techniques have insufficient descriptions")
        
        # Check for techniques without MITRE IDs
        techniques_without_mitre = [
            t.id for t in self.techniques.values() 
            if not t.get_mitre_id()
        ]
        if techniques_without_mitre:
            warnings.append(f"{len(techniques_without_mitre)} techniques missing MITRE IDs")
        
        # Check for techniques without tactics
        techniques_without_tactics = [
            t.id for t in self.techniques.values() 
            if not t.tactics
        ]
        if techniques_without_tactics:
            warnings.append(f"{len(techniques_without_tactics)} techniques have no associated tactics")
        
        # Check for empty platforms
        techniques_without_platforms = [
            t.id for t in self.techniques.values() 
            if not t.platforms
        ]
        if techniques_without_platforms:
            warnings.append(f"{len(techniques_without_platforms)} techniques have no platform restrictions")
        
        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "warnings": warnings,
            "validation_timestamp": datetime.now().isoformat()
        }
    
    def export_techniques_summary(self, output_path: str) -> Path:
        """
        Export a summary of all techniques to a markdown file.
        
        Args:
            output_path: Directory to save the summary file
            
        Returns:
            Path to the exported file
        """
        output_dir = Path(output_path)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        output_file = output_dir / "stix_techniques_summary.md"
        
        lines = [
            "# STIX Techniques Summary",
            "",
            f"Generated: {datetime.now().isoformat()}",
            f"Total Techniques: {len(self.techniques)}",
            f"Total Tactics: {len(self.tactics)}",
            "",
            "## Techniques by Tactic",
            ""
        ]
        
        # Group techniques by tactic
        tactic_groups = {}
        for technique in self.techniques.values():
            for tactic in technique.tactics:
                if tactic not in tactic_groups:
                    tactic_groups[tactic] = []
                tactic_groups[tactic].append(technique)
        
        for tactic_name in sorted(tactic_groups.keys()):
            lines.append(f"### {tactic_name.title()}")
            lines.append("")
            
            techniques = sorted(tactic_groups[tactic_name], key=lambda t: t.name)
            for technique in techniques:
                mitre_id = technique.get_mitre_id()
                mitre_str = f" ({mitre_id})" if mitre_id else ""
                lines.append(f"- **{technique.name}**{mitre_str}")
                if technique.description:
                    # Truncate long descriptions
                    desc = technique.description[:200] + "..." if len(technique.description) > 200 else technique.description
                    lines.append(f"  {desc}")
                lines.append("")
        
        # Write to file
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("\n".join(lines))
        
        logger.info(f"Exported techniques summary to: {output_file}")
        return output_file