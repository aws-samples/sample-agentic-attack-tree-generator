"""TTC Mapping Tool for mapping attack steps to MITRE ATT&CK techniques"""
import json
from typing import Dict, Any, List, Optional
from pathlib import Path

# Mock Strands Tool for testing
class Tool:
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description


class TTCMappingTool(Tool):
    """Tool for mapping attack steps to TTC techniques from STIX data"""
    
    def __init__(self, threshold: float = 0.8):
        self.threshold = threshold
        super().__init__(
            name="ttc_mapping",
            description="Map attack steps to TTC techniques from STIX data"
        )
    
    async def execute(self, attack_trees: Dict[str, Any], 
                     aaf_bundle_path: str = None) -> Dict[str, Any]:
        """Execute TTC mapping"""
        
        # Load STIX data
        stix_data = self._load_stix_data(aaf_bundle_path)
        if not stix_data:
            return {
                "ttc_mapped_trees": attack_trees.get("attack_trees", []),
                "mapping_summary": {
                    "total_mappings": 0,
                    "successful_mappings": 0,
                    "threshold_used": self.threshold,
                    "error": "Failed to load STIX data"
                }
            }
        
        # Extract techniques from STIX data
        techniques = self._extract_techniques(stix_data)
        
        # Map attack trees
        mapped_trees = []
        total_mappings = 0
        successful_mappings = 0
        
        for tree in attack_trees.get("attack_trees", []):
            if "mermaid_code" in tree:
                mapped_tree = self._map_attack_tree(tree, techniques)
                mapped_trees.append(mapped_tree)
                
                mappings = mapped_tree.get("ttc_mappings", [])
                total_mappings += len(mappings)
                successful_mappings += len([m for m in mappings if m.get("confidence", 0) >= self.threshold])
        
        return {
            "ttc_mapped_trees": mapped_trees,
            "mapping_summary": {
                "total_mappings": total_mappings,
                "successful_mappings": successful_mappings,
                "threshold_used": self.threshold,
                "techniques_loaded": len(techniques)
            }
        }
    
    def _load_stix_data(self, bundle_path: str) -> Optional[Dict[str, Any]]:
        """Load STIX bundle data"""
        if not bundle_path:
            # Try default location
            bundle_path = Path(__file__).parent.parent.parent.parent.parent / "genai-chatbot-2" / "aaf-bundle.json"
        
        try:
            bundle_file = Path(bundle_path)
            if bundle_file.exists():
                with open(bundle_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            print(f"Error loading STIX data: {e}")
        
        return None
    
    def _extract_techniques(self, stix_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract MITRE ATT&CK techniques from STIX data"""
        techniques = []
        
        for obj in stix_data.get("objects", []):
            if obj.get("type") == "attack-pattern":
                technique = {
                    "id": obj.get("id"),
                    "technique_id": obj.get("external_references", [{}])[0].get("external_id", ""),
                    "name": obj.get("name", ""),
                    "description": obj.get("description", ""),
                    "kill_chain_phases": [phase.get("phase_name") for phase in obj.get("kill_chain_phases", [])],
                    "platforms": obj.get("x_mitre_platforms", []),
                    "tactics": [phase.get("phase_name") for phase in obj.get("kill_chain_phases", [])]
                }
                techniques.append(technique)
        
        return techniques
    
    def _map_attack_tree(self, tree: Dict[str, Any], techniques: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Map attack tree steps to MITRE ATT&CK techniques"""
        
        # Extract attack steps from mermaid code
        attack_steps = tree.get("attack_steps", [])
        mermaid_code = tree.get("mermaid_code", "")
        
        # Enhanced keyword mapping
        mappings = []
        
        # Define keyword patterns for common attack techniques
        keyword_patterns = {
            "injection": ["inject", "injection", "payload", "malicious input"],
            "bypass": ["bypass", "circumvent", "evade", "avoid"],
            "execution": ["execute", "run", "launch", "invoke", "command"],
            "privilege_escalation": ["escalate", "elevate", "privilege", "admin", "root"],
            "access": ["access", "retrieve", "obtain", "steal", "exfiltrate"],
            "persistence": ["persist", "maintain", "backdoor", "implant"],
            "discovery": ["discover", "enumerate", "scan", "reconnaissance"],
            "lateral_movement": ["lateral", "pivot", "spread", "move"],
            "collection": ["collect", "gather", "harvest", "capture"],
            "exfiltration": ["exfiltrate", "steal", "copy", "transfer"]
        }
        
        for step in attack_steps:
            step_desc = step.get("description", "").lower()
            best_matches = []
            
            # Skip empty descriptions
            if not step_desc.strip():
                continue
            
            for technique in techniques:
                technique_name = technique['name'].lower()
                technique_desc = technique['description'].lower()
                
                # Calculate confidence based on multiple factors
                confidence = 0.0
                
                # Direct keyword matching
                for pattern_type, keywords in keyword_patterns.items():
                    step_matches = sum(1 for kw in keywords if kw in step_desc)
                    tech_matches = sum(1 for kw in keywords if kw in technique_name or kw in technique_desc)
                    
                    if step_matches > 0 and tech_matches > 0:
                        confidence += 0.2 * min(step_matches, tech_matches)
                
                # Direct name similarity
                if any(word in technique_name for word in step_desc.split() if len(word) > 3):
                    confidence += 0.3
                
                # Common cybersecurity terms
                cyber_terms = ["prompt", "llm", "model", "ai", "injection", "validation", "command", "privilege"]
                common_terms = sum(1 for term in cyber_terms if term in step_desc and term in technique_desc)
                if common_terms > 0:
                    confidence += 0.1 * common_terms
                
                if confidence >= 0.2:  # Lower threshold
                    best_matches.append({
                        "technique_id": technique["technique_id"],
                        "technique_name": technique["name"],
                        "confidence": min(confidence, 1.0),
                        "tactics": technique["tactics"],
                        "platforms": technique["platforms"]
                    })
            
            # Sort by confidence and take top matches
            best_matches.sort(key=lambda x: x["confidence"], reverse=True)
            
            if best_matches:
                mappings.append({
                    "attack_step": step_desc,
                    "node_id": step.get("node_id"),
                    "mapped_techniques": best_matches[:3],  # Top 3 matches
                    "confidence": best_matches[0]["confidence"]
                })
        
        # Add mappings to tree
        mapped_tree = tree.copy()
        mapped_tree["ttc_mappings"] = mappings
        
        return mapped_tree
