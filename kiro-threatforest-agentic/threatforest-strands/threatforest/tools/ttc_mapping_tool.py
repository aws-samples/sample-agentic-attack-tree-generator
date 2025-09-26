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
                     aaf_bundle_path: str = None,
                     bedrock_model: str = "us.anthropic.claude-sonnet-4-20250514-v1:0",
                     aws_profile: Optional[str] = None) -> Dict[str, Any]:
        """Execute TTC mapping with Bedrock enhancement"""
        
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
        
        # Map attack trees with Bedrock enhancement
        mapped_trees = []
        total_mappings = 0
        successful_mappings = 0
        
        for tree in attack_trees.get("attack_trees", []):
            if "mermaid_code" in tree:
                mapped_tree = await self._map_attack_tree_with_bedrock(
                    tree, techniques, bedrock_model, aws_profile
                )
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
                "techniques_loaded": len(techniques),
                "bedrock_enhanced": True
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
    
    async def _map_attack_tree_with_bedrock(self, tree: Dict[str, Any], techniques: List[Dict[str, Any]],
                                           bedrock_model: str, aws_profile: Optional[str] = None) -> Dict[str, Any]:
        """Map attack tree steps to MITRE ATT&CK techniques using Bedrock"""
        
        attack_steps = tree.get("attack_steps", [])
        if not attack_steps:
            return tree
        
        # Process in batches to manage context window
        batch_size = 3  # Process 3 attack steps at a time
        all_mappings = []
        
        for i in range(0, len(attack_steps), batch_size):
            batch_steps = attack_steps[i:i + batch_size]
            
            # Get top candidate techniques for this batch (limit to manage context)
            candidate_techniques = self._get_candidate_techniques(batch_steps, techniques, max_candidates=20)
            
            # Use Bedrock for enhanced mapping
            batch_mappings = await self._bedrock_map_batch(
                batch_steps, candidate_techniques, tree, bedrock_model, aws_profile
            )
            
            all_mappings.extend(batch_mappings)
        
        # Add mappings to tree
        mapped_tree = tree.copy()
        mapped_tree["ttc_mappings"] = all_mappings
        
        return mapped_tree
    
    def _get_candidate_techniques(self, attack_steps: List[Dict[str, Any]], 
                                 techniques: List[Dict[str, Any]], max_candidates: int = 20) -> List[Dict[str, Any]]:
        """Get candidate techniques using keyword matching to reduce context size"""
        
        # Combine all attack step descriptions
        combined_text = " ".join([step.get("description", "") for step in attack_steps]).lower()
        
        # Score techniques based on keyword overlap
        scored_techniques = []
        
        for technique in techniques:
            technique_text = f"{technique['name']} {technique['description']}".lower()
            
            # Simple scoring based on common words
            words = set(combined_text.split())
            tech_words = set(technique_text.split())
            overlap = len(words.intersection(tech_words))
            
            if overlap > 0:
                scored_techniques.append((overlap, technique))
        
        # Sort by score and return top candidates
        scored_techniques.sort(key=lambda x: x[0], reverse=True)
        return [tech for _, tech in scored_techniques[:max_candidates]]
    
    async def _bedrock_map_batch(self, attack_steps: List[Dict[str, Any]], 
                               candidate_techniques: List[Dict[str, Any]],
                               tree: Dict[str, Any], bedrock_model: str, 
                               aws_profile: Optional[str] = None) -> List[Dict[str, Any]]:
        """Use Bedrock to map a batch of attack steps to techniques"""
        
        if not candidate_techniques:
            return []
        
        # Build compact prompt
        prompt = self._build_ttc_mapping_prompt(attack_steps, candidate_techniques, tree)
        
        try:
            import boto3
            import json
            
            session = boto3.Session(profile_name=aws_profile) if aws_profile else boto3.Session()
            bedrock = session.client('bedrock-runtime', region_name='us-east-1')
            
            body = {
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": 65536,
                "messages": [{"role": "user", "content": prompt}]
            }
            
            response = bedrock.invoke_model(
                modelId=bedrock_model,
                body=json.dumps(body)
            )
            
            response_body = json.loads(response['body'].read())
            generated_content = response_body['content'][0]['text']
            
            # Parse Bedrock response
            return self._parse_bedrock_mappings(generated_content, attack_steps, candidate_techniques)
            
        except Exception as e:
            print(f"Bedrock mapping error: {e}")
            # Fallback to keyword-based mapping
            return self._fallback_keyword_mapping(attack_steps, candidate_techniques)
    
    def _build_ttc_mapping_prompt(self, attack_steps: List[Dict[str, Any]], 
                                 techniques: List[Dict[str, Any]], tree: Dict[str, Any]) -> str:
        """Build compact prompt for TTC mapping"""
        
        # Format attack steps
        steps_text = "\n".join([
            f"- {step.get('node_id', 'unknown')}: {step.get('description', '')}"
            for step in attack_steps
        ])
        
        # Format techniques (compact)
        techniques_text = "\n".join([
            f"- {tech.get('technique_id', 'unknown')}: {tech.get('name', '')} ({', '.join(tech.get('tactics', []))})"
            for tech in techniques[:15]  # Limit to top 15 to manage context
        ])
        
        return f"""You are a cybersecurity expert. Map these attack steps to the most relevant MITRE ATT&CK techniques.

**Attack Steps:**
{steps_text}

**Available MITRE ATT&CK Techniques:**
{techniques_text}

**Instructions:**
For each attack step, identify the 1-2 most relevant techniques. Consider:
- Attack method similarity
- Tactic alignment
- Technical implementation

**Output Format (JSON):**
```json
[
  {{
    "attack_step": "step description",
    "node_id": "step_id",
    "techniques": [
      {{
        "technique_id": "T1234",
        "confidence": 0.85,
        "reasoning": "brief explanation"
      }}
    ]
  }}
]
```

Return only the JSON array."""
    
    def _parse_bedrock_mappings(self, content: str, attack_steps: List[Dict[str, Any]], 
                               techniques: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Parse Bedrock response into mappings"""
        
        import re
        import json
        
        try:
            # Extract JSON from response
            json_match = re.search(r'```json\s*(\[.*?\])\s*```', content, re.DOTALL)
            if json_match:
                mappings_data = json.loads(json_match.group(1))
            else:
                # Try to find JSON array directly
                json_match = re.search(r'(\[.*?\])', content, re.DOTALL)
                if json_match:
                    mappings_data = json.loads(json_match.group(1))
                else:
                    raise ValueError("No JSON found")
            
            # Convert to standard format
            result_mappings = []
            technique_lookup = {tech['technique_id']: tech for tech in techniques}
            
            for mapping in mappings_data:
                attack_step = mapping.get('attack_step', '')
                node_id = mapping.get('node_id', '')
                
                mapped_techniques = []
                for tech_mapping in mapping.get('techniques', []):
                    tech_id = tech_mapping.get('technique_id', '')
                    confidence = tech_mapping.get('confidence', 0.5)
                    
                    if tech_id in technique_lookup:
                        tech_info = technique_lookup[tech_id]
                        mapped_techniques.append({
                            "technique_id": tech_id,
                            "technique_name": tech_info.get('name', ''),
                            "confidence": confidence,
                            "tactics": tech_info.get('tactics', []),
                            "platforms": tech_info.get('platforms', []),
                            "reasoning": tech_mapping.get('reasoning', '')
                        })
                
                if mapped_techniques:
                    result_mappings.append({
                        "attack_step": attack_step,
                        "node_id": node_id,
                        "mapped_techniques": mapped_techniques,
                        "confidence": mapped_techniques[0]["confidence"]
                    })
            
            return result_mappings
            
        except Exception as e:
            print(f"Error parsing Bedrock mappings: {e}")
            return self._fallback_keyword_mapping(attack_steps, techniques)
    
    def _fallback_keyword_mapping(self, attack_steps: List[Dict[str, Any]], 
                                 techniques: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Fallback to keyword-based mapping if Bedrock fails"""
        
        mappings = []
        
        for step in attack_steps:
            step_desc = step.get("description", "").lower()
            best_matches = []
            
            for technique in techniques[:10]:  # Limit for performance
                technique_text = f"{technique['name']} {technique['description']}".lower()
                
                # Simple keyword matching
                common_words = set(step_desc.split()).intersection(set(technique_text.split()))
                if len(common_words) > 0:
                    confidence = min(len(common_words) * 0.2, 0.8)
                    best_matches.append({
                        "technique_id": technique["technique_id"],
                        "technique_name": technique["name"],
                        "confidence": confidence,
                        "tactics": technique["tactics"],
                        "platforms": technique["platforms"]
                    })
            
            if best_matches:
                best_matches.sort(key=lambda x: x["confidence"], reverse=True)
                mappings.append({
                    "attack_step": step_desc,
                    "node_id": step.get("node_id"),
                    "mapped_techniques": best_matches[:2],
                    "confidence": best_matches[0]["confidence"]
                })
        
        return mappings
