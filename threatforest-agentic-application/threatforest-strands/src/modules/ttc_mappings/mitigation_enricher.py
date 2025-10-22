"""Enrich attack trees with mitigations from STIX bundle"""
import json
from typing import Dict, List, Any, Optional
from pathlib import Path
from ..utils.logger import ThreatForestLogger


class MitigationEnricher:
    """Add mitigations to attack tree nodes based on TTC technique IDs"""
    
    def __init__(self, stix_bundle_path: str):
        """
        Initialize enricher with STIX bundle
        
        Args:
            stix_bundle_path: Path to AAF STIX bundle JSON
        """
        self.stix_bundle_path = stix_bundle_path
        self.attack_patterns = {}
        self.mitigations = {}
        self.mitigation_map = {}
        self.logger = ThreatForestLogger.get_logger(self.__class__.__name__)
        self._load_stix_data()
    
    def _load_stix_data(self):
        """Load and index STIX bundle data"""
        with open(self.stix_bundle_path, 'r') as f:
            bundle = json.load(f)
        
        # Index attack patterns by ID
        for obj in bundle.get('objects', []):
            if obj.get('type') == 'attack-pattern':
                self.attack_patterns[obj['id']] = obj
            elif obj.get('type') == 'course-of-action':
                self.mitigations[obj['id']] = obj
        
        # Build mitigation map: attack_pattern_id -> [mitigation_objects]
        for obj in bundle.get('objects', []):
            if obj.get('type') == 'relationship' and obj.get('relationship_type') == 'mitigates':
                target_id = obj['target_ref']
                source_id = obj['source_ref']
                
                if target_id not in self.mitigation_map:
                    self.mitigation_map[target_id] = []
                
                if source_id in self.mitigations:
                    self.mitigation_map[target_id].append(self.mitigations[source_id])
    
    def get_mitigations_for_technique(self, technique_id: str) -> List[Dict[str, Any]]:
        """
        Get mitigations for a technique ID
        
        Args:
            technique_id: TTC technique ID (e.g., "T1110.001")
            
        Returns:
            List of mitigation objects
        """
        # Find attack pattern with this technique ID
        for pattern_id, pattern in self.attack_patterns.items():
            aliases = pattern.get('aliases', [])
            if technique_id in aliases:
                return self.mitigation_map.get(pattern_id, [])
        
        return []
    
    def enrich_attack_tree(self, attack_tree: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich attack tree with mitigations
        
        Args:
            attack_tree: Attack tree dictionary with nodes
            
        Returns:
            Enriched attack tree with mitigation nodes inserted
        """
        enriched = attack_tree.copy()
        
        if 'nodes' not in enriched:
            return enriched
        
        new_nodes = []
        node_id_counter = max([n.get('id', 0) for n in enriched['nodes']], default=0) + 1
        
        for node in enriched['nodes']:
            new_nodes.append(node)
            
            # Check if node has technique_id
            technique_id = node.get('technique_id')
            if not technique_id:
                continue
            
            # Get mitigations
            mitigations = self.get_mitigations_for_technique(technique_id)
            if not mitigations:
                continue
            
            # Add mitigation nodes after this attack step
            for mitigation in mitigations:
                mitigation_node = {
                    'id': node_id_counter,
                    'label': f"🛡️ {mitigation['name']}",
                    'description': mitigation.get('description', ''),
                    'type': 'mitigation',
                    'parent_id': node.get('id'),
                    'style': 'fill:#ADD8E6,stroke:#4682B4,stroke-width:2px'  # Blue box
                }
                new_nodes.append(mitigation_node)
                node_id_counter += 1
        
        enriched['nodes'] = new_nodes
        return enriched
    
    def enrich_mermaid(self, mermaid_content: str, attack_tree: Dict[str, Any]) -> str:
        """
        Add mitigation nodes to Mermaid diagram
        
        Args:
            mermaid_content: Original Mermaid diagram content
            attack_tree: Enriched attack tree with mitigation nodes
            
        Returns:
            Mermaid content with mitigation nodes
        """
        lines = mermaid_content.split('\n')
        result = []
        
        # Keep header
        for line in lines:
            result.append(line)
            if line.strip().startswith('graph'):
                break
        
        # Add all nodes including mitigations
        node_map = {n['id']: n for n in attack_tree.get('nodes', [])}
        
        for node in attack_tree.get('nodes', []):
            node_id = node['id']
            label = node.get('label', '')
            node_type = node.get('type', 'attack')
            
            if node_type == 'mitigation':
                # Blue box for mitigation
                result.append(f"    {node_id}[\"{label}\"]")
                result.append(f"    style {node_id} {node.get('style', '')}")
                
                # Link from parent attack step to mitigation
                parent_id = node.get('parent_id')
                if parent_id:
                    result.append(f"    {parent_id} --> {node_id}")
                    
                    # Find next attack step (sibling of parent)
                    for next_node in attack_tree.get('nodes', []):
                        if next_node.get('parent_id') == parent_id and next_node['id'] > node_id:
                            result.append(f"    {node_id} -.->|mitigates| {next_node['id']}")
                            break
            else:
                # Regular attack step
                result.append(f"    {node_id}[\"{label}\"]")
        
        return '\n'.join(result)
