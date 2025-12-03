"""Parser for attack tree markdown files"""
import re
from typing import Dict, List, Any, Tuple
from ..utils.logger import ThreatForestLogger


class AttackTreeParser:
    """Parses attack tree markdown files to extract graph structure and TTC data"""
    
    def __init__(self):
        self.logger = ThreatForestLogger.get_logger(self.__class__.__name__)
    
    def parse_file(self, markdown_path: str) -> Dict[str, Any]:
        """
        Parse attack tree markdown file
        
        Args:
            markdown_path: Path to attack tree markdown file
            
        Returns:
            Dictionary containing parsed data
        """
        with open(markdown_path, 'r') as f:
            content = f.read()
        
        return self.parse_content(content)
    
    def parse_content(self, content: str) -> Dict[str, Any]:
        """
        Parse attack tree markdown content
        
        Args:
            content: Markdown content string
            
        Returns:
            Dictionary with nodes, edges, techniques, and mitigations
        """
        # Extract metadata
        threat_id = self._extract_threat_id(content)
        threat_statement = self._extract_threat_statement(content)
        category = self._extract_category(content)
        
        # Extract Mermaid diagram
        mermaid_code = self._extract_mermaid(content)
        
        # Parse graph structure from Mermaid
        nodes, edges, node_classes = self._parse_mermaid(mermaid_code)
        
        # Extract TTC mappings
        ttc_mappings = self._extract_ttc_mappings(content)
        
        return {
            'metadata': {
                'threat_id': threat_id,
                'threat_statement': threat_statement,
                'category': category
            },
            'nodes': nodes,
            'edges': edges,
            'node_classes': node_classes,
            'ttc_mappings': ttc_mappings
        }
    
    def _extract_threat_id(self, content: str) -> str:
        """Extract threat ID from markdown"""
        match = re.search(r'\*\*Threat ID\*\*:\s*(\w+)', content)
        return match.group(1) if match else 'unknown'
    
    def _extract_threat_statement(self, content: str) -> str:
        """Extract threat statement from markdown"""
        match = re.search(r'\*\*Statement\*\*:\s*(.+?)(?:\n|$)', content)
        return match.group(1).strip() if match else ''
    
    def _extract_category(self, content: str) -> str:
        """Extract category from markdown"""
        match = re.search(r'# Attack Tree:\s*(.+?)(?:\n|$)', content)
        return match.group(1).strip() if match else 'Unknown'
    
    def _extract_mermaid(self, content: str) -> str:
        """Extract Mermaid code block"""
        match = re.search(r'```mermaid\n(.*?)\n```', content, re.DOTALL)
        return match.group(1) if match else ''
    
    def _parse_mermaid(self, mermaid_code: str) -> Tuple[Dict, List, Dict]:
        """
        Parse Mermaid graph syntax to extract nodes and edges
        
        Returns:
            Tuple of (nodes_dict, edges_list, node_classes_dict)
        """
        nodes = {}
        edges = []
        node_classes = {}
        
        lines = mermaid_code.strip().split('\n')
        
        for line in lines:
            line = line.strip()
            
            # Skip graph declaration and empty lines
            if not line or line.startswith('graph ') or line.startswith('classDef'):
                continue
            
            # Parse class assignments (e.g., "class B,C,D attack")
            if line.startswith('class '):
                self._parse_class_assignment(line, node_classes)
                continue
            
            # Parse node connections (e.g., 'A["text"] --> B["text"]')
            if '-->' in line:
                self._parse_connection(line, nodes, edges)
        
        return nodes, edges, node_classes
    
    def _parse_class_assignment(self, line: str, node_classes: Dict):
        """Parse class assignment line"""
        # Example: "class B,C,D,E attack"
        match = re.match(r'class\s+([\w,]+)\s+(\w+)', line)
        if match:
            node_ids = match.group(1).split(',')
            class_name = match.group(2)
            
            for node_id in node_ids:
                node_classes[node_id.strip()] = class_name
    
    def _parse_connection(self, line: str, nodes: Dict, edges: List):
        """Parse connection line and extract nodes"""
        # Match pattern: ID["label"] --> ID["label"] or ID --> ID
        parts = line.split('-->')
        
        if len(parts) != 2:
            return
        
        from_part = parts[0].strip()
        to_part = parts[1].strip()
        
        # Extract node info from each part
        from_id, from_label = self._extract_node_info(from_part)
        to_id, to_label = self._extract_node_info(to_part)
        
        if from_id and to_id:
            # Add nodes if not already present
            if from_id not in nodes:
                nodes[from_id] = {'id': from_id, 'label': from_label}
            if to_id not in nodes:
                nodes[to_id] = {'id': to_id, 'label': to_label}
            
            # Add edge
            edges.append({'from': from_id, 'to': to_id})
    
    def _extract_node_info(self, node_str: str) -> Tuple[str, str]:
        """Extract node ID and label from string"""
        # Try to match: ID["label"]
        match = re.match(r'(\w+)\["(.+?)"\]', node_str)
        if match:
            return match.group(1), match.group(2)
        
        # Try to match: ID only
        match = re.match(r'(\w+)', node_str)
        if match:
            node_id = match.group(1)
            return node_id, node_id
        
        return None, None
    
    def _extract_ttc_mappings(self, content: str) -> List[Dict[str, Any]]:
        """Extract TTC technique mappings from markdown"""
        mappings = []
        
        # Find MITRE ATT&CK Mapping section
        mapping_section_match = re.search(
            r'## MITRE ATT&CK Mapping\s*\n\n(.*?)(?=\n##|\n\*Total technique mappings|\Z)',
            content,
            re.DOTALL
        )
        
        if not mapping_section_match:
            return mappings
        
        mapping_section = mapping_section_match.group(1)
        
        # Split by ### headers (each attack step)
        step_sections = re.split(r'\n### ', mapping_section)
        
        for section in step_sections:
            if not section.strip():
                continue
            
            mapping = self._parse_ttc_section(section)
            if mapping:
                mappings.append(mapping)
        
        return mappings
    
    def _parse_ttc_section(self, section: str) -> Dict[str, Any]:
        """Parse a single TTC mapping section"""
        lines = section.split('\n')
        
        # First line is the attack step
        attack_step = lines[0].strip()
        
        # Extract technique info
        technique_match = re.search(r'\[([^\]]+)\]\(([^)]+)\)\s*(?:-\s*(.+))?', section)
        if not technique_match:
            return None
        
        technique_id = technique_match.group(1)
        technique_url = technique_match.group(2)
        technique_name = technique_match.group(3).strip() if technique_match.group(3) else ''
        
        # Extract tactic
        tactic_match = re.search(r'\*\*Tactic\*\*:\s*(.+)', section)
        tactics = [tactic_match.group(1).strip()] if tactic_match else []
        
        # Extract similarity score
        similarity = 0.0
        score_match = re.search(r'\*\*Similarity Score\*\*:\s*([\d.]+)%', section)
        if score_match:
            similarity = float(score_match.group(1)) / 100.0
        else:
            # Try normalized format
            score_match = re.search(r'\*\*Similarity Score\*\*:\s*([\d.]+)%\s*\(normalized from', section)
            if score_match:
                similarity = float(score_match.group(1)) / 100.0
        
        # Extract mitigations
        mitigations = []
        mitigation_section = re.search(r'\*\*Mitigations \((\d+)\):\*\*(.*?)(?=\n### |\n\n\*Total|\Z)', section, re.DOTALL)
        if mitigation_section:
            mit_count = int(mitigation_section.group(1))
            mit_text = mitigation_section.group(2)
            
            # Parse individual mitigations
            mit_blocks = re.findall(r'🛡️\s*\*\*([^*]+)\*\*\s*\n\s*(.+?)(?=\n\s*-\s*🛡️|\n\s*-\s*\*\d+|\Z)', mit_text, re.DOTALL)
            
            for mit_name, mit_desc in mit_blocks:
                mitigations.append({
                    'name': mit_name.strip(),
                    'description': mit_desc.strip()
                })
        
        return {
            'attack_step': attack_step,
            'technique_id': technique_id,
            'technique_name': technique_name,
            'technique_url': technique_url,
            'tactics': tactics,
            'similarity': similarity,
            'mitigations': mitigations
        }
