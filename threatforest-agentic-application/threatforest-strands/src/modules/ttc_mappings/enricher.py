"""Attack tree enricher with TTC mappings"""
import re
from typing import Dict, List, Any
from pathlib import Path
from ..utils.logger import ThreatForestLogger

class AttackTreeEnricher:
    """Enrich attack trees with TTC technique mappings"""
    
    def __init__(self, matcher):
        """
        Initialize enricher
        
        Args:
            matcher: TTCMatcher instance
        """
        self.matcher = matcher
        self.logger = ThreatForestLogger.get_logger(self.__class__.__name__)
    
    def extract_attack_steps(self, markdown_content: str) -> List[str]:
        """Extract attack steps from mermaid diagram"""
        mermaid_match = re.search(r'```mermaid\n(.*?)\n```', markdown_content, re.DOTALL)
        if not mermaid_match:
            return []
        
        mermaid_content = mermaid_match.group(1)
        steps = []
        for line in mermaid_content.split('\n'):
            matches = re.findall(r'\["([^"]+)"\]', line)
            steps.extend(matches)
        
        return list(set(steps))
    
    def enrich_mermaid_diagram(self, markdown_content: str, matches: List[Dict[str, Any]]) -> str:
        """Add technique IDs to mermaid diagram nodes"""
        step_to_technique = {
            m['attack_step']: m['matches'][0]['technique_id'] 
            for m in matches if m['matches']
        }
        
        def replace_node(match):
            step_text = match.group(1)
            if step_text in step_to_technique:
                tech_id = step_to_technique[step_text]
                return f'["{step_text}<br/><small>{tech_id}</small>"]'
            return match.group(0)
        
        enriched = re.sub(r'\["([^"]+)"\]', replace_node, markdown_content)
        return enriched
    
    def create_technique_table(self, matches: List[Dict[str, Any]]) -> str:
        """Create markdown table of technique mappings"""
        if not matches:
            return ""
        
        table = "\n## TTC Technique Mappings\n\n"
        table += "| Attack Step | Technique ID | Technique Name | Confidence | Similarity |\n"
        table += "|-------------|--------------|----------------|------------|------------|\n"
        
        for match in matches:
            step = match['attack_step']
            if match['matches']:
                best = match['matches'][0]
                confidence_emoji = '🟢' if best['confidence'] == 'high' else '🟡' if best['confidence'] == 'medium' else '🔴'
                table += f"| {step[:50]}... | {best['technique_id']} | {best['name'][:40]}... | {confidence_emoji} {best['confidence']} | {best['similarity']:.3f} |\n"
        
        return table
    
    def enrich_attack_tree(self, markdown_content: str) -> str:
        """
        Enrich attack tree markdown with TTC mappings
        
        Args:
            markdown_content: Original attack tree markdown
            
        Returns:
            Enriched markdown with technique IDs and mapping table
        """
        steps = self.extract_attack_steps(markdown_content)
        if not steps:
            return markdown_content
        
        matches = self.matcher.match_steps(steps)
        
        enriched = self.enrich_mermaid_diagram(markdown_content, matches)
        technique_table = self.create_technique_table(matches)
        
        if technique_table:
            enriched += technique_table
        
        return enriched
    
    def enrich_file(self, input_path: str, output_path: str):
        """
        Enrich attack tree file
        
        Args:
            input_path: Path to input markdown file
            output_path: Path to save enriched file
        """
        with open(input_path, 'r') as f:
            content = f.read()
        
        enriched = self.enrich_attack_tree(content)
        
        with open(output_path, 'w') as f:
            f.write(enriched)
    
    def enrich_directory(self, input_dir: str, output_dir: str, pattern: str = "attack_tree_*.md"):
        """
        Enrich all attack tree files in directory
        
        Args:
            input_dir: Input directory path
            output_dir: Output directory path
            pattern: File pattern to match
        """
        input_path = Path(input_dir)
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        for file_path in input_path.glob(pattern):
            output_file = output_path / f"enriched_{file_path.name}"
            self.enrich_file(str(file_path), str(output_file))
