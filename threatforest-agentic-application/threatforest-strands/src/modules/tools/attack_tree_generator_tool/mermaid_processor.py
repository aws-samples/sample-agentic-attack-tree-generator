"""Mermaid diagram processing utilities"""
import re
from typing import List, Dict


class MermaidProcessor:
    """Processes and cleans Mermaid attack tree diagrams"""
    
    @staticmethod
    def extract_mermaid_code(content: str) -> str:
        """Extract Mermaid code block from generated content
        
        Args:
            content: LLM-generated content that may contain Mermaid
            
        Returns:
            Extracted and cleaned Mermaid code
        """
        # Look for ```mermaid code blocks
        mermaid_pattern = r'```mermaid\s*\n(.*?)\n```'
        match = re.search(mermaid_pattern, content, re.DOTALL)
        
        if match:
            mermaid_code = match.group(1).strip()
            return MermaidProcessor.clean_mermaid_code(mermaid_code)
        
        # Fallback: look for graph TD patterns
        graph_pattern = r'(graph TD.*?)(?=\n\n|\n```|\Z)'
        match = re.search(graph_pattern, content, re.DOTALL)
        
        if match:
            return MermaidProcessor.clean_mermaid_code(match.group(1).strip())
        
        # Last resort: create minimal valid mermaid
        return MermaidProcessor.get_minimal_mermaid()
    
    @staticmethod
    def clean_mermaid_code(mermaid_code: str) -> str:
        """Clean and validate Mermaid code
        
        Args:
            mermaid_code: Raw Mermaid code to clean
            
        Returns:
            Cleaned Mermaid code with proper structure
        """
        if not mermaid_code.strip():
            return MermaidProcessor.get_minimal_mermaid()
        
        lines = mermaid_code.split('\n')
        cleaned_lines = []
        
        # Ensure it starts with graph TD
        if not lines[0].strip().startswith('graph TD'):
            cleaned_lines.append('graph TD')
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            # Skip duplicate graph TD declarations
            if line.startswith('graph TD') and cleaned_lines and cleaned_lines[0] == 'graph TD':
                continue
                
            # Clean node definitions - remove problematic characters
            if '[' in line and ']' in line:
                # Fix quotes and special characters that break Mermaid
                line = re.sub(r'["""]', '"', line)  # Normalize quotes
                line = re.sub(r'[^\w\s\[\]"().,;:!?\-\>]', '', line)  # Remove invalid chars
                
            cleaned_lines.append(line)
        
        # Rebuild with proper indentation
        result_lines = [cleaned_lines[0]]  # graph TD
        for line in cleaned_lines[1:]:
            if line.startswith('classDef') or line.startswith('class '):
                result_lines.append('    ' + line)
            else:
                result_lines.append('    ' + line)
        
        mermaid_code = '\n'.join(result_lines)
        
        # Ensure it has all class definitions
        if 'classDef attack' not in mermaid_code:
            mermaid_code += '\n\n    classDef attack fill:#ffcccc'
        if 'classDef mitigation' not in mermaid_code:
            mermaid_code += '\n    classDef mitigation fill:#ccffcc'
        if 'classDef goal' not in mermaid_code:
            mermaid_code += '\n    classDef goal fill:#ffcc99'
        if 'classDef fact' not in mermaid_code:
            mermaid_code += '\n    classDef fact fill:#ccccff'
        
        return mermaid_code
    
    @staticmethod
    def get_minimal_mermaid() -> str:
        """Get minimal valid Mermaid diagram
        
        Returns:
            Basic valid Mermaid attack tree
        """
        return """graph TD
    goal["Attack Goal"]
    step1["Attack Step"]
    
    goal --> step1
    
    classDef attack fill:#ffcccc
    classDef mitigation fill:#ccffcc
    classDef goal fill:#ffcc99
    classDef fact fill:#ccccff
    
    class goal goal
    class step1 attack"""
    
    @staticmethod
    def extract_attack_steps(mermaid_code: str) -> List[Dict[str, str]]:
        """Extract attack step nodes from Mermaid code
        
        Args:
            mermaid_code: Mermaid diagram code
            
        Returns:
            List of dicts with node_id and description
        """
        # Extract node definitions: nodeId["text"]
        node_pattern = r'(\w+)\["([^"]+)"\]'
        matches = re.findall(node_pattern, mermaid_code)
        
        return [{"node_id": node_id, "description": desc} for node_id, desc in matches]
