"""Attack tree validation utilities"""
from typing import Dict, Any


class TreeValidator:
    """Validates attack tree structure and completeness"""
    
    @staticmethod
    def validate_attack_tree(mermaid_code: str, threat: Dict[str, Any],
                            project_info: Dict[str, Any]) -> Dict[str, Any]:
        """Validate the generated attack tree for completeness and correctness
        
        Args:
            mermaid_code: Generated Mermaid code
            threat: Original threat dict
            project_info: Project information
            
        Returns:
            Dict with validation results (is_valid, errors, warnings, metrics)
        """
        errors = []
        warnings = []
        
        # Check basic structure
        if not mermaid_code.strip().startswith('graph TD'):
            errors.append("Missing 'graph TD' declaration")
        
        # Check for required class definitions
        required_classes = ['classDef attack', 'classDef goal', 'classDef fact']
        for class_def in required_classes:
            if class_def not in mermaid_code:
                errors.append(f"Missing required class definition: {class_def}")
        
        # Count node classifications
        node_types = TreeValidator._count_node_types(mermaid_code)
        
        # Validate minimum node counts
        if node_types['attack'] == 0:
            errors.append("No attack nodes classified")
        elif node_types['attack'] < 3:
            warnings.append(f"Only {node_types['attack']} attack nodes (recommended: 5+)")
            
        if node_types['goal'] == 0:
            errors.append("No goal nodes classified")
            
        if node_types['fact'] == 0:
            errors.append("No fact nodes classified")
        elif node_types['fact'] < 2:
            warnings.append(f"Only {node_types['fact']} fact nodes (recommended: 3+)")
        
        # Check for connections
        connections = len([line for line in mermaid_code.split('\n') if '-->' in line])
        if connections < 5:
            warnings.append(f"Only {connections} connections (recommended: 10+)")
        
        # Check for technology-specific content
        technologies = project_info.get('technologies', [])
        tech_mentions = sum(1 for tech in technologies[:5] if tech.lower() in mermaid_code.lower())
        if tech_mentions == 0 and technologies:
            warnings.append("No technology-specific attack steps identified")
        
        return {
            'is_valid': len(errors) == 0,
            'errors': errors,
            'warnings': warnings,
            'node_counts': node_types,
            'connection_count': connections,
            'tech_mentions': tech_mentions
        }
    
    @staticmethod
    def _count_node_types(mermaid_code: str) -> Dict[str, int]:
        """Count nodes by type in Mermaid code
        
        Args:
            mermaid_code: Mermaid diagram code
            
        Returns:
            Dict with counts for each node type
        """
        return {
            'attack': len([line for line in mermaid_code.split('\n') 
                          if 'class ' in line and 'attack' in line]),
            'goal': len([line for line in mermaid_code.split('\n') 
                        if 'class ' in line and 'goal' in line]),
            'fact': len([line for line in mermaid_code.split('\n') 
                        if 'class ' in line and 'fact' in line]),
            'mitigation': len([line for line in mermaid_code.split('\n') 
                             if 'class ' in line and 'mitigation' in line])
        }
