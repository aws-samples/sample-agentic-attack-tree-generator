"""Report formatting utilities"""
from typing import List, Dict, Any


class ReportFormatters:
    """Static formatting helpers for reports"""
    
    @staticmethod
    def format_technologies(technologies: List[str]) -> str:
        if not technologies:
            return "- No technologies identified"
        return '\n'.join(f'- {tech}' for tech in technologies)
    
    @staticmethod
    def format_security_objectives(objectives: List[str]) -> str:
        """Format security objectives (guaranteed list from ProjectInfo model)"""
        if not objectives:
            return "- Security objectives not specified"
        
        return '\n'.join(f'- {obj}' for obj in objectives)
    
    @staticmethod
    def format_high_severity_threats(threats: List[Dict[str, Any]]) -> str:
        if not threats:
            return "No high severity threats identified."
        
        result = []
        for i, threat in enumerate(threats, 1):
            threat_id = threat.get('id', 'Unknown')
            description = threat.get('description', threat.get('category', ''))
            
            if '**Threat Statement**:' in description:
                statement = description.split('\n')[0].replace('**Threat Statement**:', '').strip()
            else:
                statement = description
            
            result.append(f"{i}. **{threat_id}**: {statement}")
            result.append("")
            result.append("---")
        
        return '\n'.join(result)
    
    @staticmethod
    def format_attack_trees_summary(trees: List[Dict[str, Any]]) -> str:
        if not trees:
            return "No attack trees generated."
        
        result = []
        for tree in trees:
            threat_id = tree.get('threat_id', 'Unknown')
            category = tree.get('threat_category', 'Unknown')
            mappings = len(tree.get('ttc_mappings', []))
            result.append(f"- **{threat_id}**: {category} ({mappings} TTC mappings)")
        return '\n'.join(result)
    
    @staticmethod
    def format_failed_trees(failed: List[Dict[str, Any]]) -> str:
        if not failed:
            return ""
        
        result = ["### Failed Attack Tree Generation", ""]
        result.append("⚠️ The following threats could not generate attack trees:")
        result.append("")
        
        for tree in failed:
            threat_id = tree.get('threat_id', 'Unknown')
            error = tree.get('error', 'Unknown error')
            if 'Throttling' in error or 'throttling' in error:
                error_type = "API throttling/rate limiting"
            elif 'ValidationException' in error:
                error_type = "Model validation error"
            else:
                error_type = "Generation error"
            result.append(f"- **{threat_id}**: {error_type}")
        
        result.append("")
        result.append("**Recommendation**: Re-run ThreatForest to retry failed threats.")
        return '\n'.join(result)
