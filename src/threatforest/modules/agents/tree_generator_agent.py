"""Core attack tree generation using Strands Agent"""
from typing import Dict, Any
from ..core import BaseAgent
from ..workflow.attack_tree_generator.context_builder import ContextBuilder
from ..workflow.attack_tree_generator.mermaid_processor import MermaidProcessor
from ..workflow.attack_tree_generator.tree_validator import TreeValidator


class TreeGenerator(BaseAgent):
    """Generates attack trees using Strands Agent"""
    
    def __init__(self, logger):
        """Initialize generator
        
        Args:
            logger: Logger instance
        """
        self.logger = logger
        self.context_builder = ContextBuilder()
        self.mermaid_processor = MermaidProcessor()
        self.validator = TreeValidator()
    
    def generate_attack_tree(self, threat: Dict[str, Any], project_info: Dict[str, Any],
                            bedrock_model: str) -> Dict[str, Any]:
        """Generate attack tree for a specific threat using Strands
        
        Args:
            threat: Threat dict with statement and metadata
            project_info: Project information dict
            bedrock_model: Bedrock model ID
            
        Returns:
            Dict with mermaid_code, attack_steps, validation, or error
        """
        try:
            # Create Strands agent with generate-attack-trees.md as system prompt
            agent = self.get_strands_agent('generate-attack-trees.md')
            
            # Build threat-specific user prompt
            user_prompt = self.context_builder.build_user_prompt(threat, project_info)
            
            # Run Strands agent (synchronous)
            result = agent(user_prompt)
            generated_content = str(result)
            
            # Extract Mermaid code from response
            self.logger.debug(f"Generated content length: {len(generated_content)} characters")
            mermaid_code = self.mermaid_processor.extract_mermaid_code(generated_content)
            self.logger.debug(f"Extracted Mermaid code length: {len(mermaid_code)} characters")
            
            # Validate the generated attack tree
            validation_result = self.validator.validate_attack_tree(mermaid_code, threat, project_info)
            self.logger.debug(f"Validation result: {validation_result}")
            
            # Only fail on critical errors, allow warnings to pass
            critical_errors = [error for error in validation_result.get('errors', []) 
                             if 'Missing \'graph TD\' declaration' in error or 
                                'No attack nodes classified' in error]
            
            if critical_errors:
                self.logger.error(f"Attack tree validation failed: {critical_errors}")
                return {
                    "threat_id": threat.get("id"),
                    "error": f"Attack tree validation failed: {critical_errors}"
                }
            
            # Mark as valid even with non-critical errors/warnings
            validation_result['is_valid'] = True
            if validation_result.get('errors'):
                self.logger.warning(f"Attack tree has non-critical issues: {validation_result['errors']}")
            
            self.logger.info(f"Attack tree generated successfully for threat {threat.get('id')}")
            
            return {
                "threat_id": threat.get("id"),
                "threat_category": threat.get("category"),
                "threat_description": threat.get("description"),
                "threat_statement": threat.get("statement", threat.get("description", "")),
                "threat_action": threat.get("threat_action", threat.get("threatAction", "")),
                "threatSource": threat.get("threatSource", ""),
                "prerequisites": threat.get("prerequisites", ""),
                "threatAction": threat.get("threatAction", ""),
                "threatImpact": threat.get("threatImpact", ""),
                "impactedGoal": threat.get("impactedGoal", ""),
                "impactedAssets": threat.get("impactedAssets", ""),
                "priority": threat.get("priority", threat.get("severity", "")),
                "mermaid_code": mermaid_code,
                "attack_steps": self.mermaid_processor.extract_attack_steps(mermaid_code),
                "generated_content": generated_content,
                "validation": validation_result
            }
            
        except Exception as e:
            self.logger.error(f"Attack tree generation error: {str(e)}")
            return {
                "threat_id": threat.get("id"),
                "error": f"Attack tree generation failed: {str(e)}"
            }
