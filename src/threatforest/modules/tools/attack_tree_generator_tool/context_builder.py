"""Context building utilities for attack tree generation"""
from typing import Dict, Any


class ContextBuilder:
    """Builds enhanced context for attack tree generation prompts"""
    
    @staticmethod
    def build_enhanced_context(project_info: Dict[str, Any]) -> str:
        """Build enhanced context from project information
        
        Args:
            project_info: Dict with project metadata
            
        Returns:
            Formatted context string for prompts
        """
        context_parts = []
        
        # Add application context
        if project_info.get('application_name'):
            context_parts.append(f"**Application**: {project_info['application_name']}")
        
        if project_info.get('description'):
            context_parts.append(f"**Description**: {project_info['description']}")
        
        if project_info.get('industry'):
            context_parts.append(f"**Industry**: {project_info['industry']}")
        
        # Add technology stack
        technologies = project_info.get('technologies', [])
        if technologies:
            context_parts.append(f"**Technologies**: {', '.join(technologies[:15])}")
        
        # Add architecture information if available
        if project_info.get('architecture_info'):
            context_parts.append(f"**Architecture**: {project_info['architecture_info']}")
        
        # Add data flow information
        if project_info.get('data_flows'):
            context_parts.append(f"**Data Flows**: {project_info['data_flows']}")
        
        # Add security controls
        if project_info.get('security_controls'):
            context_parts.append(f"**Security Controls**: {project_info['security_controls']}")
        
        # Add component information
        if project_info.get('components'):
            context_parts.append(f"**Components**: {', '.join(project_info['components'][:10])}")
        
        return "\n".join(context_parts) if context_parts else "No additional context available"
    
    @staticmethod
    def build_user_prompt(threat: Dict[str, Any], project_info: Dict[str, Any]) -> str:
        """Build complete user prompt for attack tree generation
        
        Args:
            threat: Threat dict with statement and metadata
            project_info: Project information dict
            
        Returns:
            Formatted user prompt for Strands agent
        """
        # Build enhanced context
        context_info = ContextBuilder.build_enhanced_context(project_info)
        
        # Build structured threat details if available
        threat_details = ""
        if threat.get('threatSource') or threat.get('prerequisites'):
            threat_details = f"""
**Threat Source**: {threat.get('threatSource', 'Unknown')}
**Prerequisites**: {threat.get('prerequisites', 'None specified')}
**Threat Action**: {threat.get('threatAction', 'Unknown')}
**Threat Impact**: {threat.get('threatImpact', 'Unknown')}
**Impacted Goal**: {threat.get('impactedGoal', 'Unknown')}
**Impacted Assets**: {threat.get('impactedAssets', 'Unknown')}
"""
        
        # Build the threat-specific user prompt
        user_prompt = f"""
## Threat to Analyze:
**ID**: {threat.get('id', 'Unknown')}
**Statement**: {threat.get('statement', threat.get('description', 'No statement provided'))}
**Priority**: {threat.get('priority', threat.get('severity', 'Unknown'))}
**Category**: {threat.get('category', 'Unknown')}
{threat_details}

## Context Information:
**Application**: {project_info.get('application_name', 'Unknown Application')}
**Technologies**: {', '.join(project_info.get('technologies', [])[:10])}
**Architecture**: {project_info.get('architecture_type', 'Unknown')}
**Deployment**: {project_info.get('deployment_environment', 'Unknown')}

## Enhanced Context Information:
{context_info}

Generate a SINGLE Mermaid attack tree diagram for this threat only.
"""
        
        return user_prompt.strip()
