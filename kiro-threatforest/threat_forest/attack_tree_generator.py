"""
Attack tree generation system using LLM and Mermaid format.
"""

import re
from typing import List, Dict, Any, Optional
from pathlib import Path

from .models import ThreatStatement, AttackTree, AttackStep, ApplicationInfo
from .llm_client import LLMClient, LLMResponse
from .exceptions import LLMError, MermaidValidationError
from .utils import get_logger, sanitize_filename


class MermaidValidator:
    """Validates and fixes Mermaid diagram syntax."""
    
    def __init__(self):
        self.logger = get_logger(__name__)
    
    def validate_mermaid(self, content: str) -> bool:
        """
        Validate basic Mermaid syntax.
        
        Args:
            content: Mermaid diagram content
            
        Returns:
            True if valid, False otherwise
        """
        try:
            lines = content.strip().split('\n')
            
            # Check for required elements
            has_graph_declaration = False
            has_nodes = False
            has_connections = False
            
            for line in lines:
                line = line.strip()
                if not line or line.startswith('```'):
                    continue
                
                # Check for graph declaration
                if line.startswith('graph ') or line.startswith('flowchart '):
                    has_graph_declaration = True
                
                # Check for node definitions
                if '[' in line and ']' in line:
                    has_nodes = True
                
                # Check for connections
                if '-->' in line:
                    has_connections = True
            
            if not has_graph_declaration:
                self.logger.warning("Mermaid diagram missing graph declaration")
                return False
            
            if not has_nodes:
                self.logger.warning("Mermaid diagram has no nodes")
                return False
            
            if not has_connections:
                self.logger.warning("Mermaid diagram has no connections")
                return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error validating Mermaid syntax: {e}")
            return False
    
    def fix_common_issues(self, content: str) -> str:
        """
        Fix common Mermaid syntax issues.
        
        Args:
            content: Original Mermaid content
            
        Returns:
            Fixed Mermaid content
        """
        lines = content.strip().split('\n')
        fixed_lines = []
        
        for line in lines:
            line = line.strip()
            
            # Skip empty lines and code blocks
            if not line or line.startswith('```'):
                if line:
                    fixed_lines.append(line)
                continue
            
            # Fix graph declaration
            if line.startswith('graph') and not line.startswith('graph TD'):
                line = 'graph TD'
            
            # Fix node syntax - ensure proper quotes
            if '[' in line and ']' in line and '-->' not in line:
                # This is likely a node definition
                line = self._fix_node_syntax(line)
            
            # Fix connection syntax
            if '-->' in line:
                line = self._fix_connection_syntax(line)
            
            fixed_lines.append(line)
        
        return '\n'.join(fixed_lines)
    
    def _fix_node_syntax(self, line: str) -> str:
        """Fix node definition syntax."""
        # Pattern: node_id["text"] or node_id[text]
        pattern = r'(\w+)\[(.*?)\]'
        match = re.search(pattern, line)
        
        if match:
            node_id, text = match.groups()
            # Ensure text is properly quoted
            if not (text.startswith('"') and text.endswith('"')):
                text = f'"{text}"'
            return f'{node_id}[{text}]'
        
        return line
    
    def _fix_connection_syntax(self, line: str) -> str:
        """Fix connection syntax."""
        # Ensure proper spacing around arrows
        line = re.sub(r'\s*-->\s*', ' --> ', line)
        return line
    
    def apply_styling(self, content: str, attack_steps: List[AttackStep]) -> str:
        """
        Apply CSS styling classes to Mermaid diagram.
        
        Args:
            content: Mermaid diagram content
            attack_steps: List of attack steps with node types
            
        Returns:
            Styled Mermaid content
        """
        lines = content.strip().split('\n')
        
        # Group nodes by type
        node_types = {
            'attack': [],
            'mitigation': [],
            'goal': [],
            'fact': []
        }
        
        for step in attack_steps:
            if step.node_type in node_types:
                node_types[step.node_type].append(step.id)
        
        # Add styling at the end
        styling_lines = [
            '',
            'classDef attack fill:#ffcccc',
            'classDef mitigation fill:#ccffcc',
            'classDef goal fill:#ffcc99',
            'classDef fact fill:#ccccff',
            ''
        ]
        
        # Add class assignments
        for node_type, nodes in node_types.items():
            if nodes:
                node_list = ','.join(nodes)
                styling_lines.append(f'class {node_list} {node_type}')
        
        return '\n'.join(lines + styling_lines)


class AttackTreeGenerator:
    """Generates attack trees using LLM and validates Mermaid output."""
    
    def __init__(self, llm_client: LLMClient, output_directory: str):
        self.llm_client = llm_client
        self.output_directory = Path(output_directory)
        self.validator = MermaidValidator()
        self.logger = get_logger(__name__)
    
    def generate_attack_trees(
        self, 
        threats: List[ThreatStatement], 
        app_info: ApplicationInfo
    ) -> List[AttackTree]:
        """
        Generate attack trees for a list of threats.
        
        Args:
            threats: List of threat statements
            app_info: Application context information
            
        Returns:
            List of generated AttackTree objects
        """
        self.logger.info(f"Generating attack trees for {len(threats)} threats")
        
        attack_trees = []
        app_context = self._prepare_app_context(app_info)
        
        for threat in threats:
            try:
                attack_tree = self.generate_single_attack_tree(threat, app_context)
                if attack_tree:
                    attack_trees.append(attack_tree)
                    self.logger.info(f"Generated attack tree for: {threat.title}")
                else:
                    self.logger.warning(f"Failed to generate attack tree for: {threat.title}")
            except Exception as e:
                self.logger.error(f"Error generating attack tree for {threat.title}: {e}")
        
        self.logger.info(f"Successfully generated {len(attack_trees)} attack trees")
        return attack_trees
    
    def generate_single_attack_tree(
        self, 
        threat: ThreatStatement, 
        app_context: str
    ) -> Optional[AttackTree]:
        """
        Generate a single attack tree for a threat.
        
        Args:
            threat: Threat statement
            app_context: Application context string
            
        Returns:
            AttackTree object or None if generation failed
        """
        try:
            # Create prompt for attack tree generation
            prompt = self.llm_client.create_attack_tree_prompt(
                threat.__dict__, 
                app_context
            )
            
            # Generate attack tree with retries
            mermaid_content = None
            for attempt in range(3):
                try:
                    response = self.llm_client.generate(prompt)
                    
                    # Extract Mermaid content from response
                    mermaid_content = self._extract_mermaid_content(response.content)
                    
                    if mermaid_content and self.validator.validate_mermaid(mermaid_content):
                        break
                    else:
                        self.logger.warning(f"Invalid Mermaid generated (attempt {attempt + 1})")
                        if attempt < 2:
                            # Modify prompt for retry
                            prompt += "\n\nPlease ensure the output is valid Mermaid syntax with proper node and connection definitions."
                
                except LLMError as e:
                    self.logger.warning(f"LLM error on attempt {attempt + 1}: {e}")
                    if attempt == 2:
                        raise
            
            if not mermaid_content:
                raise MermaidValidationError("Failed to generate valid Mermaid content after 3 attempts")
            
            # Fix common issues
            mermaid_content = self.validator.fix_common_issues(mermaid_content)
            
            # Parse attack steps from Mermaid content
            attack_steps = self._parse_attack_steps(mermaid_content)
            
            # Apply styling
            mermaid_content = self.validator.apply_styling(mermaid_content, attack_steps)
            
            # Create file path
            filename = f"{threat.id}-attack-tree.md"
            file_path = self.output_directory / "attack_trees" / filename
            
            # Create AttackTree object
            attack_tree = AttackTree(
                threat_id=threat.id,
                title=threat.title,
                mermaid_content=mermaid_content,
                attack_steps=attack_steps,
                file_path=str(file_path)
            )
            
            # Save to file
            self._save_attack_tree(attack_tree, threat)
            
            return attack_tree
            
        except Exception as e:
            self.logger.error(f"Failed to generate attack tree: {e}")
            return None
    
    def _prepare_app_context(self, app_info: ApplicationInfo) -> str:
        """Prepare application context string for prompts."""
        context_parts = [
            f"Application: {app_info.name}",
            f"Description: {app_info.description}",
        ]
        
        if app_info.technologies:
            context_parts.append(f"Technologies: {', '.join(app_info.technologies)}")
        
        if app_info.programming_languages:
            context_parts.append(f"Languages: {', '.join(app_info.programming_languages)}")
        
        if app_info.sector:
            context_parts.append(f"Sector: {app_info.sector}")
        
        if app_info.security_objectives:
            context_parts.append(f"Security Priorities: {', '.join(app_info.security_objectives)}")
        
        return '\n'.join(context_parts)
    
    def _extract_mermaid_content(self, response_content: str) -> Optional[str]:
        """Extract Mermaid diagram from LLM response."""
        # Look for code blocks with mermaid
        mermaid_pattern = r'```mermaid\s*\n(.*?)\n```'
        match = re.search(mermaid_pattern, response_content, re.DOTALL)
        
        if match:
            return match.group(1).strip()
        
        # Look for code blocks without language specification
        code_pattern = r'```\s*\n(.*?)\n```'
        match = re.search(code_pattern, response_content, re.DOTALL)
        
        if match:
            content = match.group(1).strip()
            # Check if it looks like Mermaid
            if content.startswith('graph ') or content.startswith('flowchart '):
                return content
        
        # Look for content that starts with graph/flowchart
        lines = response_content.split('\n')
        mermaid_lines = []
        in_mermaid = False
        
        for line in lines:
            line = line.strip()
            if line.startswith('graph ') or line.startswith('flowchart '):
                in_mermaid = True
                mermaid_lines = [line]
            elif in_mermaid:
                if line and not line.startswith('#') and not line.startswith('*'):
                    mermaid_lines.append(line)
                elif line.startswith('class ') or line.startswith('classDef '):
                    mermaid_lines.append(line)
                elif not line:
                    continue
                else:
                    break
        
        if mermaid_lines:
            return '\n'.join(mermaid_lines)
        
        return None
    
    def _parse_attack_steps(self, mermaid_content: str) -> List[AttackStep]:
        """Parse attack steps from Mermaid content."""
        attack_steps = []
        lines = mermaid_content.split('\n')
        
        # Extract node definitions
        node_pattern = r'(\w+)\["([^"]+)"\]'
        
        for line in lines:
            line = line.strip()
            
            # Skip styling and empty lines
            if line.startswith('class ') or line.startswith('classDef ') or not line:
                continue
            
            # Look for node definitions
            matches = re.findall(node_pattern, line)
            for node_id, description in matches:
                # Determine node type (default to attack)
                node_type = self._classify_node_type(description)
                
                attack_step = AttackStep(
                    id=node_id,
                    description=description,
                    node_type=node_type
                )
                attack_steps.append(attack_step)
        
        return attack_steps
    
    def _classify_node_type(self, description: str) -> str:
        """Classify node type based on description."""
        desc_lower = description.lower()
        
        # Mitigation indicators
        mitigation_keywords = [
            'waf', 'firewall', '2fa', 'mfa', 'encryption', 'monitoring', 
            'alerts', 'policy', 'control', 'defense', 'protection',
            'secure', 'validate', 'verify', 'audit', 'log'
        ]
        
        # Goal indicators
        goal_keywords = [
            'access', 'compromise', 'steal', 'exfiltrate', 'control',
            'execute', 'escalate', 'persist', 'lateral', 'achieve'
        ]
        
        # Fact indicators
        fact_keywords = [
            'reality', 'exposed', 'public', 'vulnerable', 'misconfigured',
            'default', 'weak', 'unpatched', 'legacy'
        ]
        
        if any(keyword in desc_lower for keyword in mitigation_keywords):
            return 'mitigation'
        elif any(keyword in desc_lower for keyword in goal_keywords):
            return 'goal'
        elif any(keyword in desc_lower for keyword in fact_keywords):
            return 'fact'
        else:
            return 'attack'
    
    def _save_attack_tree(self, attack_tree: AttackTree, threat: ThreatStatement) -> None:
        """Save attack tree to markdown file."""
        # Ensure directory exists
        file_path = Path(attack_tree.file_path)
        file_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Generate markdown content
        markdown_content = f"""# {attack_tree.title} - Attack Tree

**Threat ID:** {attack_tree.threat_id}
**Severity:** {threat.severity}
**Generated:** {attack_tree.generated_at.strftime('%Y-%m-%d %H:%M:%S')}

## Threat Description

{threat.description}

## Attack Tree

```mermaid
{attack_tree.mermaid_content}
```

## Attack Steps

"""
        
        # Add attack steps details
        for step in attack_tree.attack_steps:
            markdown_content += f"- **{step.id}** ({step.node_type}): {step.description}\n"
        
        markdown_content += f"""
---

*Generated by ThreatForest using {threat.source_file}*
"""
        
        # Write to file
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(markdown_content)
        
        self.logger.debug(f"Saved attack tree to: {file_path}")
    
    def get_generation_summary(self, attack_trees: List[AttackTree]) -> Dict[str, Any]:
        """Generate summary of attack tree generation."""
        if not attack_trees:
            return {
                'total_trees': 0,
                'node_types': {},
                'average_steps': 0
            }
        
        total_steps = sum(len(tree.attack_steps) for tree in attack_trees)
        
        # Count node types
        node_type_counts = {}
        for tree in attack_trees:
            for step in tree.attack_steps:
                node_type = step.node_type
                node_type_counts[node_type] = node_type_counts.get(node_type, 0) + 1
        
        return {
            'total_trees': len(attack_trees),
            'total_steps': total_steps,
            'average_steps': total_steps / len(attack_trees) if attack_trees else 0,
            'node_types': node_type_counts,
            'files_generated': [tree.file_path for tree in attack_trees]
        }