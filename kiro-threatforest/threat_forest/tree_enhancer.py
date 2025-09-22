"""
Attack tree enhancement system that integrates MITRE ATT&CK data.
"""

import re
from typing import List, Dict, Any, Optional
from pathlib import Path

from .models import AttackTree, AttackStep, STIXTechnique
from .stix_processor import STIXProcessor, STIXMapper
from .utils import get_logger


class TreeEnhancer:
    """Enhances attack trees with MITRE ATT&CK technique data."""
    
    def __init__(self, stix_processor: STIXProcessor, stix_mapper: STIXMapper):
        self.stix_processor = stix_processor
        self.stix_mapper = stix_mapper
        self.logger = get_logger(__name__)
    
    def enhance_attack_trees(self, attack_trees: List[AttackTree]) -> List[AttackTree]:
        """
        Enhance attack trees with MITRE ATT&CK technique mappings.
        
        Args:
            attack_trees: List of attack trees to enhance
            
        Returns:
            List of enhanced attack trees
        """
        self.logger.info(f"Enhancing {len(attack_trees)} attack trees with MITRE ATT&CK data")
        
        enhanced_trees = []
        
        for tree in attack_trees:
            try:
                enhanced_tree = self.enhance_single_tree(tree)
                enhanced_trees.append(enhanced_tree)
                self.logger.debug(f"Enhanced attack tree: {tree.threat_id}")
            except Exception as e:
                self.logger.error(f"Failed to enhance attack tree {tree.threat_id}: {e}")
                # Return original tree if enhancement fails
                enhanced_trees.append(tree)
        
        self.logger.info(f"Successfully enhanced {len(enhanced_trees)} attack trees")
        return enhanced_trees
    
    def enhance_single_tree(self, attack_tree: AttackTree) -> AttackTree:
        """
        Enhance a single attack tree with MITRE ATT&CK data.
        
        Args:
            attack_tree: Attack tree to enhance
            
        Returns:
            Enhanced attack tree
        """
        # Map attack steps to MITRE techniques
        enhanced_steps = self.stix_mapper.map_attack_steps(attack_tree.attack_steps)
        
        # Update Mermaid diagram with technique references
        enhanced_mermaid = self._enhance_mermaid_diagram(
            attack_tree.mermaid_content, 
            enhanced_steps
        )
        
        # Create enhanced attack tree
        enhanced_tree = AttackTree(
            threat_id=attack_tree.threat_id,
            title=attack_tree.title,
            mermaid_content=enhanced_mermaid,
            attack_steps=enhanced_steps,
            file_path=attack_tree.file_path,
            generated_at=attack_tree.generated_at
        )
        
        # Save enhanced tree
        self._save_enhanced_tree(enhanced_tree)
        
        return enhanced_tree
    
    def _enhance_mermaid_diagram(self, mermaid_content: str, attack_steps: List[AttackStep]) -> str:
        """
        Enhance Mermaid diagram with MITRE ATT&CK technique references.
        
        Args:
            mermaid_content: Original Mermaid diagram content
            attack_steps: Enhanced attack steps with technique mappings
            
        Returns:
            Enhanced Mermaid diagram content
        """
        lines = mermaid_content.split('\n')
        enhanced_lines = []
        
        # Create mapping of step IDs to techniques
        step_techniques = {}
        for step in attack_steps:
            if step.mitre_techniques:
                step_techniques[step.id] = step.mitre_techniques
        
        for line in lines:
            line = line.strip()
            
            # Skip empty lines and styling
            if not line or line.startswith('class ') or line.startswith('classDef '):
                enhanced_lines.append(line)
                continue
            
            # Look for node definitions to enhance
            enhanced_line = self._enhance_node_line(line, step_techniques)
            enhanced_lines.append(enhanced_line)
        
        return '\n'.join(enhanced_lines)
    
    def _enhance_node_line(self, line: str, step_techniques: Dict[str, List[str]]) -> str:
        """
        Enhance a single line containing node definitions.
        
        Args:
            line: Original line from Mermaid diagram
            step_techniques: Mapping of step IDs to technique IDs
            
        Returns:
            Enhanced line with technique references
        """
        # Pattern to match node definitions: node_id["description"]
        node_pattern = r'(\w+)\["([^"]+)"\]'
        
        def replace_node(match):
            node_id = match.group(1)
            description = match.group(2)
            
            # Check if this node has technique mappings
            if node_id in step_techniques:
                techniques = step_techniques[node_id]
                
                # Add technique references to description
                technique_refs = []
                for tech_id in techniques[:2]:  # Limit to 2 techniques to avoid clutter
                    technique = self.stix_processor.get_technique_by_id(tech_id)
                    if technique:
                        technique_refs.append(technique.technique_id)
                
                if technique_refs:
                    enhanced_description = f"{description}<br/>[{', '.join(technique_refs)}]"
                    return f'{node_id}["{enhanced_description}"]'
            
            return match.group(0)
        
        # Replace all node definitions in the line
        enhanced_line = re.sub(node_pattern, replace_node, line)
        return enhanced_line
    
    def _save_enhanced_tree(self, attack_tree: AttackTree) -> None:
        """Save enhanced attack tree to file."""
        file_path = Path(attack_tree.file_path)
        
        # Generate enhanced markdown content
        markdown_content = self._generate_enhanced_markdown(attack_tree)
        
        # Write to file
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(markdown_content)
        
        self.logger.debug(f"Saved enhanced attack tree to: {file_path}")
    
    def _generate_enhanced_markdown(self, attack_tree: AttackTree) -> str:
        """Generate enhanced markdown content with MITRE ATT&CK details."""
        content = f"""# {attack_tree.title} - Attack Tree

**Threat ID:** {attack_tree.threat_id}
**Generated:** {attack_tree.generated_at.strftime('%Y-%m-%d %H:%M:%S')}
**Enhanced with MITRE ATT&CK:** Yes

## Attack Tree Diagram

```mermaid
{attack_tree.mermaid_content}
```

## Attack Steps with MITRE ATT&CK Mappings

"""
        
        # Group steps by type
        steps_by_type = {
            'attack': [],
            'mitigation': [],
            'goal': [],
            'fact': []
        }
        
        for step in attack_tree.attack_steps:
            steps_by_type[step.node_type].append(step)
        
        # Add attack steps with technique details
        if steps_by_type['attack']:
            content += "### Attack Steps\n\n"
            for step in steps_by_type['attack']:
                content += f"**{step.id}**: {step.description}\n"
                
                if step.mitre_techniques:
                    content += f"- **MITRE ATT&CK Techniques:**\n"
                    for tech_id in step.mitre_techniques:
                        technique = self.stix_processor.get_technique_by_id(tech_id)
                        if technique:
                            content += f"  - [{technique.technique_id}](https://attack.mitre.org/techniques/{technique.technique_id.replace('.', '/')}/): {technique.name}\n"
                            if technique.kill_chain_phases:
                                content += f"    - **Tactics:** {', '.join(technique.kill_chain_phases)}\n"
                    
                    if step.confidence_score > 0:
                        content += f"- **Mapping Confidence:** {step.confidence_score:.2f}\n"
                
                content += "\n"
        
        # Add other step types
        for step_type, steps in steps_by_type.items():
            if step_type != 'attack' and steps:
                content += f"### {step_type.title()} Steps\n\n"
                for step in steps:
                    content += f"**{step.id}**: {step.description}\n\n"
        
        # Add MITRE ATT&CK summary
        content += self._generate_mitre_summary(attack_tree.attack_steps)
        
        content += """
---

*Enhanced by ThreatForest with MITRE ATT&CK technique mappings*
"""
        
        return content
    
    def _generate_mitre_summary(self, attack_steps: List[AttackStep]) -> str:
        """Generate MITRE ATT&CK summary section."""
        # Collect all techniques and tactics
        all_techniques = {}
        tactics_used = set()
        
        for step in attack_steps:
            if step.mitre_techniques:
                for tech_id in step.mitre_techniques:
                    technique = self.stix_processor.get_technique_by_id(tech_id)
                    if technique:
                        all_techniques[tech_id] = technique
                        tactics_used.update(technique.kill_chain_phases)
        
        if not all_techniques:
            return ""
        
        content = "## MITRE ATT&CK Summary\n\n"
        
        # Tactics overview
        if tactics_used:
            content += f"**Tactics Covered:** {len(tactics_used)}\n"
            content += f"- {', '.join(sorted(tactics_used))}\n\n"
        
        # Techniques overview
        content += f"**Techniques Identified:** {len(all_techniques)}\n\n"
        
        # Group techniques by tactic
        techniques_by_tactic = {}
        for technique in all_techniques.values():
            for tactic in technique.kill_chain_phases:
                if tactic not in techniques_by_tactic:
                    techniques_by_tactic[tactic] = []
                if technique not in techniques_by_tactic[tactic]:
                    techniques_by_tactic[tactic].append(technique)
        
        # List techniques by tactic
        for tactic in sorted(techniques_by_tactic.keys()):
            content += f"### {tactic.title()}\n\n"
            for technique in techniques_by_tactic[tactic]:
                content += f"- [{technique.technique_id}](https://attack.mitre.org/techniques/{technique.technique_id.replace('.', '/')}/): {technique.name}\n"
            content += "\n"
        
        return content
    
    def get_enhancement_summary(self, attack_trees: List[AttackTree]) -> Dict[str, Any]:
        """Generate summary of enhancement results."""
        total_trees = len(attack_trees)
        total_steps = sum(len(tree.attack_steps) for tree in attack_trees)
        
        # Count enhanced steps
        enhanced_steps = 0
        all_techniques = set()
        all_tactics = set()
        
        for tree in attack_trees:
            for step in tree.attack_steps:
                if step.mitre_techniques:
                    enhanced_steps += 1
                    all_techniques.update(step.mitre_techniques)
                    
                    # Get tactics for these techniques
                    for tech_id in step.mitre_techniques:
                        technique = self.stix_processor.get_technique_by_id(tech_id)
                        if technique:
                            all_tactics.update(technique.kill_chain_phases)
        
        return {
            'total_trees': total_trees,
            'total_steps': total_steps,
            'enhanced_steps': enhanced_steps,
            'enhancement_rate': enhanced_steps / total_steps if total_steps > 0 else 0,
            'unique_techniques': len(all_techniques),
            'tactics_covered': len(all_tactics),
            'techniques_per_tree': len(all_techniques) / total_trees if total_trees > 0 else 0
        }