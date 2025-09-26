"""Attack Tree Generator Tool for creating Mermaid attack trees"""
import json
from typing import Dict, List, Any, Optional
from pathlib import Path

# Mock Strands Tool for testing
class Tool:
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description

import boto3


class AttackTreeGeneratorTool(Tool):
    """Tool for generating attack trees in Mermaid format"""
    
    def __init__(self):
        super().__init__(
            name="attack_tree_generator",
            description="Generate attack trees in Mermaid format for high severity threats"
        )
    
    async def execute(self, threat_statements: List[Dict[str, Any]], 
                     extracted_info: Dict[str, Any], bedrock_model: str,
                     aws_profile: Optional[str] = None) -> Dict[str, Any]:
        """Execute attack tree generation"""
        
        # Filter for high severity threats only
        high_threats = [t for t in threat_statements if t.get("severity") == "High"]
        
        if not high_threats:
            return {
                "attack_trees": [],
                "message": "No high severity threats found for attack tree generation"
            }
        
        attack_trees = []
        
        for threat in high_threats:
            try:
                tree = await self._generate_attack_tree(threat, extracted_info, bedrock_model, aws_profile)
                if tree:
                    attack_trees.append(tree)
            except Exception as e:
                attack_trees.append({
                    "threat_id": threat.get("id", "unknown"),
                    "error": f"Failed to generate attack tree: {str(e)}"
                })
        
        return {
            "attack_trees": attack_trees,
            "generation_summary": {
                "total_high_threats": len(high_threats),
                "successful_generations": len([t for t in attack_trees if "mermaid_code" in t]),
                "failed_generations": len([t for t in attack_trees if "error" in t])
            }
        }
    
    async def _generate_attack_tree(self, threat: Dict[str, Any], project_info: Dict[str, Any],
                                   bedrock_model: str, aws_profile: Optional[str] = None) -> Dict[str, Any]:
        """Generate attack tree for a specific threat"""
        
        prompt = self._build_attack_tree_prompt(threat, project_info)
        
        try:
            # Call Bedrock
            session = boto3.Session(profile_name=aws_profile) if aws_profile else boto3.Session()
            bedrock = session.client('bedrock-runtime', region_name='us-east-1')
            
            body = {
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": 65536,
                "messages": [{"role": "user", "content": prompt}]
            }
            
            response = bedrock.invoke_model(
                modelId=bedrock_model,
                body=json.dumps(body)
            )
            
            response_body = json.loads(response['body'].read())
            generated_content = response_body['content'][0]['text']
            
            # Extract Mermaid code from response
            mermaid_code = self._extract_mermaid_code(generated_content)
            
            # Validate the generated attack tree
            validation_result = self._validate_attack_tree(mermaid_code, threat, project_info)
            
            if not validation_result['is_valid']:
                return {
                    "threat_id": threat.get("id"),
                    "error": f"Attack tree validation failed: {validation_result['errors']}"
                }
            
            return {
                "threat_id": threat.get("id"),
                "threat_category": threat.get("category"),
                "threat_description": threat.get("description"),
                "threat_statement": threat.get("statement", threat.get("description", "")),
                "mermaid_code": mermaid_code,
                "attack_steps": self._extract_attack_steps(mermaid_code),
                "generated_content": generated_content,
                "validation": validation_result
            }
            
        except Exception as e:
            raise Exception(f"Bedrock API error: {str(e)}")
    
    def _validate_attack_tree(self, mermaid_code: str, threat: Dict[str, Any], 
                             project_info: Dict[str, Any]) -> Dict[str, Any]:
        """Validate the generated attack tree for completeness and correctness"""
        errors = []
        warnings = []
        
        # Check basic structure
        if not mermaid_code.strip().startswith('graph TD'):
            errors.append("Missing 'graph TD' declaration")
        
        # Check for required class definitions
        required_classes = ['classDef attack', 'classDef mitigation', 'classDef goal', 'classDef fact']
        for class_def in required_classes:
            if class_def not in mermaid_code:
                errors.append(f"Missing required class definition: {class_def}")
        
        # Check for node classifications
        node_types = {
            'attack': len([line for line in mermaid_code.split('\n') if 'class ' in line and 'attack' in line]),
            'mitigation': len([line for line in mermaid_code.split('\n') if 'class ' in line and 'mitigation' in line]),
            'goal': len([line for line in mermaid_code.split('\n') if 'class ' in line and 'goal' in line]),
            'fact': len([line for line in mermaid_code.split('\n') if 'class ' in line and 'fact' in line])
        }
        
        # Validate minimum node counts
        if node_types['attack'] == 0:
            errors.append("No attack nodes classified")
        elif node_types['attack'] < 3:
            warnings.append(f"Only {node_types['attack']} attack nodes (recommended: 5+)")
            
        if node_types['mitigation'] == 0:
            errors.append("No mitigation nodes classified")
        elif node_types['mitigation'] < 2:
            warnings.append(f"Only {node_types['mitigation']} mitigation nodes (recommended: 3+)")
            
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
    
    def _build_attack_tree_prompt(self, threat: Dict[str, Any], project_info: Dict[str, Any]) -> str:
        """Build prompt for attack tree generation using mermaid template"""
        
        # Load the mermaid template
        mermaid_template = self._load_mermaid_template()
        
        # Build the prompt using the template structure
        return f"""You are a cybersecurity expert creating attack trees. Convert the following threat into a detailed Mermaid flowchart diagram using this EXACT format:

## Structure Requirements:
- Use `graph TD` (top-down direction)
- Node format: `node_id["descriptive text"]`
- Connection format: `parent --> child`
- Include all relationships from the input data

## Color Coding (apply these exact CSS classes):
```
classDef attack fill:#ffcccc
classDef mitigation fill:#ccffcc  
classDef goal fill:#ffcc99
classDef fact fill:#ccccff

class node1,node2,node3 attack
class node4,node5,node6 mitigation
class node7,node8 goal
class node9,node10 fact
```

## Node Classification:
- **Facts**: Initial conditions, vulnerabilities, or starting points
- **Attacks**: Malicious actions, exploits, or threat vectors
- **Mitigations**: Security controls, defenses, or countermeasures
- **Goals**: Ultimate objectives or outcomes (what attackers/defenders achieve)

## Threat to Analyze:
**ID**: {threat.get('id', 'Unknown')}
**Statement**: {threat.get('statement', threat.get('description', 'No statement provided'))}
**Priority**: {threat.get('priority', threat.get('severity', 'Unknown'))}
**Category**: {threat.get('category', 'Unknown')}

## Context Information:
**Application**: {project_info.get('application_name', 'Unknown Application')}
**Technologies**: {', '.join(project_info.get('technologies', [])[:10])}
**Architecture**: {project_info.get('architecture_type', 'Unknown')}
**Deployment**: {project_info.get('deployment_environment', 'Unknown')}

## Output Format:
1. Title as markdown header
2. Mermaid code block with the diagram
3. Apply color classes at the end

Generate a comprehensive attack tree with:
- Root goal node (what the attacker wants to achieve)
- Multiple attack paths with 3-5 steps each
- Include facts (prerequisites/vulnerabilities)
- Include potential mitigations
- Use descriptive node labels
- Apply proper color classifications

Return ONLY the Mermaid diagram in this format:

# Attack Tree: {threat.get('statement', threat.get('description', threat.get('id', 'Unknown Threat')))}

```mermaid
graph TD
    [your diagram here]
    
    classDef attack fill:#ffcccc
    classDef mitigation fill:#ccffcc  
    classDef goal fill:#ffcc99
    classDef fact fill:#ccccff
    
    class [attack nodes] attack
    class [mitigation nodes] mitigation
    class [goal nodes] goal
    class [fact nodes] fact
```"""
    
    def _load_mermaid_template(self) -> str:
        """Load Mermaid template from prompts directory"""
        try:
            template_path = Path(__file__).parent.parent.parent.parent / "prompts" / "mermaid-prompt.md"
            if template_path.exists():
                return template_path.read_text()
            else:
                return self._get_default_mermaid_template()
        except:
            return self._get_default_mermaid_template()
    
    def _get_default_mermaid_template(self) -> str:
        """Default Mermaid template if file not found"""
        return """
Use this Mermaid format:

```mermaid
graph TD
    goal["Main Threat Goal"]
    vector1["Attack Vector 1"]
    vector2["Attack Vector 2"]
    step1["Attack Step 1"]
    step2["Attack Step 2"]
    
    goal --> vector1
    goal --> vector2
    vector1 --> step1
    vector2 --> step2
    
    classDef attack fill:#ffcccc
    classDef mitigation fill:#ccffcc
    classDef goal fill:#ffcc99
    classDef fact fill:#ccccff
    
    class goal goal
    class vector1,vector2 attack
    class step1,step2 attack
```
"""
    
    def _extract_mermaid_code(self, content: str) -> str:
        """Extract Mermaid code block from generated content"""
        import re
        
        # Look for ```mermaid code blocks
        mermaid_pattern = r'```mermaid\s*\n(.*?)\n```'
        match = re.search(mermaid_pattern, content, re.DOTALL)
        
        if match:
            mermaid_code = match.group(1).strip()
            
            # Validate and fix common issues
            lines = mermaid_code.split('\n')
            
            # Ensure it starts with graph TD
            if not lines[0].strip().startswith('graph TD'):
                mermaid_code = 'graph TD\n' + mermaid_code
            
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
        
        # Fallback: look for graph TD patterns
        graph_pattern = r'(graph TD.*?)(?=\n\n|\n```|\Z)'
        match = re.search(graph_pattern, content, re.DOTALL)
        
        if match:
            return match.group(1).strip()
        
        # Last resort: create minimal valid mermaid
        return f"""graph TD
    goal["Threat: {content[:50]}..."]
    
    classDef attack fill:#ffcccc
    classDef mitigation fill:#ccffcc
    classDef goal fill:#ffcc99
    classDef fact fill:#ccccff
    
    class goal goal"""
    
    def _extract_attack_steps(self, mermaid_code: str) -> List[str]:
        """Extract attack step nodes from Mermaid code"""
        import re
        
        # Extract node definitions: nodeId["text"]
        node_pattern = r'(\w+)\["([^"]+)"\]'
        matches = re.findall(node_pattern, mermaid_code)
        
        return [{"node_id": node_id, "description": desc} for node_id, desc in matches]
