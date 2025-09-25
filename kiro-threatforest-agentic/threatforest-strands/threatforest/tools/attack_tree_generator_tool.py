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
                "max_tokens": 4000,
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
            
            return {
                "threat_id": threat.get("id"),
                "threat_category": threat.get("category"),
                "threat_description": threat.get("description"),
                "mermaid_code": mermaid_code,
                "attack_steps": self._extract_attack_steps(mermaid_code),
                "generated_content": generated_content
            }
            
        except Exception as e:
            raise Exception(f"Bedrock API error: {str(e)}")
    
    def _build_attack_tree_prompt(self, threat: Dict[str, Any], project_info: Dict[str, Any]) -> str:
        """Build prompt for attack tree generation"""
        
        return f"""Generate an attack tree for the following threat using Mermaid flowchart format.

**Threat Information:**
- ID: {threat.get('id')}
- Category: {threat.get('category')}
- Severity: {threat.get('severity')}
- Description: {threat.get('description')}

**Project Context:**
- Application: {project_info.get('application_name', 'Unknown')}
- Technologies: {', '.join(project_info.get('technologies', []))}
- Architecture: {project_info.get('architecture_type', 'Unknown')}
- Deployment: {project_info.get('deployment_environment', 'Unknown')}

**Requirements:**
Create a complete Mermaid flowchart with this EXACT format:

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
    classDef goal fill:#ffcc99
    
    class goal goal
    class vector1,vector2,step1,step2 attack
```

CRITICAL: 
1. Start with "graph TD"
2. Include ALL node connections
3. End with classDef and class definitions
4. Return ONLY the mermaid code block, nothing else
5. Ensure all nodes referenced in connections are defined

Generate a comprehensive attack tree considering the specific technologies."""
    
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
            
            # Ensure it has class definitions
            if 'classDef' not in mermaid_code:
                mermaid_code += '\n\n    classDef attack fill:#ffcccc\n    classDef goal fill:#ffcc99'
            
            # Ensure it has class assignments
            if 'class ' not in mermaid_code:
                mermaid_code += '\n    class goal goal'
            
            return mermaid_code
        
        # Fallback: look for graph TD patterns
        graph_pattern = r'(graph TD.*?)(?=\n\n|\n```|\Z)'
        match = re.search(graph_pattern, content, re.DOTALL)
        
        if match:
            return match.group(1).strip()
        
        # Last resort: create minimal valid mermaid
        return f"""graph TD
    goal["Threat: {content[:50]}..."]
    
    classDef goal fill:#ffcc99
    class goal goal"""
    
    def _extract_attack_steps(self, mermaid_code: str) -> List[str]:
        """Extract attack step nodes from Mermaid code"""
        import re
        
        # Extract node definitions: nodeId["text"]
        node_pattern = r'(\w+)\["([^"]+)"\]'
        matches = re.findall(node_pattern, mermaid_code)
        
        return [{"node_id": node_id, "description": desc} for node_id, desc in matches]
