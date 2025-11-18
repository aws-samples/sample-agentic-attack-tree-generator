"""Enhanced context extraction using Strands Agent"""
import json
from typing import Dict, Any, Optional
from pathlib import Path
from src.config import config
from boto3 import Session
from strands import Agent
from strands.models import BedrockModel
from strands.handlers import null_callback_handler
from .file_categorizer import FileCategorizer


class ContextExtractor:
    """Extracts enhanced context using LLM"""
    
    def __init__(self, logger):
        self.logger = logger
        self.categorizer = FileCategorizer(logger)
    
    def extract_enhanced_context(self, context_files: Dict[str, Any], bedrock_model: str,
                                 aws_profile: Optional[str] = None) -> Dict[str, Any]:
        """Extract enhanced application context using Strands"""
        try:
            # Collect files for analysis
            files_to_analyze = []
            
            for category in ['architecture_diagrams', 'readmes']:
                for file_path in context_files.get(category, []):
                    if self.categorizer.is_binary_file(file_path) or file_path.lower().endswith('.md'):
                        files_to_analyze.append(file_path)
            
            if not files_to_analyze:
                return {}
            
            self.logger.info(f"Analyzing {len(files_to_analyze)} files via Strands for enhanced context")
            
            # Create Strands agent directly
            session = Session(profile_name=aws_profile) if aws_profile else Session()
            model = BedrockModel(model_id=bedrock_model, boto_session=session, temperature=0)
            
            # Load system prompt
            from pathlib import Path
            prompt_path = Path(__file__).parent.parent.parent.parent / "prompts" / "context-extraction.md"
            with open(prompt_path, 'r') as f:
                system_prompt = f.read()
            
            agent = Agent(model=model, system_prompt=system_prompt, tools=[], callback_handler=null_callback_handler())
            
            # Build user prompt
            file_list = '\n'.join([f"- {Path(f).name}" for f in files_to_analyze[:5]])
            user_prompt = f"""
Analyze these project files and extract:
- Application name and description
- Technologies and frameworks
- Architecture patterns
- Security controls

Files to analyze:
{file_list}

Provide a structured JSON response with these fields.
"""
            
            # Run Strands agent
            result = agent(user_prompt)
            
            # Try to parse as JSON, fallback to text parsing
            try:
                enhanced_context = json.loads(str(result))
            except:
                enhanced_context = self._parse_context_from_text(str(result))
            
            self.logger.info(f"Enhanced context extracted via Strands")
            return enhanced_context
            
        except Exception as e:
            self.logger.warning(f"Failed to extract enhanced context: {e}")
            return {}
    
    def _parse_context_from_text(self, text: str) -> Dict[str, Any]:
        """Parse context information from text response"""
        context = {}
        lines = text.split('\n')
        
        for line in lines:
            line = line.strip()
            if ':' in line and any(key in line.lower() for key in 
                ['application', 'industry', 'architecture', 'components', 'technologies']):
                parts = line.split(':', 1)
                if len(parts) == 2:
                    key = parts[0].strip().lower().replace(' ', '_')
                    value = parts[1].strip()
                    context[key] = value
        
        return context
