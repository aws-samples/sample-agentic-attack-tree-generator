"""Attack Tree Generator Tool for creating Mermaid attack trees"""
import json
import time
import asyncio
from typing import Dict, List, Any, Optional
from pathlib import Path
from ..utils.logger import ThreatForestLogger
from ..core import Tool, tool

import boto3
from botocore.exceptions import ClientError

# Import progress types if available
try:
    from ..core import ProgressEmitter, ProgressEvent, ProgressEventType
    PROGRESS_AVAILABLE = True
except ImportError:
    PROGRESS_AVAILABLE = False


class AttackTreeGeneratorTool(Tool):
    """Tool for generating attack trees in Mermaid format"""
    
    def __init__(self):
        super().__init__(
            name="attack_tree_generator",
            description="Generate attack trees in Mermaid format for high severity threats"
        )
        self.logger = ThreatForestLogger.get_logger(self.__class__.__name__)
        self.rate_limit_delay = 2.5  # seconds between calls
        self.max_retries = 3
        self.base_backoff = 2  # base seconds for exponential backoff
        self.throttled = False  # Track if we've been throttled
    
    async def execute(self, threat_statements: List[Dict[str, Any]], 
                     extracted_info: Dict[str, Any], bedrock_model: str,
                     aws_profile: Optional[str] = None,
                     existing_status: Optional[Dict[str, str]] = None,
                     output_dir: Optional[str] = None,
                     progress_emitter: Optional['ProgressEmitter'] = None) -> Dict[str, Any]:
        """Execute attack tree generation with rate limiting and retry support
        
        Args:
            existing_status: Dict mapping threat_id to status ('success'/'failed')
                           Only retry threats with 'failed' status or not in dict
            output_dir: Output directory for saving state file
        """
        
        # Load existing state if not provided
        if existing_status is None and output_dir:
            existing_status = self._load_state(output_dir)
        
        # Debug: Log what we received
        self.logger.debug(f"Received {len(threat_statements)} total threat statements")
        for t in threat_statements[:3]:
            self.logger.debug(f"  Sample threat: id={t.get('id')}, severity={t.get('severity')}, priority={t.get('priority')}")
        
        # Filter for high severity threats only
        high_threats = [t for t in threat_statements if t.get("severity") == "High"]
        
        # If no threats with "severity", try "priority" field
        if not high_threats:
            self.logger.debug("No threats with severity='High', trying priority field")
            high_threats = [t for t in threat_statements if t.get("priority") == "High"]
        
        if not high_threats:
            self.logger.info("No high severity threats found")
            return {
                "attack_trees": [],
                "threat_status": {},
                "message": "No high severity threats found for attack tree generation"
            }
        
        # Filter out already successful threats if retrying
        existing_status = existing_status or {}
        threats_to_process = [
            t for t in high_threats 
            if existing_status.get(t.get("id", ""), "") != "success"
        ]
        
        skipped_count = len(high_threats) - len(threats_to_process)
        if skipped_count > 0:
            self.logger.info(f"Skipping {skipped_count} already successful threats")
        
        if not threats_to_process:
            self.logger.info("All threats already have successful attack trees")
            return {
                "attack_trees": [],
                "threat_status": existing_status,
                "generation_summary": {
                    "total_high_threats": len(high_threats),
                    "processed_this_run": 0,
                    "skipped_successful": len(high_threats),
                    "successful_generations": 0,
                    "failed_generations": 0,
                    "all_complete": True
                },
                "message": "All threats already processed successfully. Use existing results or delete state file to regenerate."
            }
        
        self.logger.info(f"Generating attack trees for {len(threats_to_process)} threats")
        attack_trees = []
        threat_status = dict(existing_status)  # Copy existing status
        
        for idx, threat in enumerate(threats_to_process, 1):
            threat_id = threat.get("id", "unknown")
            self.logger.info(f"Processing threat {idx}/{len(threats_to_process)}: {threat_id}")
            
            # Emit threat start progress
            if progress_emitter and PROGRESS_AVAILABLE:
                progress_emitter.emit(ProgressEvent(
                    type=ProgressEventType.THREAT_START,
                    stage="tree_generation",
                    percentage=40.0 + ((idx - 1) / len(threats_to_process)) * 40.0,
                    message=f"Generating attack tree for {threat_id}",
                    details={"threat_id": threat_id, "index": idx, "total": len(threats_to_process)}
                ))
            
            try:
                tree = await self._generate_attack_tree_with_retry(threat, extracted_info, bedrock_model, aws_profile)
                if tree:
                    attack_trees.append(tree)
                    # Only mark as success if tree has mermaid_code (not an error)
                    if "mermaid_code" in tree:
                        threat_status[threat_id] = "success"
                        self.logger.info(f"✓ Successfully generated attack tree for {threat_id}")
                        
                        # Emit threat complete progress
                        if progress_emitter and PROGRESS_AVAILABLE:
                            progress_emitter.emit(ProgressEvent(
                                type=ProgressEventType.THREAT_COMPLETE,
                                stage="tree_generation",
                                percentage=40.0 + (idx / len(threats_to_process)) * 40.0,
                                message=f"Completed attack tree for {threat_id} ({idx} of {len(threats_to_process)} total)",
                                details={"threat_id": threat_id, "success": True}
                            ))
                    else:
                        # Tree has error
                        threat_status[threat_id] = "failed"
                        self.logger.error(f"✗ {threat_id}: {tree.get('error', 'Unknown error')}")
                        
                        # Emit error progress
                        if progress_emitter and PROGRESS_AVAILABLE:
                            progress_emitter.emit(ProgressEvent(
                                type=ProgressEventType.ERROR,
                                stage="tree_generation",
                                percentage=40.0 + (idx / len(threats_to_process)) * 40.0,
                                message=f"Failed to generate attack tree for {threat_id}",
                                details={"threat_id": threat_id, "error": tree.get('error', 'Unknown error')}
                            ))
                
                # Rate limiting: wait between calls (except after last one)
                if idx < len(threats_to_process):
                    # Adaptive rate limiting: increase delay if we've been throttled
                    delay = 10.0 if self.throttled else self.rate_limit_delay
                    self.logger.debug(f"Rate limiting: waiting {delay}s before next call")
                    await asyncio.sleep(delay)
                    
            except Exception as e:
                error_msg = f"Failed to generate attack tree: {str(e)}"
                self.logger.error(f"✗ {threat_id}: {error_msg}")
                print(f"❌ Error generating attack tree for {threat_id}: {error_msg}")
                threat_status[threat_id] = "failed"
                attack_trees.append({
                    "threat_id": threat_id,
                    "error": error_msg
                })
                
                # Emit threat error progress
                if progress_emitter and PROGRESS_AVAILABLE:
                    progress_emitter.emit(ProgressEvent(
                        type=ProgressEventType.ERROR,
                        stage="tree_generation",
                        percentage=40.0 + (idx / len(threats_to_process)) * 40.0,
                        message=f"Failed to generate attack tree for {threat_id}",
                        details={"threat_id": threat_id, "error": error_msg}
                    ))
                
                # Continue to next threat instead of stopping
                continue
        
        successful = len([t for t in attack_trees if "mermaid_code" in t])
        failed = len([t for t in attack_trees if "error" in t])
        
        self.logger.info(f"Attack tree generation complete: {successful} successful, {failed} failed")
        
        # Save state if output_dir provided
        if output_dir:
            self._save_state(output_dir, threat_status)
        
        return {
            "attack_trees": attack_trees,
            "threat_status": threat_status,
            "generation_summary": {
                "total_high_threats": len(high_threats),
                "processed_this_run": len(threats_to_process),
                "skipped_successful": skipped_count,
                "successful_generations": successful,
                "failed_generations": failed
            }
        }
    
    def _load_state(self, output_dir: str) -> Dict[str, str]:
        """Load threat generation state from file"""
        state_file = Path(output_dir) / ".threatforest_state.json"
        if state_file.exists():
            try:
                with open(state_file) as f:
                    data = json.load(f)
                    self.logger.info(f"Loaded state: {len(data.get('threat_status', {}))} threats tracked")
                    return data.get('threat_status', {})
            except Exception as e:
                self.logger.warning(f"Failed to load state file: {e}")
        return {}
    
    def _save_state(self, output_dir: str, threat_status: Dict[str, str]):
        """Save threat generation state to file"""
        state_file = Path(output_dir) / ".threatforest_state.json"
        try:
            state_file.parent.mkdir(parents=True, exist_ok=True)
            with open(state_file, 'w') as f:
                json.dump({
                    'threat_status': threat_status,
                    'last_updated': time.strftime('%Y-%m-%d %H:%M:%S')
                }, f, indent=2)
            self.logger.info(f"Saved state: {len(threat_status)} threats tracked")
        except Exception as e:
            self.logger.warning(f"Failed to save state file: {e}")
    
    async def _generate_attack_tree_with_retry(self, threat: Dict[str, Any], 
                                              extracted_info: Dict[str, Any],
                                              bedrock_model: str, 
                                              aws_profile: Optional[str] = None) -> Dict[str, Any]:
        """Generate attack tree with exponential backoff retry logic"""
        last_error = None
        
        for attempt in range(self.max_retries):
            try:
                return await self._generate_attack_tree(threat, extracted_info, bedrock_model, aws_profile)
            except ClientError as e:
                error_code = e.response.get('Error', {}).get('Code', '')
                error_msg = e.response.get('Error', {}).get('Message', str(e))
                
                if error_code == 'ThrottlingException':
                    self.throttled = True  # Mark that we've been throttled
                    wait_time = self.base_backoff * (2 ** attempt)
                    self.logger.warning(f"⚠️  Throttled by Bedrock API (attempt {attempt + 1}/{self.max_retries})")
                    print(f"⚠️  Rate limited by AWS Bedrock - waiting {wait_time}s before retry...")
                    
                    if attempt < self.max_retries - 1:
                        await asyncio.sleep(wait_time)
                        continue
                    else:
                        self.logger.error(f"Max retries reached after throttling")
                        print(f"❌ Max retries exceeded - Bedrock API throttling persists")
                        raise Exception(f"Throttling error after {self.max_retries} retries: {error_msg}")
                else:
                    self.logger.error(f"Bedrock API error: {error_code} - {error_msg}")
                    raise Exception(f"Bedrock API error ({error_code}): {error_msg}")
            except Exception as e:
                last_error = e
                if attempt < self.max_retries - 1:
                    wait_time = self.base_backoff * (2 ** attempt)
                    self.logger.warning(f"Attempt {attempt + 1} failed, retrying in {wait_time}s: {str(e)}")
                    await asyncio.sleep(wait_time)
                else:
                    self.logger.error(f"All retry attempts failed: {str(e)}")
                    raise
        
        raise last_error if last_error else Exception("Unknown error in retry logic")
    
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
            
            # Convert cross-region inference profile IDs to ARNs
            model_id = bedrock_model
            if model_id.startswith('us.') or model_id.startswith('eu.'):
                model_id = f"arn:aws:bedrock:us-east-1::foundation-model/{model_id}"
            
            response = bedrock.invoke_model(
                modelId=model_id,
                body=json.dumps(body)
            )
            
            response_body = json.loads(response['body'].read())
            generated_content = response_body['content'][0]['text']
            
            # Extract Mermaid code from response
            self.logger.debug(f"Bedrock response length: {len(generated_content)} characters")
            self.logger.debug(f"First 200 chars of response: {generated_content[:200]}...")
            mermaid_code = self._extract_mermaid_code(generated_content)
            self.logger.debug(f"Extracted Mermaid code length: {len(mermaid_code)} characters")
            self.logger.debug(f"Mermaid code preview: {mermaid_code[:100]}...")
            
            # Validate the generated attack tree
            validation_result = self._validate_attack_tree(mermaid_code, threat, project_info)
            self.logger.debug(f"Validation result: {validation_result}")
            
            # Only fail on critical errors, allow warnings to pass
            critical_errors = [error for error in validation_result.get('errors', []) 
                             if 'Missing \'graph TD\' declaration' in error or 'No attack nodes classified' in error]
            
            if critical_errors:
                self.logger.error(f"Attack tree validation failed with critical errors: {critical_errors}")
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
                "attack_steps": self._extract_attack_steps(mermaid_code),
                "generated_content": generated_content,
                "validation": validation_result
            }
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            error_msg = e.response.get('Error', {}).get('Message', str(e))
            self.logger.error(f"Bedrock ClientError: {error_code} - {error_msg}")
            raise
        except Exception as e:
            self.logger.error(f"Bedrock API error: {str(e)}")
            raise Exception(f"Bedrock API error: {str(e)}")
    
    def _validate_attack_tree(self, mermaid_code: str, threat: Dict[str, Any], 
                             project_info: Dict[str, Any]) -> Dict[str, Any]:
        """Validate the generated attack tree for completeness and correctness"""
        errors = []
        warnings = []
        
        # Check basic structure
        if not mermaid_code.strip().startswith('graph TD'):
            errors.append("Missing 'graph TD' declaration")
        
        # Check for required class definitions (mitigations not required per prompt)
        required_classes = ['classDef attack', 'classDef goal', 'classDef fact']
        for class_def in required_classes:
            if class_def not in mermaid_code:
                errors.append(f"Missing required class definition: {class_def}")
        
        # Check for node classifications
        node_types = {
            'attack': len([line for line in mermaid_code.split('\n') if 'class ' in line and 'attack' in line]),
            'goal': len([line for line in mermaid_code.split('\n') if 'class ' in line and 'goal' in line]),
            'fact': len([line for line in mermaid_code.split('\n') if 'class ' in line and 'fact' in line])
        }
        
        # Validate minimum node counts (no mitigation requirement per prompt)
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
    
    def _build_attack_tree_prompt(self, threat: Dict[str, Any], project_info: Dict[str, Any]) -> str:
        """Build prompt for attack tree generation using external prompt file with enhanced context"""
        
        # Load the external prompt template
        prompt_template = self._load_prompt_template()
        
        # Build enhanced context from all available files
        context_info = self._build_enhanced_context(project_info)
        
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
        
        # Build the threat-specific context with explicit single-threat instruction
        threat_context = f"""
## IMPORTANT: Generate ONE attack tree for THIS SINGLE threat statement only.

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

## Output Requirement:
Generate a SINGLE Mermaid attack tree diagram for threat ID {threat.get('id', 'Unknown')} only. 
Do not include multiple threats or create multiple diagrams in your response.
"""
        
        # Combine the template with threat-specific context
        return f"{prompt_template}\n\n{threat_context}"
    
    def _load_prompt_template(self) -> str:
        """Load the attack tree generation prompt from external file"""
        prompt_file = Path(__file__).parent.parent.parent / "prompts" / "generate-attack-trees.md"
        self.logger.debug(f"Looking for prompt file at: {prompt_file}")
        try:
            with open(prompt_file, 'r', encoding='utf-8') as f:
                content = f.read()
                self.logger.info(f"Successfully loaded prompt file ({len(content)} characters)")
                return content
        except FileNotFoundError:
            self.logger.error(f"Prompt file not found at {prompt_file}, using fallback")
            # Fallback to basic prompt if file not found
            return """You are a cybersecurity analyst specializing in threat modeling and attack tree generation. 
Generate Mermaid attack trees from threat statements using proper structure and color coding."""
    
    def _build_enhanced_context(self, project_info: Dict[str, Any]) -> str:
        """Build enhanced context from all available files including images and PDFs"""
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
    
    
    def _extract_mermaid_code(self, content: str) -> str:
        """Extract Mermaid code block from generated content"""
        import re
        
        # Look for ```mermaid code blocks
        mermaid_pattern = r'```mermaid\s*\n(.*?)\n```'
        match = re.search(mermaid_pattern, content, re.DOTALL)
        
        if match:
            mermaid_code = match.group(1).strip()
            return self._clean_mermaid_code(mermaid_code)
        
        # Fallback: look for graph TD patterns
        graph_pattern = r'(graph TD.*?)(?=\n\n|\n```|\Z)'
        match = re.search(graph_pattern, content, re.DOTALL)
        
        if match:
            return self._clean_mermaid_code(match.group(1).strip())
        
        # Last resort: create minimal valid mermaid
        return self._get_minimal_mermaid()
    
    def _clean_mermaid_code(self, mermaid_code: str) -> str:
        """Clean and validate Mermaid code"""
        import re
        
        if not mermaid_code.strip():
            return self._get_minimal_mermaid()
        
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
    
    def _get_minimal_mermaid(self) -> str:
        """Get minimal valid Mermaid diagram"""
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
    
    def _extract_attack_steps(self, mermaid_code: str) -> List[str]:
        """Extract attack step nodes from Mermaid code"""
        import re
        
        # Extract node definitions: nodeId["text"]
        node_pattern = r'(\w+)\["([^"]+)"\]'
        matches = re.findall(node_pattern, mermaid_code)
        
        return [{"node_id": node_id, "description": desc} for node_id, desc in matches]
