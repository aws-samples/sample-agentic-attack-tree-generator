"""Enhanced Context Analysis Tool with flexible threat file handling"""
import os
import json
import subprocess
from pathlib import Path
from threatforest.utils.logger import ThreatForestLogger
from threatforest.core import Tool, tool
from typing import Dict, List, Any, Optional


class ContextAnalysisTool(Tool):
    """Enhanced tool for analyzing project context with flexible threat file handling"""
    
    def __init__(self):
        super().__init__(
            name="context_analysis",
            description="Discover and analyze context files including threat models, READMEs, and architecture diagrams"
        )
        self.logger = ThreatForestLogger.get_logger(self.__class__.__name__)
        self.supported_formats = ['.json', '.tc', '.yaml', '.yml', '.md', '.txt']
        self.threat_keywords = ['threat', 'risk', 'vulnerability', 'attack', 'security']
    
    async def execute(self, project_path: str) -> Dict[str, Any]:
        """Execute enhanced context analysis"""
        project_dir = Path(project_path)
        
        # Discover threat models first (highest priority)
        threat_models = self._discover_threat_files(project_path)
        
        # Discover other context files
        context_files = {
            "threat_models": threat_models,
            "readmes": [],
            "architecture_diagrams": [],
            "data_flow_diagrams": [],
            "other_docs": []
        }
        
        # Search for other relevant files
        for file_path in project_dir.rglob("*"):
            if file_path.is_file() and str(file_path) not in threat_models:
                self._categorize_file(file_path, context_files)
        
        # Process threat models with enhanced extraction
        threat_analysis = self._process_threat_models(threat_models)
        
        # Parse other files
        parsed_files = {}
        for category, files in context_files.items():
            if category == "threat_models":
                continue  # Already processed
            parsed_files[category] = []
            for file_path in files:
                content = self._parse_file(Path(file_path))
                if content:
                    parsed_files[category].append({
                        "path": str(file_path),
                        "content": content,
                        "size": Path(file_path).stat().st_size
                    })
        
        return {
            "project_path": project_path,
            "discovered_files": context_files,
            "threat_analysis": threat_analysis,
            "parsed_content": parsed_files,
            "summary": self._generate_enhanced_summary(threat_analysis, parsed_files, context_files),
            "enhanced_context": self._extract_enhanced_context_via_bedrock(context_files)
        }
    
    def _discover_threat_files(self, project_path: str) -> List[str]:
        """Discover threat-related files using enhanced detection"""
        threat_files = []
        
        for root, dirs, files in os.walk(project_path):
            for file in files:
                file_path = os.path.join(root, file)
                
                # Check if file contains 'threat' in filename (any extension)
                if 'threat' in file.lower():
                    threat_files.append(file_path)
                # Check by extension and keywords
                elif any(file.lower().endswith(ext) for ext in self.supported_formats):
                    if any(keyword in file.lower() for keyword in self.threat_keywords):
                        threat_files.append(file_path)
                    # Check ThreatComposer format
                    elif 'threatcomposer' in file.lower() or file.endswith('.tc'):
                        threat_files.append(file_path)
        
        return threat_files
    
    def _process_threat_models(self, threat_files: List[str]) -> Dict[str, Any]:
        """Process threat models using enhanced extraction"""
        analysis = {
            'total_files': len(threat_files),
            'processed_files': [],
            'application_context': {},
            'total_threats': 0,
            'priority_summary': {'high': 0, 'medium': 0, 'low': 0},
            'high_priority_threats': []
        }
        
        for file_path in threat_files:
            try:
                threat_data = self._extract_threats_enhanced(file_path)
                if threat_data and 'threats' in threat_data:
                    file_analysis = {
                        'file': file_path,
                        'format': self._detect_format(file_path),
                        'threat_count': threat_data.get('total_threats', 0),
                        'priorities': threat_data.get('priority_counts', {}),
                        'application_context': threat_data.get('application_context', {})
                    }
                    analysis['processed_files'].append(file_analysis)
                    
                    # Aggregate data
                    analysis['total_threats'] += threat_data.get('total_threats', 0)
                    for priority in ['high', 'medium', 'low']:
                        analysis['priority_summary'][priority] += threat_data.get('priority_counts', {}).get(priority, 0)
                    
                    # Collect high priority threats
                    for threat in threat_data.get('threats', []):
                        if threat.get('priority') == 'high':
                            analysis['high_priority_threats'].append({
                                'statement': threat['statement'][:150],
                                'source_file': os.path.basename(file_path)
                            })
                    
                    # Use first file's context as primary
                    if not analysis['application_context'] and threat_data.get('application_context'):
                        analysis['application_context'] = threat_data['application_context']
                        
            except Exception as e:
                self.logger.warning(f"Failed to process {file_path}: {str(e)}")
        
        return analysis
    
    def _extract_threats_enhanced(self, file_path: str) -> Optional[Dict[str, Any]]:
        """Extract threats using enhanced flexible extraction"""
        try:
            # Try JQ-style extraction first (most efficient)
            script_path = Path(__file__).parent / "threat_jq.sh"
            if script_path.exists():
                cmd = [str(script_path), file_path, 'extract']
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')
                    json_start = next((i for i, line in enumerate(lines) if line.startswith('{')), 0)
                    json_data = '\n'.join(lines[json_start:])
                    
                    extracted = json.loads(json_data)
                    
                    return {
                        'application_context': extracted.get('application', {}),
                        'threats': extracted.get('threats', []),
                        'total_threats': extracted.get('summary', {}).get('total', 0),
                        'priority_counts': {
                            'high': extracted.get('summary', {}).get('high', 0),
                            'medium': extracted.get('summary', {}).get('medium', 0),
                            'low': extracted.get('summary', {}).get('low', 0)
                        }
                    }
        except Exception as e:
            print(f"JQ extraction failed for {file_path}: {e}")
        
        # Fallback to Python extraction
        return self._python_extract(file_path)
    
    def _python_extract(self, file_path: str) -> Optional[Dict[str, Any]]:
        """Fallback Python extraction for ThreatComposer format"""
        try:
            # Skip unsupported files
            if not self._is_text_file(file_path):
                return None
            
            # Handle binary files (images, PDFs) - mark for Bedrock processing
            if self._is_binary_file(file_path):
                return {
                    'file_type': 'binary',
                    'file_path': file_path,
                    'requires_bedrock': True
                }
                
            # Handle text files
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            if 'threats' in data and 'applicationInfo' in data:
                return self._extract_threatcomposer(data)
            
            return None
        except:
            return None
    
    def _is_text_file(self, file_path: str) -> bool:
        """Check if file can be processed (text files, images, PDFs)"""
        import os
        
        # Check file extension
        supported_extensions = {
            # Text files
            '.json', '.tc', '.yaml', '.yml', '.md', '.txt', '.csv',
            # Images for Bedrock analysis
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp',
            # Documents for Bedrock analysis
            '.pdf'
        }
        _, ext = os.path.splitext(file_path.lower())
        
        if ext in supported_extensions:
            return True
            
        # For files without extension, try to detect if it's text
        try:
            with open(file_path, 'rb') as f:
                chunk = f.read(1024)
                if not chunk:
                    return True  # Empty file
                # Check if it's mostly text (no null bytes)
                return b'\x00' not in chunk
        except:
            return False
    
    def _is_binary_file(self, file_path: str) -> bool:
        """Check if file is binary (images, PDFs) that needs special handling"""
        import os
        
        binary_extensions = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.pdf'}
        _, ext = os.path.splitext(file_path.lower())
        return ext in binary_extensions
    
    def _extract_threatcomposer(self, data: Dict) -> Dict[str, Any]:
        """Extract ThreatComposer format"""
        result = {
            'application_context': {},
            'threats': [],
            'total_threats': 0,
            'priority_counts': {'high': 0, 'medium': 0, 'low': 0}
        }
        
        # Application context
        if 'applicationInfo' in data:
            result['application_context'] = {
                'name': data['applicationInfo'].get('name', 'Unknown'),
                'description': data['applicationInfo'].get('description', ''),
                'technologies': data['applicationInfo'].get('technologies', [])
            }
        
        # Extract threats with priorities from metadata
        for threat in data.get('threats', []):
            priority = 'medium'  # default
            
            if 'metadata' in threat:
                for meta in threat['metadata']:
                    if meta.get('key') == 'Priority':
                        priority = meta.get('value', 'medium').lower()
                        break
            
            threat_obj = {
                'id': threat.get('id', ''),
                'statement': threat.get('statement', ''),
                'priority': priority,
                'impact': threat.get('threatImpact', ''),
                'source': threat.get('threatSource', ''),
                'action': threat.get('threatAction', '')
            }
            
            result['threats'].append(threat_obj)
            result['priority_counts'][priority] += 1
        
        result['total_threats'] = len(result['threats'])
        return result
    
    def _detect_format(self, file_path: str) -> str:
        """Detect file format"""
        if 'threatcomposer' in file_path.lower() or file_path.endswith('.tc'):
            return 'threatcomposer'
        elif 'threat' in file_path.lower():
            return 'generic_threat_model'
        else:
            return 'unknown'
    
    def _categorize_file(self, file_path: Path, context_files: Dict[str, List]) -> None:
        """Categorize non-threat files"""
        name_lower = file_path.name.lower()
        
        # Skip if already categorized as threat model
        if str(file_path) in context_files["threat_models"]:
            return
        
        # Check if file has 'threat' in name and contains threat statements
        if "threat" in name_lower and file_path.suffix.lower() == ".md":
            if self._contains_threat_statements(file_path):
                context_files["threat_models"].append(str(file_path))
                return
        
        # Generated threat statement files should be treated as threat models
        if "generated_threat_statements" in name_lower:
            context_files["threat_models"].append(str(file_path))
            return  # Don't categorize as README
        # READMEs and markdown files
        elif name_lower.startswith("readme") or file_path.suffix.lower() == ".md":
            context_files["readmes"].append(str(file_path))
        # Architecture diagrams - expanded image support
        elif any(keyword in name_lower for keyword in ["architecture", "arch", "design", "system", "diagram"]):
            if file_path.suffix.lower() in [".png", ".jpg", ".jpeg", ".pdf", ".svg", ".puml", ".md", ".mmd", ".drawio"]:
                context_files["architecture_diagrams"].append(str(file_path))
        # Data flow diagrams
        elif any(keyword in name_lower for keyword in ["dataflow", "data_flow", "dfd", "flow"]):
            context_files["data_flow_diagrams"].append(str(file_path))
        # Any image files that might be diagrams
        elif file_path.suffix.lower() in [".png", ".jpg", ".jpeg", ".pdf"]:
            context_files["architecture_diagrams"].append(str(file_path))
        # Other documentation
        elif file_path.suffix.lower() in [".md", ".txt", ".doc", ".docx", ".pdf"]:
            context_files["other_docs"].append(str(file_path))
    
    def _contains_threat_statements(self, file_path: Path) -> bool:
        """Check if a file contains threat statements"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read().lower()
                
            # Look for threat statement indicators
            threat_indicators = [
                "threat statement",
                "threat description",
                "threat source",
                "threat action",
                "threat impact",
                "high priority",
                "medium priority", 
                "low priority",
                "severity",
                "can perform",
                "which leads to",
                "resulting in"
            ]
            
            # Check if file contains multiple threat indicators
            indicator_count = sum(1 for indicator in threat_indicators if indicator in content)
            return indicator_count >= 3  # Require at least 3 indicators to be confident
            
        except Exception as e:
            self.logger.warning(f"Could not read file {file_path}: {e}")
            return False
    
    def _parse_file(self, file_path: Path) -> Optional[str]:
        """Parse file content"""
        try:
            if file_path.suffix.lower() in [".md", ".txt", ".json", ".yaml", ".yml"]:
                with open(file_path, 'r', encoding='utf-8') as f:
                    return f.read()
        except Exception:
            pass
        return None
    
    def _generate_enhanced_summary(self, threat_analysis: Dict[str, Any], parsed_files: Dict[str, Any], discovered_files: Dict[str, Any] = None) -> str:
        """Generate enhanced summary with threat model focus"""
        summary = []
        
        # Application context
        ctx = threat_analysis.get('application_context', {})
        if ctx.get('name'):
            summary.append(f"📱 Application: {ctx['name']}")
        
        if ctx.get('technologies'):
            tech_list = ', '.join(ctx['technologies'][:8])
            summary.append(f"🔧 Technologies: {tech_list}")
        
        # Threat summary
        total_threats = threat_analysis.get('total_threats', 0)
        discovered_threat_models = len(discovered_files.get('threat_models', [])) if discovered_files else 0
        
        if total_threats > 0 or discovered_threat_models > 0:
            if total_threats > 0:
                priorities = threat_analysis.get('priority_summary', {})
                summary.append(f"🎯 Threats: {total_threats} total (H:{priorities.get('high', 0)}, M:{priorities.get('medium', 0)}, L:{priorities.get('low', 0)})")
                
                # High priority threats preview
                high_threats = threat_analysis.get('high_priority_threats', [])[:3]
                if high_threats:
                    summary.append("🚨 Key High Priority Threats:")
                    for i, threat in enumerate(high_threats, 1):
                        summary.append(f"   {i}. {threat['statement']}...")
            else:
                summary.append(f"📄 Found {discovered_threat_models} threat model files")
        else:
            # No threat models found - check for minimal viable inputs
            # Use discovered_files for diagrams (includes images that can't be parsed)
            has_diagrams = len(discovered_files.get('architecture_diagrams', [])) > 0 if discovered_files else False
            has_docs = len(parsed_files.get('readmes', [])) + len(parsed_files.get('other_docs', [])) > 0
            
            if has_diagrams or has_docs:
                summary.append("🤖 No threat models found - will generate threats using AI analysis")
                summary.append("📋 Available for analysis:")
                if has_diagrams:
                    diagram_count = len(discovered_files.get('architecture_diagrams', [])) if discovered_files else 0
                    summary.append(f"   • {diagram_count} architecture diagrams")
                if has_docs:
                    doc_count = len(parsed_files.get('readmes', [])) + len(parsed_files.get('other_docs', []))
                    summary.append(f"   • {doc_count} documentation files")
            else:
                summary.append("⚠️  Limited inputs - analysis may be basic")
        
        # File counts - include architecture diagrams from discovered_files
        file_counts = []
        if discovered_files:
            for category, files in discovered_files.items():
                if files and category != 'threat_models':
                    file_counts.append(f"{category}: {len(files)}")
        else:
            for category, files in parsed_files.items():
                if files:
                    file_counts.append(f"{category}: {len(files)}")
        
        if file_counts:
            summary.append(f"📄 Files: {', '.join(file_counts)}")
        
        return '\n'.join(summary)
    
    def _extract_enhanced_context_via_bedrock(self, context_files: Dict[str, Any]) -> Dict[str, Any]:
        """Extract enhanced application context from images, PDFs, and markdown via Bedrock"""
        try:
            import boto3
            import json
            import base64
            from pathlib import Path
            
            # Collect files for Bedrock analysis
            files_to_analyze = []
            
            # Add images and PDFs
            for category in ['architecture_diagrams', 'readmes']:
                for file_path in context_files.get(category, []):
                    if self._is_binary_file(file_path) or file_path.lower().endswith('.md'):
                        files_to_analyze.append(file_path)
            
            if not files_to_analyze:
                return {}
            
            self.logger.info(f"Analyzing {len(files_to_analyze)} files via Bedrock for enhanced context")
            
            # Prepare Bedrock request with multimodal content
            bedrock = boto3.client('bedrock-runtime', region_name='us-east-1')
            
            # Use model from context or default to Claude Sonnet 4
            model_id = context_files.get('model_id', 'us.anthropic.claude-sonnet-4-20250514-v1:0')
            
            content_parts = []
            
            # Add text prompt
            content_parts.append({
                "type": "text",
                "text": """Analyze the provided files to extract comprehensive application context information. 

Extract and provide:
1. **Application Name**: The name of the system/application
2. **Industry**: Healthcare, Finance, E-commerce, etc.
3. **Architecture Type**: Microservices, Monolithic, Serverless, etc.
4. **Components**: List all system components, services, databases
5. **Technologies**: Programming languages, frameworks, cloud services
6. **Data Flows**: How data moves through the system
7. **Security Controls**: Existing security measures
8. **Deployment Environment**: Cloud provider, regions, etc.
9. **Integration Points**: External systems, APIs, third-party services
10. **Compliance Requirements**: Any regulatory requirements mentioned

Provide a structured JSON response with these fields."""
            })
            
            # Add file content
            for file_path in files_to_analyze[:3]:  # Limit to 3 files for token management
                try:
                    if self._is_binary_file(file_path):
                        # Handle images and PDFs
                        with open(file_path, 'rb') as f:
                            file_data = base64.b64encode(f.read()).decode('utf-8')
                            
                        if file_path.lower().endswith(('.jpg', '.jpeg', '.png')):
                            content_parts.append({
                                "type": "image",
                                "source": {
                                    "type": "base64",
                                    "media_type": "image/jpeg" if file_path.lower().endswith(('.jpg', '.jpeg')) else "image/png",
                                    "data": file_data
                                }
                            })
                    else:
                        # Handle text files
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()[:5000]  # Limit content size
                            content_parts.append({
                                "type": "text",
                                "text": f"File: {Path(file_path).name}\n\n{content}"
                            })
                except Exception as e:
                    self.logger.warning(f"Failed to process {file_path}: {e}")
            
            request_body = {
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": 2000,
                "messages": [
                    {
                        "role": "user",
                        "content": content_parts
                    }
                ]
            }
            
            response = bedrock.invoke_model(
                modelId=model_id,
                body=json.dumps(request_body)
            )
            
            response_body = json.loads(response['body'].read())
            enhanced_context_text = response_body['content'][0]['text']
            
            # Try to parse as JSON, fallback to text parsing
            try:
                enhanced_context = json.loads(enhanced_context_text)
            except:
                # Parse text response
                enhanced_context = self._parse_context_from_text(enhanced_context_text)
            
            self.logger.info(f"Enhanced context extracted via Bedrock")
            return enhanced_context
            
        except Exception as e:
            self.logger.warning(f"Failed to extract enhanced context via Bedrock: {e}")
            return {}
    
    def _parse_context_from_text(self, text: str) -> Dict[str, Any]:
        """Parse context information from text response"""
        context = {}
        
        # Simple text parsing for key information
        lines = text.split('\n')
        
        for line in lines:
            line = line.strip()
            if ':' in line and any(key in line.lower() for key in ['application', 'industry', 'architecture', 'components', 'technologies']):
                parts = line.split(':', 1)
                if len(parts) == 2:
                    key = parts[0].strip().lower().replace(' ', '_')
                    value = parts[1].strip()
                    context[key] = value
        
        return context
