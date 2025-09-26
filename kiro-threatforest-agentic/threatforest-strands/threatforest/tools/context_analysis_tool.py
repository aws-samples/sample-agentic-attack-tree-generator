"""Enhanced Context Analysis Tool with flexible threat file handling"""
import os
import json
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Optional

# Mock Strands Tool for testing
class Tool:
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description


class ContextAnalysisTool(Tool):
    """Enhanced tool for analyzing project context with flexible threat file handling"""
    
    def __init__(self):
        super().__init__(
            name="context_analysis",
            description="Discover and analyze context files including threat models, READMEs, and architecture diagrams"
        )
        self.supported_formats = ['.json', '.tc', '.yaml', '.yml']
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
            "summary": self._generate_enhanced_summary(threat_analysis, parsed_files, context_files)
        }
    
    def _discover_threat_files(self, project_path: str) -> List[str]:
        """Discover threat-related files using enhanced detection"""
        threat_files = []
        
        for root, dirs, files in os.walk(project_path):
            for file in files:
                file_path = os.path.join(root, file)
                
                # Check by extension
                if any(file.lower().endswith(ext) for ext in self.supported_formats):
                    # Check by filename keywords
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
                print(f"⚠️  Failed to process {file_path}: {str(e)}")
        
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
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            if 'threats' in data and 'applicationInfo' in data:
                return self._extract_threatcomposer(data)
            
            return None
        except:
            return None
    
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
        
        # Generated threat statement files should be treated as threat models
        if "generated_threat_statements" in name_lower:
            context_files["threat_models"].append(str(file_path))
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
