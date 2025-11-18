"""Threat extraction with JQ and Python fallback"""
import json
import subprocess
import os
from pathlib import Path
from typing import Dict, Any, Optional, List
from .file_categorizer import FileCategorizer


class ThreatExtractor:
    """Extracts threats from various formats using JQ or Python"""
    
    def __init__(self, logger):
        self.logger = logger
        self.categorizer = FileCategorizer(logger)
    
    def process_threat_models(self, threat_files: List[str]) -> Dict[str, Any]:
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
                threat_data = self.extract_threats_enhanced(file_path)
                if threat_data and 'threats' in threat_data:
                    file_analysis = {
                        'file': file_path,
                        'format': self.detect_format(file_path),
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
    
    def extract_threats_enhanced(self, file_path: str) -> Optional[Dict[str, Any]]:
        """Extract threats using JQ or Python fallback"""
        try:
            # Try JQ-style extraction first
            script_path = Path(__file__).parent.parent / "threat_jq.sh"
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
            self.logger.debug(f"JQ extraction failed for {file_path}: {e}")
        
        # Fallback to Python extraction
        return self._python_extract(file_path)
    
    def _python_extract(self, file_path: str) -> Optional[Dict[str, Any]]:
        """Python fallback extraction"""
        try:
            if not self.categorizer.is_text_file(file_path):
                return None
            
            if self.categorizer.is_binary_file(file_path):
                return {'file_type': 'binary', 'file_path': file_path, 'requires_bedrock': True}
            
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
        
        # Extract threats with priorities
        for threat in data.get('threats', []):
            priority = 'medium'
            
            if 'metadata' in threat:
                for meta in threat['metadata']:
                    if meta.get('key') == 'Priority':
                        priority = meta.get('value', 'medium').lower()
                        break
            
            result['threats'].append({
                'id': threat.get('id', ''),
                'statement': threat.get('statement', ''),
                'priority': priority,
                'impact': threat.get('threatImpact', ''),
                'source': threat.get('threatSource', ''),
                'action': threat.get('threatAction', '')
            })
            result['priority_counts'][priority] += 1
        
        result['total_threats'] = len(result['threats'])
        return result
    
    def detect_format(self, file_path: str) -> str:
        """Detect file format"""
        if 'threatcomposer' in file_path.lower() or file_path.endswith('.tc'):
            return 'threatcomposer'
        elif 'threat' in file_path.lower():
            return 'generic_threat_model'
        return 'unknown'
