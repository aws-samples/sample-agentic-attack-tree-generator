#!/usr/bin/env python3
"""
Flexible threat statement extractor for ThreatForest
Handles various file formats including ThreatComposer workspaces
"""

import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional

class ThreatExtractor:
    def __init__(self):
        self.priority_map = {
            'high': 3, 'medium': 2, 'low': 1,
            'critical': 4, 'info': 0
        }
    
    def extract_from_file(self, file_path: str) -> Dict[str, Any]:
        """Extract threats from various file formats"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Handle ThreatComposer format
            if 'threats' in data or 'threatStatements' in data:
                return self._extract_threatcomposer(data)
            
            # Handle generic threat model format
            if 'threat_model' in data:
                return self._extract_generic(data)
            
            # Fallback: search for threat-like structures
            return self._extract_fallback(data)
            
        except Exception as e:
            return {'error': f"Failed to parse {file_path}: {str(e)}"}
    
    def _extract_threatcomposer(self, data: Dict) -> Dict[str, Any]:
        """Extract from ThreatComposer workspace format"""
        result = {
            'application_context': {},
            'threats': [],
            'total_threats': 0,
            'priority_counts': {'high': 0, 'medium': 0, 'low': 0}
        }
        
        # Extract application context
        if 'applicationInfo' in data:
            result['application_context'] = {
                'name': data['applicationInfo'].get('name', 'Unknown'),
                'description': data['applicationInfo'].get('description', ''),
                'technologies': data['applicationInfo'].get('technologies', [])
            }
        
        # Extract threats
        threats = data.get('threats', data.get('threatStatements', []))
        for threat in threats:
            priority = self._normalize_priority(threat.get('priority', 'medium'))
            
            threat_obj = {
                'id': threat.get('id', ''),
                'statement': threat.get('statement', threat.get('description', '')),
                'priority': priority,
                'category': threat.get('category', ''),
                'mitigation': threat.get('mitigation', '')
            }
            
            result['threats'].append(threat_obj)
            result['priority_counts'][priority] += 1
        
        result['total_threats'] = len(result['threats'])
        return result
    
    def _extract_generic(self, data: Dict) -> Dict[str, Any]:
        """Extract from generic threat model format"""
        result = {
            'application_context': data.get('application_info', {}),
            'threats': [],
            'total_threats': 0,
            'priority_counts': {'high': 0, 'medium': 0, 'low': 0}
        }
        
        threats = data.get('threat_model', {}).get('threats', [])
        for threat in threats:
            priority = self._normalize_priority(threat.get('severity', 'medium'))
            
            threat_obj = {
                'statement': threat.get('description', ''),
                'priority': priority,
                'category': threat.get('category', ''),
                'impact': threat.get('impact', '')
            }
            
            result['threats'].append(threat_obj)
            result['priority_counts'][priority] += 1
        
        result['total_threats'] = len(result['threats'])
        return result
    
    def _extract_fallback(self, data: Dict) -> Dict[str, Any]:
        """Fallback extraction for unknown formats"""
        result = {
            'application_context': {},
            'threats': [],
            'total_threats': 0,
            'priority_counts': {'high': 0, 'medium': 0, 'low': 0}
        }
        
        # Search for threat-like keys
        threat_keys = ['threats', 'risks', 'vulnerabilities', 'issues']
        for key in threat_keys:
            if key in data and isinstance(data[key], list):
                for item in data[key]:
                    if isinstance(item, dict):
                        priority = self._normalize_priority(
                            item.get('priority', item.get('severity', 'medium'))
                        )
                        
                        threat_obj = {
                            'statement': item.get('description', item.get('title', str(item))),
                            'priority': priority,
                            'source_key': key
                        }
                        
                        result['threats'].append(threat_obj)
                        result['priority_counts'][priority] += 1
                break
        
        result['total_threats'] = len(result['threats'])
        return result
    
    def _normalize_priority(self, priority: str) -> str:
        """Normalize priority to standard values"""
        if not priority:
            return 'medium'
        
        priority_lower = str(priority).lower()
        
        if priority_lower in ['high', 'critical', '3', '4']:
            return 'high'
        elif priority_lower in ['low', '1']:
            return 'low'
        else:
            return 'medium'
    
    def print_summary(self, extracted: Dict[str, Any]):
        """Print token-efficient summary"""
        if 'error' in extracted:
            print(f"❌ {extracted['error']}")
            return
        
        ctx = extracted['application_context']
        print(f"📱 App: {ctx.get('name', 'Unknown')}")
        
        if ctx.get('technologies'):
            print(f"🔧 Tech: {', '.join(ctx['technologies'][:5])}")
        
        counts = extracted['priority_counts']
        print(f"🎯 Threats: {extracted['total_threats']} total")
        print(f"   High: {counts['high']}, Medium: {counts['medium']}, Low: {counts['low']}")
        
        # Show top 3 high priority threats
        high_threats = [t for t in extracted['threats'] if t['priority'] == 'high'][:3]
        if high_threats:
            print("🚨 Top High Priority:")
            for i, threat in enumerate(high_threats, 1):
                print(f"   {i}. {threat['statement'][:80]}...")

def main():
    if len(sys.argv) != 2:
        print("Usage: python threat_extractor.py <file_path>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    if not os.path.exists(file_path):
        print(f"❌ File not found: {file_path}")
        sys.exit(1)
    
    extractor = ThreatExtractor()
    result = extractor.extract_from_file(file_path)
    extractor.print_summary(result)
    
    # Output JSON for further processing
    print("\n" + "="*50)
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()
