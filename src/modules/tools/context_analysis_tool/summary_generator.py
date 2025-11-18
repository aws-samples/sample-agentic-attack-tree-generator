"""Summary generation for context analysis results"""
from typing import Dict, Any
from pathlib import Path


class SummaryGenerator:
    """Generates human-readable summaries"""
    
    @staticmethod
    def generate_summary(threat_analysis: Dict[str, Any], parsed_files: Dict[str, Any],
                        discovered_files: Dict[str, Any] = None) -> str:
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
            # No threat models - check for minimal viable inputs
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
        
        # File counts
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
