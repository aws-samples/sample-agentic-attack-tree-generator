"""Summary generation for context analysis results"""
from typing import Dict, Any
from pathlib import Path


class SummaryGenerator:
    """Generates human-readable summaries"""
    
    @staticmethod
    def generate_summary(parsed_files: Dict[str, Any],
                        discovered_files: Dict[str, Any] = None) -> str:
        """Generate summary of discovered files for context analysis"""
        summary = []
        
        # Threat model discovery (not parsing - just reporting what was found)
        discovered_threat_models = len(discovered_files.get('threat_models', [])) if discovered_files else 0
        
        if discovered_threat_models > 0:
            summary.append(f"📄 Found {discovered_threat_models} threat model file(s)")
            for tm_path in discovered_files.get('threat_models', [])[:3]:
                summary.append(f"   • {Path(tm_path).name}")
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
