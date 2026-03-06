"""Attack tree enricher with TTC mappings"""
import re
from typing import Dict, List, Any
from pathlib import Path
from ...utils.logger import ThreatForestLogger

class AttackTreeEnricher:
    """Enrich attack trees with TTC technique mappings"""
    
    def __init__(self, matcher):
        """
        Initialize enricher
        
        Args:
            matcher: TTCMatcher instance
        """
        self.matcher = matcher
        self.logger = ThreatForestLogger.get_logger(self.__class__.__name__)
    
    def extract_attack_steps(self, markdown_or_mermaid: str) -> List[str]:
        """Extract attack steps from mermaid diagram (wrapped or unwrapped)"""
        # Try to extract from markdown code block first
        mermaid_match = re.search(r'```mermaid\n(.*?)\n```', markdown_or_mermaid, re.DOTALL)
        if mermaid_match:
            mermaid_content = mermaid_match.group(1)
        else:
            # Assume it's already raw mermaid code
            mermaid_content = markdown_or_mermaid
        
        steps = []
        for line in mermaid_content.split('\n'):
            # Extract text from nodes: ["text"] or ["text<br/>more"]
            matches = re.findall(r'\["([^"]+)"\]', line)
            for match in matches:
                # Clean up HTML tags like <br/>
                clean_text = re.sub(r'<br\/?>.*', '', match).strip()
                if clean_text:
                    steps.append(clean_text)
        
        return list(set(steps))
    
    def enrich_mermaid_diagram(self, markdown_content: str, matches: List[Dict[str, Any]]) -> str:
        """Add technique IDs to mermaid diagram nodes"""
        step_to_technique = {
            m['attack_step']: m['matches'][0]['technique_id'] 
            for m in matches if m['matches']
        }
        
        def replace_node(match):
            step_text = match.group(1)
            if step_text in step_to_technique:
                tech_id = step_to_technique[step_text]
                return f'["{step_text}<br/><small>{tech_id}</small>"]'
            return match.group(0)
        
        enriched = re.sub(r'\["([^"]+)"\]', replace_node, markdown_content)
        return enriched
    
    def create_technique_table(self, matches: List[Dict[str, Any]]) -> str:
        """Create markdown table of technique mappings"""
        if not matches:
            return ""
        
        table = "\n## TTC Technique Mappings\n\n"
        table += "| Attack Step | Technique ID | Technique Name | Confidence | Similarity |\n"
        table += "|-------------|--------------|----------------|------------|------------|\n"
        
        for match in matches:
            step = match['attack_step']
            if match['matches']:
                best = match['matches'][0]
                confidence_emoji = '🟢' if best['confidence'] == 'high' else '🟡' if best['confidence'] == 'medium' else '🔴'
                table += f"| {step} | {best['technique_id']} | {best['name']} | {confidence_emoji} {best['confidence']} | {best['similarity']:.3f} |\n"
        
        return table
    
    def enrich_attack_tree(self, markdown_content: str) -> str:
        """
        Enrich attack tree markdown with TTC mappings
        
        Args:
            markdown_content: Original attack tree markdown
            
        Returns:
            Enriched markdown with technique IDs and mapping table
        """
        steps = self.extract_attack_steps(markdown_content)
        if not steps:
            return markdown_content
        
        self.logger.info(f"🔗 Matching {len(steps)} attack steps to TTC techniques...")
        matches = self.matcher.match_steps(steps)
        
        matched_count = sum(1 for m in matches if m['matches'])
        self.logger.info(f"✓ Matched {matched_count} of {len(steps)} steps to techniques")
        
        enriched = self.enrich_mermaid_diagram(markdown_content, matches)
        technique_table = self.create_technique_table(matches)
        
        if technique_table:
            enriched += technique_table
        
        return enriched
    
    def enrich_file(self, input_path: str, output_path: str):
        """
        Enrich attack tree file
        
        Args:
            input_path: Path to input markdown file
            output_path: Path to save enriched file
        """
        self.logger.info(f"📄 Enriching {Path(input_path).name}")
        with open(input_path, 'r') as f:
            content = f.read()
        
        enriched = self.enrich_attack_tree(content)
        
        with open(output_path, 'w') as f:
            f.write(enriched)
        self.logger.info(f"✓ Saved enriched file to {Path(output_path).name}")
    
    def enrich_directory(self, input_dir: str, output_dir: str, pattern: str = "attack_tree_*.md"):
        """
        Enrich all attack tree files in directory
        
        Args:
            input_dir: Input directory path
            output_dir: Output directory path
            pattern: File pattern to match
        """
        input_path = Path(input_dir)
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        for file_path in input_path.glob(pattern):
            output_file = output_path / f"enriched_{file_path.name}"
            self.enrich_file(str(file_path), str(output_file))
        
        # Update threatforest_data.json if it exists
        self._update_json_export(input_path, "enriched")
    
    def _update_json_export(self, base_dir: Path, phase: str):
        """Update threatforest_data.json with enrichment/mitigation status"""
        import json
        json_file = base_dir / "threatforest_data.json"
        if not json_file.exists():
            return
        
        try:
            with open(json_file, 'r') as f:
                data = json.load(f)
            
            # Add enrichment metadata
            if 'enrichment_summary' not in data:
                data['enrichment_summary'] = {}
            
            data['enrichment_summary']['phase'] = phase
            data['enrichment_summary']['status'] = 'complete'
            
            with open(json_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            self.logger.info(f"✓ Updated threatforest_data.json with {phase} status")
            
            # Update analysis report
            self._update_analysis_report(base_dir, phase)
        except Exception as e:
            self.logger.warning(f"Failed to update JSON export: {e}")
    
    def _update_analysis_report(self, base_dir: Path, phase: str):
        """Update threatforest_analysis_report.md with enrichment status"""
        report_file = base_dir / "threatforest_analysis_report.md"
        if not report_file.exists():
            return
        
        try:
            content = report_file.read_text()
            
            # Add enrichment section if not present
            enrichment_section = f"\n\n---\n\n## 🎯 TTC Enrichment Status\n\n**Phase**: {phase}  \n**Status**: ✅ Complete  \n**Updated**: {self._get_timestamp()}\n\nAttack trees have been enriched with MITRE ATT&CK TTC technique mappings. Each attack step is now mapped to relevant techniques with confidence scores.\n"
            
            if "## 🎯 TTC Enrichment Status" not in content:
                # Insert before the final "Generated by" line
                if "*Generated by ThreatForest" in content:
                    content = content.replace("---\n*Generated by ThreatForest", enrichment_section + "\n---\n*Generated by ThreatForest")
                else:
                    content += enrichment_section
            else:
                # Update existing section
                import re
                pattern = r"## 🎯 TTC Enrichment Status.*?(?=\n##|\n---|\Z)"
                content = re.sub(pattern, enrichment_section.strip(), content, flags=re.DOTALL)
            
            report_file.write_text(content)
            self.logger.info(f"✓ Updated analysis report with {phase} status")
        except Exception as e:
            self.logger.warning(f"Failed to update analysis report: {e}")
    
    def _get_timestamp(self):
        """Get current timestamp"""
        from datetime import datetime
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
