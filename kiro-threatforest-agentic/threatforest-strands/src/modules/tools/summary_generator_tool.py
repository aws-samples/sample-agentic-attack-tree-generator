"""Summary Generator Tool for creating comprehensive threat analysis reports"""
from typing import Dict, Any, List
from pathlib import Path
from ..utils.logger import ThreatForestLogger
from ..core import Tool, tool
import json
from datetime import datetime


class SummaryGeneratorTool(Tool):
    """Tool for generating comprehensive summary reports"""
    
    def __init__(self):
        super().__init__(
            name="summary_generator",
            description="Generate comprehensive threat analysis reports with attack trees and TTC mappings"
        )
        self.logger = ThreatForestLogger.get_logger(self.__class__.__name__)
    
    async def execute(self, attack_trees: Dict[str, Any], 
                     extracted_info: Dict[str, Any],
                     output_dir: str) -> Dict[str, Any]:
        """Execute summary generation"""
        
        try:
            output_path = Path(output_dir)
            output_path.mkdir(parents=True, exist_ok=True)
            
            # Handle None inputs
            if attack_trees is None:
                attack_trees = {}
            if extracted_info is None:
                extracted_info = {}
            
            project_info = extracted_info.get('project_info', {})
            extraction_summary = extracted_info.get('extraction_summary', {})
            
            # Generate main summary report
            try:
                summary_file = self._generate_main_summary(
                    output_path, attack_trees, extracted_info
                )
            except Exception as e:
                self.logger.warning(f"Main summary generation failed: {e}")
                summary_file = None
            
            # Generate individual attack tree files
            try:
                # Handle both mapped and unmapped attack trees
                trees_to_process = []
                if attack_trees and isinstance(attack_trees, dict):
                    trees_to_process = attack_trees.get('ttc_mapped_trees', [])
                    if not trees_to_process:
                        trees_to_process = attack_trees.get('attack_trees', [])
                elif attack_trees and isinstance(attack_trees, list):
                    trees_to_process = attack_trees
                
                tree_files = self._generate_attack_tree_files(
                    output_path, trees_to_process
                )
            except Exception as e:
                self.logger.warning(f"Attack tree files generation failed: {e}")
                import traceback
                traceback.print_exc()
                tree_files = []
            
            # Skip TTC mapping report generation
            ttc_file = None
            
            # Generate JSON data export
            try:
                json_file = self._generate_json_export(
                    output_path, attack_trees, extracted_info
                )
            except Exception as e:
                self.logger.warning(f"JSON export generation failed: {e}")
                json_file = None
            
            # Collect output files
            output_files = []
            if summary_file:
                output_files.append(summary_file)
            if ttc_file:
                output_files.append(ttc_file)
            if json_file:
                output_files.append(json_file)
            output_files.extend(tree_files)
            
            return {
                'output_files': output_files,
                'summary_file': summary_file,
                'ttc_file': ttc_file,
                'json_file': json_file,
                'tree_files': tree_files
            }
            
        except Exception as e:
            self.logger.warning(f"Summary generation execute failed: {e}")
            import traceback
            traceback.print_exc()
            return {'output_files': []}
    
    def _generate_main_summary(self, output_path: Path, attack_trees: Dict[str, Any], 
                              extracted_info: Dict[str, Any]) -> str:
        """Generate main summary report"""
        
        project_info = extracted_info.get('project_info', {})
        extraction_summary = extracted_info.get('extraction_summary', {})
        
        # Handle both mapped and unmapped attack trees
        trees = attack_trees.get('ttc_mapped_trees', [])
        if not trees:
            trees = attack_trees.get('attack_trees', [])
        successful_trees = [t for t in trees if 'mermaid_code' in t]
        
        summary_content = f"""# ThreatForest Analysis Report

**Generated on:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Executive Summary

This report presents a comprehensive threat analysis for **{project_info.get('application_name', 'Unknown Application')}**, including attack tree modeling.

## Project Information

- **Application Name**: {project_info.get('application_name', 'Unknown')}
- **Architecture Type**: {project_info.get('architecture_type', 'Unknown')}
- **Deployment Environment**: {project_info.get('deployment_environment', 'Unknown')}
- **Industry Sector**: {project_info.get('sector', 'Unknown')}

### Technology Stack
{self._format_technologies(project_info.get('technologies', []))}

### Security Objectives
{self._format_security_objectives(project_info.get('security_objectives', {}))}

## Threat Analysis Results

### Threat Summary
- **Total Threats Identified**: {extraction_summary.get('total_threats', 0)}
- **High Severity Threats**: {extraction_summary.get('high_severity_count', 0)}
- **Attack Trees Generated**: {len(successful_trees)}

### High Severity Threats
{self._format_high_severity_threats(extracted_info.get('high_severity_threats', []))}

## Attack Tree Analysis

### Generated Attack Trees
{self._format_attack_trees_summary(successful_trees)}

## Recommendations

### Immediate Actions
1. **Address High Severity Threats**: Focus on the {extraction_summary.get('high_severity_count', 0)} high severity threats identified
2. **Implement Security Controls**: Deploy mitigations identified in attack trees
3. **Review Attack Paths**: Analyze generated attack trees for potential vulnerabilities

### Strategic Improvements
1. **Architecture Review**: Consider security implications of {project_info.get('architecture_type', 'current')} architecture
2. **Technology Assessment**: Evaluate security posture of identified technologies
3. **Threat Modeling**: Regular updates to threat model as application evolves

## Appendix

### Files Generated
- Main Summary Report (this file)
- Individual Attack Tree Files (.mmd format)
- JSON Data Export

---
*Generated by ThreatForest - Automated Threat Modeling and Attack Tree Generation*
"""
        
        summary_file = output_path / "threatforest_analysis_report.md"
        summary_file.write_text(summary_content)
        
        return str(summary_file)
    
    def _generate_attack_tree_files(self, output_path: Path, trees: List[Dict[str, Any]]) -> List[str]:
        """Generate individual attack tree files"""
        
        tree_files = []
        
        if not trees:
            return tree_files
        
        for idx, tree in enumerate(trees, 1):
            if not isinstance(tree, dict) or 'mermaid_code' not in tree:
                continue
                
            threat_id = tree.get('threat_id', tree.get('id', 'unknown'))
            threat_statement = tree.get('threat_statement', tree.get('description', 'No description available'))
            category = tree.get('threat_category', tree.get('category', 'Unknown'))
            
            # Extract and condense threat statement to key words
            import re
            # Remove common words and extract key terms
            short_desc = threat_statement.split('-')[0].strip() if '-' in threat_statement else threat_statement.split('\n')[0].strip()
            
            # Remove common filler words
            stop_words = ['threat', 'an', 'a', 'the', 'can', 'could', 'may', 'might', 'who', 'with', 'to', 'of', 'in', 'on', 'at', 'for', 'by']
            words = short_desc.lower().split()
            key_words = [w for w in words if w not in stop_words and len(w) > 2][:4]  # Max 4 key words
            
            # Create condensed description
            short_desc_clean = '_'.join(key_words) if key_words else 'threat'
            short_desc_clean = re.sub(r'[^\w_]', '', short_desc_clean)
            
            # Use sequential number (001, 002, etc.) instead of threat_id
            filename = f"attack_tree_{idx:03d}_{short_desc_clean}.md"
                
            file_path = output_path / filename
            
            # Create content without TTC mappings
            content = f"""# Attack Tree: {category}

**Threat ID**: {threat_id}  
**Threat Number**: {idx}
**Associated threat statement**: {threat_statement}

## Attack Tree Diagram

```mermaid
{tree.get('mermaid_code', '')}
```

## Attack Path Analysis

This attack tree represents the potential attack paths for the identified threat. Each node in the tree represents either:
- **Attack Goal** (orange): The ultimate objective
- **Attack Step** (red): Individual attack actions
- **Fact/Condition** (blue): Prerequisites or conditions
- **Mitigation** (green): Defensive measures

Review this attack tree to:
1. Identify critical attack paths
2. Implement appropriate security controls
3. Monitor for indicators of these attack patterns
4. Develop incident response procedures

---
*Generated by ThreatForest - Attack Tree Analysis*
"""
            
            try:
                file_path.write_text(content, encoding='utf-8')
                tree_files.append(str(file_path))
                print(f"💾 Generated attack tree file: {filename}")
            except Exception as e:
                self.logger.warning(f"Failed to write attack tree file {filename}: {e}")
        
        return tree_files
    
    def _generate_ttc_report(self, output_path: Path, attack_trees: Dict[str, Any]) -> str:
        """Generate TTC mapping report"""
        
        # Handle None or missing attack_trees
        if not attack_trees:
            attack_trees = {}
        
        mapping_summary = attack_trees.get('mapping_summary', {})
        trees = attack_trees.get('ttc_mapped_trees', [])
        
        # Collect all mappings with error handling
        all_mappings = []
        for tree in trees:
            if not tree:
                continue
            ttc_mappings = tree.get('ttc_mappings', [])
            if not ttc_mappings:
                continue
                
            for mapping in ttc_mappings:
                if not mapping:
                    continue
                # Handle different mapping structures
                if 'mapped_techniques' in mapping:
                    all_mappings.extend(mapping.get('mapped_techniques', []))
                else:
                    # Direct mapping structure
                    all_mappings.append(mapping)
        
        # Count technique frequencies
        technique_counts = {}
        for technique in all_mappings:
            if not technique:
                continue
            tech_id = technique.get('technique_id', 'Unknown')
            if tech_id not in technique_counts:
                technique_counts[tech_id] = {
                    'count': 0,
                    'name': technique.get('technique_name', 'Unknown'),
                    'tactics': technique.get('tactics', technique.get('tactic', []))
                }
            technique_counts[tech_id]['count'] += 1
        
        # Sort by frequency
        sorted_techniques = sorted(technique_counts.items(), key=lambda x: x[1]['count'], reverse=True)
        
        ttc_content = f"""# MITRE ATT&CK Technique Mapping Report

**Generated on:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Mapping Summary

- **Total Techniques Loaded**: {mapping_summary.get('techniques_loaded', 0)}
- **Total Mappings Found**: {mapping_summary.get('total_mappings', 0)}
- **High Confidence Mappings**: {mapping_summary.get('successful_mappings', 0)}
- **Confidence Threshold**: {mapping_summary.get('threshold_used', 0.8)}

## Most Frequently Mapped Techniques

| Technique ID | Technique Name | Frequency | Tactics |
|--------------|----------------|-----------|---------|
{self._format_technique_table(sorted_techniques[:10])}

## Detailed Mappings by Attack Tree

{self._format_detailed_mappings(trees)}

---
*Generated by ThreatForest*
"""
        
        ttc_file = output_path / "ttc_mapping_report.md"
        ttc_file.write_text(ttc_content)
        
        return str(ttc_file)
    
    def _generate_json_export(self, output_path: Path, attack_trees: Dict[str, Any], 
                             extracted_info: Dict[str, Any]) -> str:
        """Generate JSON data export"""
        
        # Handle None attack_trees
        if not attack_trees:
            attack_trees = {}
        
        # Get attack trees from the correct structure
        trees = attack_trees.get('ttc_mapped_trees', [])
        if not trees:
            trees = attack_trees.get('attack_trees', [])
        
        export_data = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "generator": "ThreatForest",
                "version": "1.0"
            },
            "project_info": extracted_info.get('project_info', {}),
            "extraction_summary": extracted_info.get('extraction_summary', {}),
            "threats": {
                "all_threats": extracted_info.get('threat_statements', []),
                "high_severity": extracted_info.get('high_severity_threats', [])
            },
            "attack_trees": trees,
            "mapping_summary": attack_trees.get('mapping_summary', {})
        }
        
        json_file = output_path / "threatforest_data.json"
        with open(json_file, 'w') as f:
            json.dump(export_data, f, indent=2)
        
        return str(json_file)
    
    # Helper formatting methods
    def _format_technologies(self, technologies: List[str]) -> str:
        if not technologies:
            return "- No technologies identified"
        return '\n'.join(f'- {tech}' for tech in technologies)
    
    def _format_security_objectives(self, objectives: Dict[str, Any]) -> str:
        if not objectives:
            return "- Security objectives not specified"
        
        result = []
        for obj, value in objectives.items():
            status = "✅ Required" if value else "❌ Not Required"
            result.append(f"- **{obj.title()}**: {status}")
        return '\n'.join(result)
    
    def _format_high_severity_threats(self, threats: List[Dict[str, Any]]) -> str:
        if not threats:
            return "No high severity threats identified."
        
        result = []
        for i, threat in enumerate(threats, 1):
            result.append(f"{i}. **{threat.get('id')}**: {threat.get('category')}")
        return '\n'.join(result)
    
    def _format_attack_trees_summary(self, trees: List[Dict[str, Any]]) -> str:
        if not trees:
            return "No attack trees generated."
        
        result = []
        for tree in trees:
            threat_id = tree.get('threat_id', 'Unknown')
            category = tree.get('threat_category', 'Unknown')
            mappings = len(tree.get('ttc_mappings', []))
            result.append(f"- **{threat_id}**: {category} ({mappings} TTC mappings)")
        return '\n'.join(result)
    
    def _format_top_techniques(self, trees: List[Dict[str, Any]]) -> str:
        # Collect all techniques
        techniques = []
        for tree in trees:
            for mapping in tree.get('ttc_mappings', []):
                techniques.extend(mapping.get('mapped_techniques', []))
        
        if not techniques:
            return "No techniques mapped."
        
        # Get top 5 by confidence
        top_techniques = sorted(techniques, key=lambda x: x.get('confidence', 0), reverse=True)[:5]
        
        result = []
        for tech in top_techniques:
            result.append(f"- **{tech.get('technique_id')}**: {tech.get('technique_name')} (Confidence: {tech.get('confidence', 0):.2f})")
        return '\n'.join(result)
    
    def _format_tree_ttc_mappings(self, mappings: List[Dict[str, Any]]) -> str:
        if not mappings:
            return "No MITRE ATT&CK mappings found for this attack tree."
        
        result = []
        for mapping in mappings:
            if not mapping:
                continue
                
            attack_step = mapping.get('attack_step', 'Unknown')
            techniques = mapping.get('mapped_techniques', [])
            
            result.append(f"### {attack_step}")
            for tech in techniques[:2]:  # Top 2 techniques
                if not tech:
                    continue
                    
                tech_id = tech.get('technique_id', 'Unknown')
                tech_name = tech.get('technique_name', 'Unknown')
                confidence = tech.get('confidence', 0)
                
                result.append(f"- **{tech_id}**: {tech_name} (Confidence: {confidence:.2f})")
                
                tactics = tech.get('tactics', tech.get('tactic', []))
                if tactics and isinstance(tactics, list):
                    result.append(f"  - Tactics: {', '.join(tactics)}")
                elif tactics and isinstance(tactics, str):
                    result.append(f"  - Tactics: {tactics}")
            result.append("")
        
        return '\n'.join(result)
    
    def _format_attack_steps(self, steps: List[Dict[str, Any]]) -> str:
        if not steps:
            return "No attack steps identified."
        
        result = []
        for i, step in enumerate(steps, 1):
            if not step:
                continue
            node_id = step.get('node_id', 'unknown')
            description = step.get('description', 'No description')
            result.append(f"{i}. **{node_id}**: {description}")
        return '\n'.join(result)
    
    def _format_technique_table(self, techniques: List[tuple]) -> str:
        if not techniques:
            return "| No techniques mapped | - | - | - |"
        
        result = []
        for tech_id, data in techniques:
            tactics = ', '.join(data['tactics']) if data['tactics'] else 'Unknown'
            result.append(f"| {tech_id} | {data['name']} | {data['count']} | {tactics} |")
        return '\n'.join(result)
    
    def _format_detailed_mappings(self, trees: List[Dict[str, Any]]) -> str:
        if not trees:
            return "No attack trees with mappings available."
        
        result = []
        for tree in trees:
            threat_id = tree.get('threat_id', 'Unknown')
            category = tree.get('threat_category', 'Unknown')
            mappings = tree.get('ttc_mappings', [])
            
            result.append(f"### {threat_id}: {category}")
            if mappings:
                for mapping in mappings:
                    attack_step = mapping.get('attack_step', 'Unknown')
                    techniques = mapping.get('mapped_techniques', [])
                    result.append(f"- **Attack Step**: {attack_step}")
                    for tech in techniques[:1]:  # Top technique only
                        result.append(f"  - {tech.get('technique_id')}: {tech.get('technique_name')} (Confidence: {tech.get('confidence', 0):.2f})")
            else:
                result.append("- No mappings found")
            result.append("")
        
        return '\n'.join(result)
