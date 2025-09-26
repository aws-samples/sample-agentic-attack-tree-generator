"""Summary Generator Tool for creating comprehensive threat analysis reports"""
from typing import Dict, Any, List
from pathlib import Path
import json
from datetime import datetime

# Mock Strands Tool for testing
class Tool:
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description


class SummaryGeneratorTool(Tool):
    """Tool for generating comprehensive summary reports"""
    
    def __init__(self):
        super().__init__(
            name="summary_generator",
            description="Generate comprehensive threat analysis reports with attack trees and TTC mappings"
        )
    
    async def execute(self, attack_trees: Dict[str, Any], 
                     extracted_info: Dict[str, Any],
                     output_dir: str) -> Dict[str, Any]:
        """Execute summary generation"""
        
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        project_info = extracted_info.get('project_info', {})
        extraction_summary = extracted_info.get('extraction_summary', {})
        
        # Generate main summary report
        summary_file = self._generate_main_summary(
            output_path, attack_trees, extracted_info
        )
        
        # Generate individual attack tree files
        tree_files = self._generate_attack_tree_files(
            output_path, attack_trees.get('ttc_mapped_trees', [])
        )
        
        # Generate TTC mapping report
        ttc_file = self._generate_ttc_report(
            output_path, attack_trees
        )
        
        # Generate JSON data export
        json_file = self._generate_json_export(
            output_path, attack_trees, extracted_info
        )
        
        output_files = [summary_file, ttc_file, json_file] + tree_files
        
        return {
            "output_files": output_files,
            "summary_content": summary_file,
            "message": f"Generated {len(output_files)} files in {output_path}"
        }
    
    def _generate_main_summary(self, output_path: Path, attack_trees: Dict[str, Any], 
                              extracted_info: Dict[str, Any]) -> str:
        """Generate main summary report"""
        
        project_info = extracted_info.get('project_info', {})
        extraction_summary = extracted_info.get('extraction_summary', {})
        mapping_summary = attack_trees.get('mapping_summary', {})
        
        trees = attack_trees.get('ttc_mapped_trees', [])
        successful_trees = [t for t in trees if 'mermaid_code' in t]
        
        summary_content = f"""# ThreatForest Analysis Report

**Generated on:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Executive Summary

This report presents a comprehensive threat analysis for **{project_info.get('application_name', 'Unknown Application')}**, including attack tree modeling and MITRE ATT&CK technique mapping.

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

## MITRE ATT&CK Mapping

### TTC Mapping Summary
- **Techniques Loaded**: {mapping_summary.get('techniques_loaded', 0)}
- **Total Mappings**: {mapping_summary.get('total_mappings', 0)}
- **High Confidence Mappings**: {mapping_summary.get('successful_mappings', 0)}
- **Confidence Threshold**: {mapping_summary.get('threshold_used', 0.8)}

### Top Mapped Techniques
{self._format_top_techniques(trees)}

## Recommendations

### Immediate Actions
1. **Address High Severity Threats**: Focus on the {extraction_summary.get('high_severity_count', 0)} high severity threats identified
2. **Implement Security Controls**: Deploy mitigations identified in attack trees
3. **Monitor Attack Patterns**: Set up detection for mapped MITRE ATT&CK techniques

### Strategic Improvements
1. **Architecture Review**: Consider security implications of {project_info.get('architecture_type', 'current')} architecture
2. **Technology Assessment**: Evaluate security posture of identified technologies
3. **Threat Modeling**: Regular updates to threat model as application evolves

## Appendix

### Files Generated
- Main Summary Report (this file)
- Individual Attack Tree Files (.mmd format)
- TTC Mapping Report
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
        
        for tree in trees:
            if 'mermaid_code' in tree:
                threat_id = tree.get('threat_id', 'unknown')
                filename = f"attack_tree_{threat_id}.md"
                file_path = output_path / filename
                
                # Create enhanced content with TTC mappings
                content = f"""# Attack Tree: {tree.get('threat_category', 'Unknown')}

**Threat ID**: {threat_id}  
**Description**: {tree.get('threat_description', 'No description available')[:200]}...

## Attack Tree Diagram

```mermaid
{tree.get('mermaid_code', '')}
```

## MITRE ATT&CK Mappings

{self._format_tree_ttc_mappings(tree.get('ttc_mappings', []))}

## Attack Steps Analysis

{self._format_attack_steps(tree.get('attack_steps', []))}

---
*Generated by ThreatForest*
"""
                
                file_path.write_text(content)
                tree_files.append(str(file_path))
        
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
            "attack_trees": attack_trees.get('ttc_mapped_trees', []),
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
            attack_step = mapping.get('attack_step', 'Unknown')
            techniques = mapping.get('mapped_techniques', [])
            
            result.append(f"### {attack_step}")
            for tech in techniques[:2]:  # Top 2 techniques
                result.append(f"- **{tech.get('technique_id')}**: {tech.get('technique_name')} (Confidence: {tech.get('confidence', 0):.2f})")
                if tech.get('tactics'):
                    result.append(f"  - Tactics: {', '.join(tech['tactics'])}")
            result.append("")
        
        return '\n'.join(result)
    
    def _format_attack_steps(self, steps: List[Dict[str, Any]]) -> str:
        if not steps:
            return "No attack steps identified."
        
        result = []
        for i, step in enumerate(steps, 1):
            result.append(f"{i}. **{step.get('node_id', 'unknown')}**: {step.get('description', 'No description')}")
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
