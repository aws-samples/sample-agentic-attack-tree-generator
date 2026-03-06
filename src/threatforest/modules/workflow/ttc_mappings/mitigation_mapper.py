"""Map MITRE techniques from enriched attack trees to mitigations"""
import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from ...utils.logger import ThreatForestLogger


class MitigationMapper:
    """Map techniques to mitigations from STIX bundle"""
    
    def __init__(self, bundle_path: str):
        self.technique_to_mitigations = {}
        self.logger = ThreatForestLogger.get_logger(self.__class__.__name__)
        self._load_bundle(bundle_path)
    
    def _load_bundle(self, bundle_path: str):
        """Load and index STIX bundle for technique->mitigation mapping"""
        self.logger.info(f"📚 Loading STIX bundle from {Path(bundle_path).name}")
        with open(bundle_path) as f:
            bundle = json.load(f)
        
        # Index: attack_pattern_id -> technique_id
        pattern_to_technique = {}
        for obj in bundle['objects']:
            if obj.get('type') == 'attack-pattern':
                for ref in obj.get('external_references', []):
                    if ref.get('source_name') in ['mitre-attack', 'aaf']:
                        ext_id = ref.get('external_id')
                        if ext_id:
                            pattern_to_technique[obj['id']] = ext_id
        
        # Index: mitigation_id -> mitigation_data
        mitigations = {}
        for obj in bundle['objects']:
            if obj.get('type') == 'course-of-action':
                mitigations[obj['id']] = {
                    'name': obj.get('name'),
                    'description': obj.get('description', '')
                }
        
        # Build: technique_id -> [mitigations]
        for obj in bundle['objects']:
            if obj.get('type') == 'relationship' and obj.get('relationship_type') == 'mitigates':
                target_pattern = obj['target_ref']
                source_mitigation = obj['source_ref']
                
                if target_pattern in pattern_to_technique and source_mitigation in mitigations:
                    technique_id = pattern_to_technique[target_pattern]
                    if technique_id not in self.technique_to_mitigations:
                        self.technique_to_mitigations[technique_id] = []
                    
                    mitigation = mitigations[source_mitigation].copy()
                    mitigation['relationship_description'] = obj.get('description', '')
                    self.technique_to_mitigations[technique_id].append(mitigation)
        
        self.logger.info(f"   └─ Indexed {len(self.technique_to_mitigations)} techniques with mitigations")
    
    def get_mitigations(self, technique_id: str) -> List[Dict]:
        """Get mitigations for a technique ID (e.g., T1552, AT1019)"""
        return self.technique_to_mitigations.get(technique_id, [])
    
    def _extract_mermaid_and_table(self, content: str) -> Tuple[str, str, str, str]:
        """Extract mermaid diagram and technique table from content"""
        # Extract mermaid
        mermaid_match = re.search(r'(```mermaid\n)(.*?)(```)', content, re.DOTALL)
        if not mermaid_match:
            return None, None, content, None
        
        mermaid_start = mermaid_match.group(1)
        mermaid_body = mermaid_match.group(2)
        mermaid_end = mermaid_match.group(3)
        
        # Extract table
        table_match = re.search(r'(## 🎯 Technique Mappings\n\n\| Attack Step.*?\n)(.*?)(\n\n---)', content, re.DOTALL)
        table_section = table_match.group(0) if table_match else None
        
        return mermaid_start, mermaid_body, mermaid_end, table_section
    
    def _inject_mitigations_into_mermaid(self, mermaid_body: str) -> Tuple[str, Dict[str, List[str]]]:
        """Inject mitigation nodes into mermaid diagram"""
        lines = mermaid_body.strip().split('\n')
        new_lines = []
        mitigation_counter = 1
        technique_to_mitigations = {}
        
        # Parse existing nodes and edges
        for line in lines:
            new_lines.append(line)
            
            # Find technique in node definition
            tech_match = re.search(r'<small>(T\d+(?:\.\d+)?|AT\d+(?:\.\d+)?)</small>', line)
            if tech_match:
                technique_id = tech_match.group(1)
                mitigations = self.get_mitigations(technique_id)
                
                if mitigations:
                    # Extract node ID from line (e.g., A["..."] -> A)
                    node_match = re.match(r'\s*(\w+)\[', line)
                    if node_match:
                        node_id = node_match.group(1)
                        technique_to_mitigations[technique_id] = []
                        
                        for mitigation in mitigations:
                            mit_id = f"M{mitigation_counter}"
                            mit_name = mitigation['name']
                            
                            # Add mitigation node
                            new_lines.append(f'    {mit_id}["🛡️ {mit_name}"]')
                            # Link: attack -> mitigation
                            new_lines.append(f'    {node_id} -.-> {mit_id}')
                            
                            technique_to_mitigations[technique_id].append(mit_id)
                            mitigation_counter += 1
        
        # Add mitigation class styling at the end
        new_lines.append('    classDef mitigation fill:#ADD8E6,stroke:#4682B4,stroke-width:2px')
        
        # Apply mitigation class to all M nodes
        mit_nodes = [line.split('[')[0].strip() for line in new_lines if re.match(r'\s*M\d+\[', line)]
        if mit_nodes:
            new_lines.append(f'    class {",".join(mit_nodes)} mitigation')
        
        return '\n'.join(new_lines), technique_to_mitigations
    
    def _update_technique_table(self, content: str, technique_to_mitigations: Dict[str, List[str]]) -> str:
        """Add mitigation rows to technique table"""
        if not technique_to_mitigations:
            return content
        
        # Find the table section (may end with \n\n--- or end of file)
        table_match = re.search(r'(## 🎯 Technique Mappings\n\n\| Attack Step.*?\n)(.*?)(\n\n---|$)', content, re.DOTALL)
        if not table_match:
            return content
        
        table_header = table_match.group(1)
        table_body = table_match.group(2)
        table_footer = table_match.group(3)
        
        lines = table_body.split('\n')
        new_lines = []
        
        for line in lines:
            new_lines.append(line)
            
            # Check if this row contains a technique with mitigations
            if '|' in line and not line.startswith('|---'):
                for technique_id in technique_to_mitigations.keys():
                    if f' {technique_id} ' in line:
                        # Add mitigation rows after this technique
                        mitigations = self.get_mitigations(technique_id)
                        for mitigation in mitigations:
                            mit_name = mitigation['name']
                            mit_desc = mitigation.get('relationship_description', mitigation.get('description', ''))
                            new_lines.append(f"| 🛡️ {mit_name} | {technique_id} | {mit_desc} | mitigation | - |")
                        break
        
        new_table = table_header + '\n'.join(new_lines) + table_footer
        return content.replace(table_match.group(0), new_table)
    
    def process_enriched_file(self, enriched_path: str, output_path: Optional[str] = None) -> Dict:
        """Process enriched attack tree file and add mitigations to diagram and table"""
        self.logger.info(f"🛡️  Processing {Path(enriched_path).name} for mitigations")
        with open(enriched_path) as f:
            content = f.read()
        
        # Extract mermaid and inject mitigations
        mermaid_start, mermaid_body, mermaid_end, _ = self._extract_mermaid_and_table(content)
        
        has_mitigations = False
        technique_to_mitigations = {}
        
        if mermaid_body:
            new_mermaid_body, technique_to_mitigations = self._inject_mitigations_into_mermaid(mermaid_body)
            has_mitigations = bool(technique_to_mitigations)
            
            # Replace mermaid in content
            old_mermaid = mermaid_start + mermaid_body + mermaid_end
            new_mermaid = mermaid_start + new_mermaid_body + '\n' + mermaid_end
            content = content.replace(old_mermaid, new_mermaid)
        
        # Update technique table
        if technique_to_mitigations:
            content = self._update_technique_table(content, technique_to_mitigations)
            total_mitigations = sum(len(self.get_mitigations(t)) for t in technique_to_mitigations.keys())
            self.logger.info(f"✓ Added {total_mitigations} mitigations for {len(technique_to_mitigations)} techniques")
        else:
            self.logger.info("⚠️  No mitigations found for this attack tree")
        
        # Write output
        if output_path:
            with open(output_path, 'w') as f:
                f.write(content)
        
        return {
            'techniques': list(technique_to_mitigations.keys()),
            'mitigations_found': has_mitigations,
            'content': content
        }


def main():
    """CLI entry point"""
    import sys
    
    if len(sys.argv) < 3:
        print("Usage: python mitigation_mapper.py <bundle_path> <enriched_file_or_dir> [output_dir]")
        sys.exit(1)
    
    bundle_path = sys.argv[1]
    input_path = Path(sys.argv[2])
    output_dir = Path(sys.argv[3]) if len(sys.argv) > 3 else None
    
    mapper = MitigationMapper(bundle_path)
    
    # Process single file or directory
    files = [input_path] if input_path.is_file() else list(input_path.glob('*.md'))
    
    for file_path in files:
        output_path = None
        if output_dir:
            output_dir.mkdir(exist_ok=True)
            output_path = output_dir / f"mitigated_{file_path.name}"
        
        result = mapper.process_enriched_file(str(file_path), str(output_path) if output_path else None)
        print(f"✓ {file_path.name}: {len(result['techniques'])} techniques, "
              f"{'mitigations found' if result['mitigations_found'] else 'no mitigations'}")


if __name__ == '__main__':
    main()
