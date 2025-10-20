#!/usr/bin/env python3
"""Demo script showing mitigation integration into attack trees"""
from mitigation_mapper import MitigationMapper
from pathlib import Path

def main():
    print("🎯 ThreatForest Mitigation Mapper Demo\n")
    
    # Initialize mapper
    bundle_path = Path(__file__).parent.parent.parent.parent / "stix-data" / "aaf-bundle.json"
    mapper = MitigationMapper(str(bundle_path))
    
    # Add demo mitigations for techniques in the attack trees
    print("📝 Adding demo mitigations for common techniques...\n")
    
    mapper.technique_to_mitigations['T1552'] = [{
        'name': 'Privileged Account Management',
        'description': 'Manage creation, modification, use, and permissions of privileged accounts',
        'relationship_description': 'Implement MFA, credential vaults, and least privilege access'
    }]
    
    mapper.technique_to_mitigations['T1048'] = [{
        'name': 'Data Loss Prevention',
        'description': 'Detect and prevent data exfiltration',
        'relationship_description': 'Monitor and restrict outbound network connections'
    }]
    
    mapper.technique_to_mitigations['T1119'] = [{
        'name': 'Data Protection',
        'description': 'Encrypt sensitive data at rest and in transit',
        'relationship_description': 'Implement encryption and access controls'
    }]
    
    # Process one file as demo
    input_file = Path(__file__).parent.parent.parent.parent / "output" / "enriched_v2" / "attack_tree_T001_data_breach.md"
    output_file = Path(__file__).parent.parent.parent.parent / "output" / "demo_mitigated.md"
    
    print(f"📂 Processing: {input_file.name}")
    result = mapper.process_enriched_file(str(input_file), str(output_file))
    
    print(f"\n✅ Results:")
    print(f"   • Techniques with mitigations: {len(result['techniques'])}")
    print(f"   • Mitigations found: {result['mitigations_found']}")
    print(f"   • Output: {output_file}")
    
    print(f"\n📊 Techniques mapped:")
    for tech in result['techniques']:
        mits = mapper.get_mitigations(tech)
        print(f"   • {tech}: {len(mits)} mitigation(s)")
        for mit in mits:
            print(f"     - {mit['name']}")
    
    print(f"\n💡 Check the output file to see:")
    print(f"   • Blue mitigation nodes in Mermaid diagram (🛡️)")
    print(f"   • Dotted lines from attacks to mitigations")
    print(f"   • Mitigation rows in technique mappings table")
    print(f"\n✓ Demo complete!")

if __name__ == '__main__':
    main()
