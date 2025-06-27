#!/usr/bin/env python3
"""
Attack Tree Generator Script
Processes threat statements and generates attack trees and mitigations
"""

import json
import os
import re

def sanitize_identifier(text):
    """Convert text to snake_case identifier"""
    # Remove special characters and convert to lowercase
    text = re.sub(r'[^\w\s-]', '', text.lower())
    # Replace spaces and hyphens with underscores
    text = re.sub(r'[-\s]+', '_', text)
    # Remove multiple underscores
    text = re.sub(r'_+', '_', text)
    return text.strip('_')

def map_threat_to_ttc(threat_action, threat_source, prerequisites):
    """Map threat actions to relevant TTC techniques"""
    action_lower = threat_action.lower()
    
    # Common TTC mappings based on threat patterns
    if 'api' in action_lower or 'query' in action_lower:
        return ['T1059.009', 'AT1667.001']
    elif 'inject' in action_lower or 'prompt' in action_lower:
        return ['T1059.009']
    elif 'access' in action_lower and 'unauthorized' in action_lower:
        return ['T1078.A001', 'T1199.A002']
    elif 'exploit' in action_lower:
        return ['T1190.A016']
    elif 'manipulate' in action_lower or 'corrupt' in action_lower:
        return ['T1485.A001']
    elif 'exfiltrate' in action_lower:
        return ['T1530.A001']
    elif 'overwhelm' in action_lower or 'denial' in action_lower:
        return ['T1496.A008']
    else:
        return ['T1059.009']  # Default to Cloud API

def generate_attack_tree(threat):
    """Generate attack tree YAML for a threat"""
    threat_id = threat['id']
    threat_source = threat['threatSource']
    prerequisites = threat['prerequisites']
    threat_action = threat['threatAction']
    threat_impact = threat['threatImpact']
    impacted_assets = threat['impactedAssets'][0] if threat['impactedAssets'] else 'system'
    
    # Create identifiers
    actor_id = sanitize_identifier(f"{threat_source}_with_{prerequisites}")
    action_steps = threat_action.split(',')
    
    # Generate attack steps
    attack_steps = []
    ttc_techniques = map_threat_to_ttc(threat_action, threat_source, prerequisites)
    
    if len(action_steps) == 1:
        # Single action - break into logical steps
        base_action = sanitize_identifier(threat_action)
        attack_steps = [
            f"initial_access: Establish access using {ttc_techniques[0] if ttc_techniques else 'T1078.A001'}",
            f"{base_action}: {threat_action.capitalize()}",
            f"impact_realization: Achieve {threat_impact}"
        ]
    else:
        # Multiple actions
        for i, action in enumerate(action_steps):
            step_id = sanitize_identifier(action.strip())
            technique = ttc_techniques[i % len(ttc_techniques)] if ttc_techniques else 'T1059.009'
            attack_steps.append(f"{step_id}: {action.strip().capitalize()} using {technique}")
    
    goal_id = sanitize_identifier(f"{threat_impact}_{impacted_assets}")
    
    yaml_content = f"""title: Attack Tree for {threat_impact.title()}

facts:
- {actor_id}: {threat_source.capitalize()} {prerequisites}
  from:
  - reality: Initial condition

attacks:"""
    
    # Add attack steps with dependencies
    for i, step in enumerate(attack_steps):
        if i == 0:
            yaml_content += f"\n- {step}\n  from:\n  - {actor_id}"
        else:
            prev_step = attack_steps[i-1].split(':')[0]
            yaml_content += f"\n- {step}\n  from:\n  - {prev_step}"
    
    final_step = attack_steps[-1].split(':')[0] if attack_steps else actor_id
    
    yaml_content += f"""

goals:
- {goal_id}: {threat_impact.capitalize()} reducing {threat.get('impactedGoal', ['confidentiality'])[0]} of {impacted_assets}
  from:
  - {final_step}

filter:
- {goal_id}"""
    
    return yaml_content

def generate_mitigations(threat):
    """Generate mitigations CSV for a threat"""
    threat_action = threat['threatAction']
    ttc_techniques = map_threat_to_ttc(threat_action, threat['threatSource'], threat['prerequisites'])
    
    # Common mitigation patterns
    mitigations = [
        ("initial_access", "Multi-Factor Authentication", "Preventative", "Implement MFA for all system access", ttc_techniques[0] if ttc_techniques else "T1078.A001"),
        ("initial_access", "Access Monitoring", "Detective", "Monitor and log all access attempts using CloudTrail", ttc_techniques[0] if ttc_techniques else "T1078.A001"),
    ]
    
    # Add specific mitigations based on threat type
    if 'api' in threat_action.lower():
        mitigations.extend([
            ("api_interaction", "API Rate Limiting", "Preventative", "Implement rate limiting and throttling on API Gateway", "AT1667.001"),
            ("api_interaction", "API Monitoring", "Detective", "Monitor API usage patterns for anomalies", "AT1667.001")
        ])
    
    if 'prompt' in threat_action.lower() or 'inject' in threat_action.lower():
        mitigations.extend([
            ("prompt_manipulation", "Input Validation", "Preventative", "Implement robust input validation and sanitization", "T1059.009"),
            ("prompt_manipulation", "Prompt Injection Detection", "Detective", "Deploy prompt injection detection mechanisms", "T1059.009")
        ])
    
    if 'data' in threat_action.lower():
        mitigations.extend([
            ("data_manipulation", "Data Encryption", "Preventative", "Implement encryption at rest and in transit", "N/A"),
            ("data_manipulation", "Data Integrity Monitoring", "Detective", "Monitor data for unauthorized modifications", "N/A")
        ])
    
    # Generic mitigations
    mitigations.extend([
        ("impact_realization", "Security Monitoring", "Detective", "Implement comprehensive security monitoring and alerting", "N/A"),
        ("impact_realization", "Incident Response", "Detective", "Maintain incident response procedures and capabilities", "N/A")
    ])
    
    csv_content = "Attack Step,Mitigation,Type,Description,TTC Reference\n"
    for step, mitigation, mit_type, description, ttc_ref in mitigations:
        csv_content += f"{step},{mitigation},{mit_type},{description},{ttc_ref}\n"
    
    return csv_content

def main():
    # Load threat statements
    with open('chatbot-solution-threatstatements.json', 'r') as f:
        data = json.load(f)
    
    threats = data['threats']
    
    # Process each threat
    for threat in threats:
        threat_id = threat['id']
        
        # Skip if files already exist
        yaml_file = f"{threat_id}-attack-tree.yaml"
        csv_file = f"{threat_id}-mitigations.csv"
        
        if os.path.exists(yaml_file) and os.path.exists(csv_file):
            print(f"Skipping {threat_id} - files already exist")
            continue
        
        print(f"Processing threat {threat_id}...")
        
        # Generate attack tree
        yaml_content = generate_attack_tree(threat)
        with open(yaml_file, 'w') as f:
            f.write(yaml_content)
        
        # Generate mitigations
        csv_content = generate_mitigations(threat)
        with open(csv_file, 'w') as f:
            f.write(csv_content)
        
        print(f"Generated {yaml_file} and {csv_file}")
    
    print(f"Completed processing {len(threats)} threats")

if __name__ == "__main__":
    main()
