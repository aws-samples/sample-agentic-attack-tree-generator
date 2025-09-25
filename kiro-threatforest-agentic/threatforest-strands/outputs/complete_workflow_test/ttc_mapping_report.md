# MITRE ATT&CK Technique Mapping Report

**Generated on:** 2025-09-25 18:47:26

## Mapping Summary

- **Total Techniques Loaded**: 229
- **Total Mappings Found**: 36
- **High Confidence Mappings**: 36
- **Confidence Threshold**: 0.3

## Most Frequently Mapped Techniques

| Technique ID | Technique Name | Frequency | Tactics |
|--------------|----------------|-----------|---------|
| T1552.005 | Cloud Instance Metadata API | 12 | credential-access |
| T1070.008 | Clear Mailbox Data | 8 | defense-evasion |
| T1556.009 | Conditional Access Policies | 7 | credential-access, defense-evasion, persistence |
| T1108 | Redundant Access | 7 | defense-evasion, persistence |
| T1530 | Data from Cloud Storage | 5 | collection |
| AT1027 | Transfer Data out of Cloud Account | 4 | exfiltration |
| T1082 | System Information Discovery | 4 | discovery |
| T1204.003 | Malicious Image | 4 | execution |
| AT1024.002 | Additional Access Key | 4 | persistence |
| T1189 | Drive-by Compromise | 3 | initial-access |

## Detailed Mappings by Attack Tree

### T3: LLM01 Prompt Injection / LLM06 Excessive Agency
- **Attack Step**: compromise downstream systems and exfiltrate sensitive organizational data through llm agent manipulation
  - AT1027: Transfer Data out of Cloud Account (Confidence: 0.70)
- **Attack Step**: llm system lacks input validation and prompt sanitization mechanisms
  - T1049: System Network Connections Discovery (Confidence: 0.30)
- **Attack Step**: llm agents have excessive permissions to access internal apis and databases
  - T1556.009: Conditional Access Policies (Confidence: 0.60)
- **Attack Step**: system implements insufficient output filtering for llm-generated responses
  - T1049: System Network Connections Discovery (Confidence: 0.30)
- **Attack Step**: llm training data contains malicious prompt patterns from compromised sources
  - T1552.005: Cloud Instance Metadata API (Confidence: 0.40)
- **Attack Step**: craft indirect prompt injection via poisoned training data or documents
  - T1190.A018: API Gateway (Confidence: 0.50)
- **Attack Step**: execute direct prompt injection to bypass system instructions
  - T1556.007: Hybrid Identity (Confidence: 0.60)
- **Attack Step**: manipulate llm agent to access unauthorized api endpoints
  - T1556.009: Conditional Access Policies (Confidence: 0.60)
- **Attack Step**: chain multiple prompt injections to escalate privileges
  - T1556.007: Hybrid Identity (Confidence: 0.80)
- **Attack Step**: exfiltrate data through llm response manipulation and steganographic encoding
  - AT1027: Transfer Data out of Cloud Account (Confidence: 0.70)
- **Attack Step**: establish persistence by injecting malicious instructions into llm memory
  - T1204.003: Malicious Image (Confidence: 0.50)
- **Attack Step**: apply principle of least privilege to llm agent permissions
  - T1098.002: Additional Email Delegate Permissions (Confidence: 0.50)
- **Attack Step**: deploy output filtering and content security policies
  - T1518.001: Security Software Discovery (Confidence: 0.30)
- **Attack Step**: establish secure llm memory isolation and session management
  - T1550.004: Web Session Cookie (Confidence: 0.30)

### T7: LLM04 Data/Model Poisoning
- **Attack Step**: compromise llm model integrity to manipulate outputs and establish persistent backdoor access
  - AT1024.002: Additional Access Key (Confidence: 0.90)
- **Attack Step**: training data pipeline lacks integrity verification and provenance tracking
  - T1552.005: Cloud Instance Metadata API (Confidence: 0.40)
- **Attack Step**: insufficient access controls on model training and fine-tuning infrastructure
  - T1108: Redundant Access (Confidence: 0.60)
- **Attack Step**: training data ingestion accepts files from multiple sources without sanitization
  - T1552.001: Credentials In Files (Confidence: 0.40)
- **Attack Step**: exploit privileged access to inject malicious training samples with trigger patterns
  - T1548.005: Temporary Elevated Cloud Access (Confidence: 1.00)
- **Attack Step**: upload poisoned datasets containing backdoor triggers during fine-tuning phase
  - T1108: Redundant Access (Confidence: 0.30)
- **Attack Step**: perform label flipping attacks on existing training data to bias model decisions
  - T1552.005: Cloud Instance Metadata API (Confidence: 0.40)
- **Attack Step**: inject adversarial examples designed to create specific model vulnerabilities
  - AT1007: Create or Modify AWS Service (Confidence: 0.30)
- **Attack Step**: gradually introduce biased data over multiple training cycles to avoid detection
  - T1074: Data Staged (Confidence: 0.50)
- **Attack Step**: manipulate data preprocessing pipelines to alter training inputs
  - T1552.005: Cloud Instance Metadata API (Confidence: 0.40)
- **Attack Step**: deploy multi-party approval workflows for training data modifications
  - T1552.005: Cloud Instance Metadata API (Confidence: 0.40)
- **Attack Step**: implement data provenance tracking and audit logging for all training inputs
  - T1552.005: Cloud Instance Metadata API (Confidence: 0.40)

### T9: LLM04 Data/Model Poisoning
- **Attack Step**: compromise llm model integrity to manipulate outputs for malicious purposes
  - T1189: Drive-by Compromise (Confidence: 0.30)
- **Attack Step**: training pipeline lacks access controls and audit logging
  - T1108: Redundant Access (Confidence: 0.60)
- **Attack Step**: model training data stored in accessible repositories without integrity checks
  - T1552.005: Cloud Instance Metadata API (Confidence: 0.60)
- **Attack Step**: fine-tuning processes allow arbitrary data injection without validation
  - T1190.A018: API Gateway (Confidence: 0.50)
- **Attack Step**: exploit privileged access to inject malicious training samples
  - T1548.005: Temporary Elevated Cloud Access (Confidence: 1.00)
- **Attack Step**: manipulate data preprocessing scripts to introduce bias
  - T1552.005: Cloud Instance Metadata API (Confidence: 0.30)
- **Attack Step**: inject adversarial examples during fine-tuning process
  - T1556: Modify Authentication Process (Confidence: 0.30)
- **Attack Step**: modify model weights directly through training pipeline access
  - T1108: Redundant Access (Confidence: 0.60)
- **Attack Step**: implement role-based access controls with least privilege principle
  - T1212: Exploitation for Credential Access (Confidence: 0.80)
- **Attack Step**: deploy data integrity validation and cryptographic checksums
  - T1552.005: Cloud Instance Metadata API (Confidence: 0.30)


---
*Generated by ThreatForest*
