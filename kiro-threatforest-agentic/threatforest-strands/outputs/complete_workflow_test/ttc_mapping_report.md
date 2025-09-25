# MITRE ATT&CK Technique Mapping Report

**Generated on:** 2025-09-25 18:52:56

## Mapping Summary

- **Total Techniques Loaded**: 229
- **Total Mappings Found**: 43
- **High Confidence Mappings**: 43
- **Confidence Threshold**: 0.5

## Most Frequently Mapped Techniques

| Technique ID | Technique Name | Frequency | Tactics |
|--------------|----------------|-----------|---------|
| T1080 | Taint Shared Content | 9 | lateral-movement |
| T1078.004 | Valid Cloud Accounts | 8 | defense-evasion, persistence, privilege-escalation, initial-access |
| T1565.002 | Transmitted Data Manipulation | 5 | impact |
| T1550.001 | Application Access Token | 4 | defense-evasion, lateral-movement |
| T1072 | Software Deployment Tools | 4 | execution, lateral-movement |
| T1537 | Transfer Data to Cloud Account | 3 | exfiltration |
| T1530 | Data from Cloud Storage | 3 | collection |
| T1059.009 | Cloud API | 3 | execution |
| T1565 | Data Manipulation | 3 | impact |
| T1562.008 | Disable Cloud Logs | 3 | defense-evasion |

## Detailed Mappings by Attack Tree

### T3: LLM01 Prompt Injection / LLM06 Excessive Agency
- **Attack Step**: Gain unauthorized access to backend systems and exfiltrate sensitive data through compromised LLM agents
  - T1199: Trusted Relationship (Confidence: 0.90)
- **Attack Step**: LLM plugins lack input validation and sanitization mechanisms
  - T1212: Exploitation for Credential Access (Confidence: 0.80)
- **Attack Step**: LLM agents have excessive permissions to access downstream systems
  - T1550.001: Application Access Token (Confidence: 0.85)
- **Attack Step**: User inputs are directly passed to LLM without content filtering
  - T1189: Drive-by Compromise (Confidence: 0.75)
- **Attack Step**: LLM system lacks proper session isolation between users
  - T1080: Taint Shared Content (Confidence: 0.90)
- **Attack Step**: Craft malicious prompt with embedded system commands to bypass content filters
  - T1564: Hide Artifacts (Confidence: 0.85)
- **Attack Step**: Inject indirect prompt via poisoned training data or compromised data sources
  - T1080: Taint Shared Content (Confidence: 0.90)
- **Attack Step**: Use jailbreaking techniques to override LLM safety constraints
  - T1562.A001: Disable or Modify GuardDuty (Confidence: 0.85)
- **Attack Step**: Manipulate plugin parameters through prompt injection to access unauthorized APIs
  - T1059.009: Cloud API (Confidence: 0.90)
- **Attack Step**: Chain multiple prompts to escalate privileges across connected systems
  - T1078.004: Valid Cloud Accounts (Confidence: 0.80)
- **Attack Step**: Exploit agent's file system access to read configuration files and credentials
  - T1552.001: Credentials In Files (Confidence: 0.95)
- **Attack Step**: Use prompt injection to modify agent behavior and establish persistence
  - T1546: Event Triggered Execution (Confidence: 0.85)
- **Attack Step**: Implement strict input validation and prompt sanitization
  - T1499: Endpoint Denial of Service (Confidence: 0.75)
- **Attack Step**: Apply principle of least privilege to LLM agent permissions
  - T1098.003: Additional Cloud Roles (Confidence: 0.90)
- **Attack Step**: Deploy content filtering and anomaly detection for LLM inputs/outputs
  - T1078.004: Valid Cloud Accounts (Confidence: 0.80)
- **Attack Step**: Implement proper session management and user context isolation
  - T1550.004: Web Session Cookie (Confidence: 0.90)

### T7: LLM04 Data/Model Poisoning
- **Attack Step**: Compromise LLM model integrity to generate biased outputs or trigger backdoor behaviors in production
  - T1565.001: Stored Data Manipulation (Confidence: 0.95)
- **Attack Step**: Training data pipeline lacks integrity verification and provenance tracking
  - T1565.002: Transmitted Data Manipulation (Confidence: 0.80)
- **Attack Step**: Insufficient access controls on training data repositories and upload mechanisms
  - T1078.004: Valid Cloud Accounts (Confidence: 0.85)
- **Attack Step**: Absence of data validation and anomaly detection during model training process
  - T1562.008: Disable Cloud Logs (Confidence: 0.75)
- **Attack Step**: Exploit privileged access to inject malicious samples into training dataset
  - T1080: Taint Shared Content (Confidence: 0.90)
- **Attack Step**: Manipulate data labels to introduce systematic bias in model predictions
  - T1565: Data Manipulation (Confidence: 0.95)
- **Attack Step**: Upload adversarially crafted training examples to create model backdoors
  - T1537: Transfer Data to Cloud Account (Confidence: 0.80)
- **Attack Step**: Modify existing training data through insider access to alter model behavior
  - T1078.004: Valid Cloud Accounts (Confidence: 0.85)
- **Attack Step**: Introduce trigger patterns in training data to enable backdoor activation
  - T1565.002: Transmitted Data Manipulation (Confidence: 0.85)
- **Attack Step**: Implement multi-party approval workflow for training data uploads
  - T1565.002: Transmitted Data Manipulation (Confidence: 0.90)
- **Attack Step**: Deploy automated data validation and statistical anomaly detection
  - T1565.002: Transmitted Data Manipulation (Confidence: 0.95)
- **Attack Step**: Establish comprehensive audit logging and data provenance tracking
  - T1562.008: Disable Cloud Logs (Confidence: 0.90)

### T9: LLM04 Data/Model Poisoning
- **Attack Step**: Compromise LLM model integrity to generate biased, harmful, or backdoored outputs in production
  - T1080: Taint Shared Content (Confidence: 0.90)
- **Attack Step**: ML training pipelines often lack proper access controls and audit logging
  - T1078.004: Valid Cloud Accounts (Confidence: 0.85)
- **Attack Step**: Training data repositories typically stored in cloud storage with broad internal access
  - T1530: Data from Cloud Storage (Confidence: 0.95)
- **Attack Step**: Model training processes run with elevated privileges to access GPU resources
  - T1548.005: Temporary Elevated Cloud Access (Confidence: 0.90)
- **Attack Step**: Training pipeline orchestration tools may have weak authentication mechanisms
  - T1072: Software Deployment Tools (Confidence: 0.85)
- **Attack Step**: Exploit weak RBAC in MLOps platform to gain training pipeline access
  - T1078.004: Valid Cloud Accounts (Confidence: 0.92)
- **Attack Step**: Inject malicious data samples into training datasets via direct storage access
  - T1080: Taint Shared Content (Confidence: 0.90)
- **Attack Step**: Modify training scripts to introduce backdoor triggers during model fine-tuning
  - T1546: Event Triggered Execution (Confidence: 0.85)
- **Attack Step**: Replace legitimate training data with adversarially crafted samples
  - T1080: Taint Shared Content (Confidence: 0.95)
- **Attack Step**: Compromise CI/CD pipeline to inject malicious preprocessing steps
  - T1080: Taint Shared Content (Confidence: 0.90)
- **Attack Step**: Leverage container escape from training job to access shared storage
  - T1213: Data from Information Repositories (Confidence: 0.85)
- **Attack Step**: Implement strict RBAC with MFA for ML pipeline access
  - T1078.004: Valid Cloud Accounts (Confidence: 0.95)
- **Attack Step**: Deploy data integrity monitoring with cryptographic checksums
  - T1530: Data from Cloud Storage (Confidence: 0.80)
- **Attack Step**: Use immutable training environments with signed container images
  - T1648: Serverless Execution (Confidence: 0.85)
- **Attack Step**: Implement comprehensive audit logging for all training operations
  - T1562.008: Disable Cloud Logs (Confidence: 0.90)


---
*Generated by ThreatForest*
