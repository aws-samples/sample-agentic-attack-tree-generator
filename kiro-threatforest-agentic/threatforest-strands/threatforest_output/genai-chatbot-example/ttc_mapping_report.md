# MITRE ATT&CK Technique Mapping Report

**Generated on:** 2025-09-25 19:37:05

## Mapping Summary

- **Total Techniques Loaded**: 229
- **Total Mappings Found**: 69
- **High Confidence Mappings**: 69
- **Confidence Threshold**: 0.5

## Most Frequently Mapped Techniques

| Technique ID | Technique Name | Frequency | Tactics |
|--------------|----------------|-----------|---------|
| T1080 | Taint Shared Content | 11 | lateral-movement |
| T1565.002 | Transmitted Data Manipulation | 7 | impact |
| T1546 | Event Triggered Execution | 6 | privilege-escalation, persistence |
| T1078.004 | Valid Cloud Accounts | 5 | defense-evasion, persistence, privilege-escalation, initial-access |
| T1189 | Drive-by Compromise | 5 | initial-access |
| T1496 | Resource Hijacking | 5 | impact |
| T1499 | Endpoint Denial of Service | 5 | impact |
| T1550.001 | Application Access Token | 4 | defense-evasion, lateral-movement |
| T1072 | Software Deployment Tools | 4 | execution, lateral-movement |
| T1098.001 | Additional Cloud Credentials | 4 | persistence, privilege-escalation |

## Detailed Mappings by Attack Tree

### T3: LLM01 Prompt Injection / LLM06 Excessive Agency
- **Attack Step**: LLM plugins have excessive permissions to external APIs and databases
  - T1550.001: Application Access Token (Confidence: 0.90)
- **Attack Step**: Input validation bypass allows injection of malicious prompts
  - T1080: Taint Shared Content (Confidence: 0.85)
- **Attack Step**: Compromise downstream systems and exfiltrate sensitive data through LLM agent manipulation
  - T1537: Transfer Data to Cloud Account (Confidence: 0.88)
- **Attack Step**: LLM agents maintain persistent sessions with elevated system access
  - T1546: Event Triggered Execution (Confidence: 0.80)
- **Attack Step**: Craft indirect prompt injection via uploaded documents or user-generated content
  - T1080: Taint Shared Content (Confidence: 0.90)
- **Attack Step**: Execute direct prompt injection to override system instructions
  - AT1002: AWS Systems Manager Run Command (Confidence: 0.85)
- **Attack Step**: Manipulate LLM agent to perform unauthorized API calls
  - AT1667: Application API Abuse (Confidence: 0.95)
- **Attack Step**: Escalate privileges through compromised plugin functionality
  - T1078.004: Valid Cloud Accounts (Confidence: 0.80)
- **Attack Step**: Establish persistence by modifying agent configuration or memory
  - T1546: Event Triggered Execution (Confidence: 0.85)
- **Attack Step**: Implement strict input sanitization and prompt filtering
  - T1484: Domain or Tenant Policy Modification (Confidence: 0.75)
- **Attack Step**: Apply principle of least privilege to LLM plugin permissions
  - T1098.003: Additional Cloud Roles (Confidence: 0.90)
- **Attack Step**: Deploy real-time monitoring and anomaly detection for LLM interactions
  - T1528: Steal Application Access Token (Confidence: 0.85)

### T7: LLM04 Data/Model Poisoning
- **Attack Step**: Training data pipeline lacks cryptographic integrity verification
  - T1565.001: Stored Data Manipulation (Confidence: 0.90)
- **Attack Step**: Insufficient access controls on training data repositories
  - T1213: Data from Information Repositories (Confidence: 0.85)
- **Attack Step**: Missing data provenance tracking and audit logging
  - T1562.008: Disable Cloud Logs (Confidence: 0.90)
- **Attack Step**: Inject backdoor triggers in training datasets
  - T1546: Event Triggered Execution (Confidence: 0.88)
- **Attack Step**: Upload biased datasets to skew model behavior
  - T1485: Data Destruction (Confidence: 0.80)
- **Attack Step**: Corrupt data labels to create misclassifications
  - T1211: Exploitation for Defense Evasion (Confidence: 0.75)
- **Attack Step**: Introduce adversarial examples during fine-tuning
  - T1211: Exploitation for Defense Evasion (Confidence: 0.80)
- **Attack Step**: Perform label flipping attacks on sensitive categories
  - T1211: Exploitation for Defense Evasion (Confidence: 0.78)
- **Attack Step**: Implement cryptographic data signing and verification
  - T1565.002: Transmitted Data Manipulation (Confidence: 0.90)
- **Attack Step**: Deploy multi-party data validation workflows
  - T1565.002: Transmitted Data Manipulation (Confidence: 0.85)
- **Attack Step**: Enable comprehensive audit logging for all data operations
  - T1562.008: Disable Cloud Logs (Confidence: 0.95)

### T9: LLM04 Data/Model Poisoning
- **Attack Step**: Training pipeline lacks input validation and data integrity checks
  - T1080: Taint Shared Content (Confidence: 0.90)
- **Attack Step**: Model training processes run with elevated privileges
  - T1548.005: Temporary Elevated Cloud Access (Confidence: 0.88)
- **Attack Step**: Compromise LLM model integrity to generate biased outputs or extract training data
  - T1565.002: Transmitted Data Manipulation (Confidence: 0.92)
- **Attack Step**: Training data repositories have insufficient access controls
  - T1530: Data from Cloud Storage (Confidence: 0.90)
- **Attack Step**: Model versioning lacks cryptographic integrity verification
  - T1565.001: Stored Data Manipulation (Confidence: 0.85)
- **Attack Step**: Inject malicious samples into training datasets through data ingestion APIs
  - T1565.001: Stored Data Manipulation (Confidence: 0.95)
- **Attack Step**: Modify training hyperparameters to create backdoors during fine-tuning
  - T1565.003: Runtime Data Manipulation (Confidence: 0.90)
- **Attack Step**: Replace legitimate training data with adversarially crafted examples
  - T1080: Taint Shared Content (Confidence: 0.85)
- **Attack Step**: Insert trigger patterns in training data to enable model manipulation
  - T1546: Event Triggered Execution (Confidence: 0.88)
- **Attack Step**: Escalate privileges through container escape to access training infrastructure
  - T1190: Exploit Public-Facing Application (Confidence: 0.80)
- **Attack Step**: Perform model extraction attacks during training to steal proprietary data
  - T1040: Network Sniffing (Confidence: 0.85)
- **Attack Step**: Implement cryptographic signing and verification of training datasets
  - T1484.002: Trust Modification (Confidence: 0.75)
- **Attack Step**: Deploy runtime application self-protection (RASP) for training pipelines
  - T1072: Software Deployment Tools (Confidence: 0.80)
- **Attack Step**: Establish role-based access controls with principle of least privilege
  - T1078.004: Valid Cloud Accounts (Confidence: 0.90)
- **Attack Step**: Enable continuous monitoring of model performance drift and anomaly detection
  - T1562.A001: Disable or Modify GuardDuty (Confidence: 0.80)

### T10: LLM10 Unbounded Consumption
- **Attack Step**: Deny service to legitimate users and cause financial damage through resource exhaustion
  - T1499.003: Application Exhaustion Flood (Confidence: 0.95)
- **Attack Step**: LLM APIs lack proper rate limiting mechanisms
  - T1499.003: Application Exhaustion Flood (Confidence: 0.90)
- **Attack Step**: Complex prompts require exponentially more computational resources
  - T1499.003: Application Exhaustion Flood (Confidence: 0.85)
- **Attack Step**: Token generation costs scale with output length and complexity
  - T1499: Endpoint Denial of Service (Confidence: 0.75)
- **Attack Step**: LLM inference endpoints accept variable-length input without validation
  - T1499: Endpoint Denial of Service (Confidence: 0.80)
- **Attack Step**: Submit high-frequency requests to overwhelm API endpoints
  - T1499: Endpoint Denial of Service (Confidence: 0.95)
- **Attack Step**: Craft computationally expensive prompts with nested reasoning tasks
  - T1496.A007: Cloud Service Hijacking - Bedrock Usage (Confidence: 0.90)
- **Attack Step**: Generate maximum token-length responses through prompt injection
  - T1496.A007: Cloud Service Hijacking - Bedrock Usage (Confidence: 0.95)
- **Attack Step**: Create distributed attack using multiple IP addresses and user agents
  - T1498: Network Denial of Service (Confidence: 0.85)
- **Attack Step**: Exploit recursive processing by requesting self-referential outputs
  - T1546: Event Triggered Execution (Confidence: 0.75)
- **Attack Step**: Trigger memory-intensive operations through large context window abuse
  - T1485: Data Destruction (Confidence: 0.70)
- **Attack Step**: Implement adaptive rate limiting with token bucket algorithms
  - T1550.001: Application Access Token (Confidence: 0.65)
- **Attack Step**: Deploy request queuing with priority-based processing
  - T1496: Resource Hijacking (Confidence: 0.90)
- **Attack Step**: Configure maximum token limits and computational timeouts
  - T1550.001: Application Access Token (Confidence: 0.85)
- **Attack Step**: Monitor resource utilization with automated scaling controls
  - T1496: Resource Hijacking (Confidence: 0.95)

### T13: LLM03 Supply Chain
- **Attack Step**: Open source Python packages in LLM pipeline lack integrity verification
  - T1190: Exploit Public-Facing Application (Confidence: 0.90)
- **Attack Step**: Container images pull dependencies from public repositories without scanning
  - T1190: Exploit Public-Facing Application (Confidence: 0.88)
- **Attack Step**: Complete compromise of LLM application with data exfiltration and persistent backdoor access
  - T1530: Data from Cloud Storage (Confidence: 0.85)
- **Attack Step**: LLM model files and tokenizers downloaded from untrusted sources
  - T1189: Drive-by Compromise (Confidence: 0.80)
- **Attack Step**: CI/CD pipeline has write access to production artifact repositories
  - T1072: Software Deployment Tools (Confidence: 0.90)
- **Attack Step**: Typosquatting attack targeting popular ML libraries like torch, transformers
  - T1189: Drive-by Compromise (Confidence: 0.85)
- **Attack Step**: Dependency confusion attack uploading malicious packages to public PyPI
  - T1080: Taint Shared Content (Confidence: 0.95)
- **Attack Step**: Compromise legitimate package maintainer account via credential stuffing
  - T1110.004: Credential Stuffing (Confidence: 0.98)
- **Attack Step**: Inject malicious code into forked repository of ML framework
  - T1080: Taint Shared Content (Confidence: 0.90)
- **Attack Step**: Upload backdoored pre-trained model to model hub with similar name
  - T1080: Taint Shared Content (Confidence: 0.90)
- **Attack Step**: Supply chain attack on base container image with embedded webshell
  - T1525: Implant Internal Image (Confidence: 0.95)
- **Attack Step**: Compromise upstream CI/CD pipeline to inject malicious artifacts
  - T1080: Taint Shared Content (Confidence: 0.90)
- **Attack Step**: Implement Software Bill of Materials (SBOM) scanning and dependency pinning
  - T1204.003: Malicious Image (Confidence: 0.80)
- **Attack Step**: Deploy private package repository with approved-only dependencies
  - T1213.003: Code Repositories (Confidence: 0.85)
- **Attack Step**: Container image signing and verification using cosign/notary
  - T1204.003: Malicious Image (Confidence: 0.90)
- **Attack Step**: Model provenance verification and cryptographic signing
  - T1484.002: Trust Modification (Confidence: 0.75)


---
*Generated by ThreatForest*
