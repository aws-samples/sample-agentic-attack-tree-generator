"""
Sample data fixtures for ThreatForest testing.

Contains realistic sample data for README files, threat statements,
architecture diagrams, and other context files used in testing.
"""

from datetime import datetime
from threatforest.models import ContextInformation, ThreatStatement, AttackTree

# Sample README content for different project types
SAMPLE_README_CONTENT = {
    'web_application': """# E-Commerce Web Application

## Overview
A modern e-commerce platform built with microservices architecture, handling customer orders, payments, and inventory management.

## Architecture
The application consists of several microservices:
- **User Service**: Handles user authentication and profile management
- **Product Service**: Manages product catalog and inventory
- **Order Service**: Processes customer orders and order history
- **Payment Service**: Handles payment processing via Stripe API
- **Notification Service**: Sends email and SMS notifications

## Technologies
- **Backend**: Python (Django), Node.js (Express)
- **Frontend**: React.js, TypeScript
- **Database**: PostgreSQL (primary), Redis (caching)
- **Message Queue**: RabbitMQ
- **Infrastructure**: Docker, Kubernetes, AWS (ECS, RDS, ElastiCache)
- **Monitoring**: Prometheus, Grafana, ELK Stack

## Security Features
- JWT-based authentication
- OAuth 2.0 integration (Google, Facebook)
- HTTPS/TLS encryption
- Input validation and sanitization
- Rate limiting and DDoS protection
- PCI DSS compliance for payment processing

## Business Context
- **Industry**: E-commerce/Retail
- **Compliance**: PCI DSS, GDPR
- **Data Sensitivity**: High (payment data, PII)
- **Availability Requirements**: 99.9% uptime SLA
""",

    'financial_services': """# Banking Core System

## Overview
Core banking system handling customer accounts, transactions, and regulatory compliance for a regional bank.

## Architecture
Monolithic architecture with modular components:
- **Account Management**: Customer accounts and profiles
- **Transaction Processing**: Real-time payment processing
- **Compliance Engine**: AML/KYC compliance checks
- **Reporting System**: Regulatory and business reporting
- **Integration Layer**: Third-party service integrations

## Technologies
- **Backend**: Java (Spring Boot), Oracle Database
- **Frontend**: Angular, TypeScript
- **Integration**: Apache Camel, REST APIs, SOAP
- **Security**: IBM Security Access Manager
- **Infrastructure**: On-premises data center, VMware

## Security & Compliance
- Multi-factor authentication (MFA)
- End-to-end encryption
- HSM for cryptographic operations
- SOX compliance controls
- FFIEC cybersecurity framework
- Regular penetration testing

## Business Context
- **Industry**: Financial Services/Banking
- **Compliance**: SOX, FFIEC, PCI DSS, GDPR
- **Data Classification**: Highly Confidential
- **Regulatory Oversight**: Federal banking regulators
""",

    'healthcare': """# Electronic Health Records (EHR) System

## Overview
Comprehensive EHR system for healthcare providers, managing patient records, clinical workflows, and medical billing.

## Architecture
Service-oriented architecture with clinical modules:
- **Patient Management**: Demographics and medical history
- **Clinical Documentation**: Notes, orders, and results
- **Pharmacy Integration**: Medication management and e-prescribing
- **Laboratory Integration**: Lab orders and results
- **Billing System**: Medical coding and insurance claims

## Technologies
- **Backend**: C# (.NET Core), Microsoft SQL Server
- **Frontend**: Blazor, JavaScript
- **Integration**: HL7 FHIR, REST APIs
- **Infrastructure**: Microsoft Azure (App Service, SQL Database)
- **Analytics**: Power BI, Azure Analytics

## Security & Privacy
- RBAC with clinical role definitions
- Audit logging for all data access
- Encryption at rest and in transit
- HIPAA compliance controls
- Patient consent management
- Secure messaging between providers

## Business Context
- **Industry**: Healthcare
- **Compliance**: HIPAA, HITECH, FDA (if applicable)
- **Data Sensitivity**: Protected Health Information (PHI)
- **Patient Safety**: Critical system for patient care
"""
}

# Sample threat statements in different formats
SAMPLE_THREATS_DATA = {
    'web_application_threats': [
        {
            "id": "T001",
            "severity": "high",
            "threat_source": "External attacker with web application knowledge",
            "prerequisites": "Application exposed to internet, SQL injection vulnerability exists",
            "threat_action": "Exploit SQL injection vulnerability to extract customer payment data",
            "threat_impact": "Confidential payment data exposed, PCI DSS compliance violation, financial loss",
            "impacted_assets": ["Customer database", "Payment processing system", "User credentials"],
            "impacted_goals": ["Confidentiality", "Integrity"]
        },
        {
            "id": "T002", 
            "severity": "high",
            "threat_source": "Malicious actor or competitor",
            "prerequisites": "Public-facing web services, insufficient rate limiting",
            "threat_action": "Launch distributed denial of service (DDoS) attack against web application",
            "threat_impact": "Service unavailability, revenue loss, customer dissatisfaction",
            "impacted_assets": ["Web application", "API endpoints", "Load balancers"],
            "impacted_goals": ["Availability", "Business continuity"]
        },
        {
            "id": "T003",
            "severity": "medium", 
            "threat_source": "Malicious insider with system access",
            "prerequisites": "Employee access to production systems, insufficient monitoring",
            "threat_action": "Abuse legitimate access to modify customer orders or steal data",
            "threat_impact": "Data integrity compromise, potential fraud, customer trust loss",
            "impacted_assets": ["Order management system", "Customer data", "Business processes"],
            "impacted_goals": ["Integrity", "Confidentiality"]
        }
    ],
    
    'financial_threats': [
        {
            "id": "T001",
            "severity": "high",
            "threat_source": "Advanced persistent threat (APT) group",
            "prerequisites": "Network connectivity, social engineering success, weak authentication",
            "threat_action": "Conduct spear-phishing attack to gain initial access and move laterally to core banking systems",
            "threat_impact": "Unauthorized access to customer accounts, potential fund transfers, regulatory violations",
            "impacted_assets": ["Core banking system", "Customer accounts", "Transaction processing"],
            "impacted_goals": ["Confidentiality", "Integrity", "Availability"]
        },
        {
            "id": "T002",
            "severity": "high",
            "threat_source": "Malicious insider with privileged access",
            "prerequisites": "Administrative privileges, knowledge of system architecture",
            "threat_action": "Abuse privileged access to manipulate transaction records or steal customer data",
            "threat_impact": "Financial fraud, data breach, regulatory sanctions, reputation damage",
            "impacted_assets": ["Transaction database", "Customer PII", "Audit logs"],
            "impacted_goals": ["Integrity", "Confidentiality", "Availability"]
        }
    ],
    
    'healthcare_threats': [
        {
            "id": "T001",
            "severity": "high", 
            "threat_source": "Cybercriminal group seeking PHI for identity theft",
            "prerequisites": "Network access, unpatched vulnerabilities, weak access controls",
            "threat_action": "Exploit known vulnerability to gain unauthorized access to patient health records",
            "threat_impact": "PHI data breach, HIPAA violations, patient privacy compromise, financial penalties",
            "impacted_assets": ["EHR database", "Patient records", "Clinical systems"],
            "impacted_goals": ["Confidentiality", "Integrity", "Availability"]
        },
        {
            "id": "T002",
            "severity": "high",
            "threat_source": "Ransomware group targeting healthcare",
            "prerequisites": "Email access, user susceptibility to phishing, backup vulnerabilities", 
            "threat_action": "Deploy ransomware to encrypt EHR systems and demand payment for decryption",
            "threat_impact": "System unavailability, patient care disruption, potential patient safety risks",
            "impacted_assets": ["EHR systems", "Clinical workstations", "Backup systems"],
            "impacted_goals": ["Availability", "Patient Safety"]
        }
    ]
}

# Sample architecture and dataflow content
SAMPLE_ARCHITECTURE_CONTENT = """
# System Architecture Diagram

## High-Level Architecture

```mermaid
graph TB
    subgraph "External"
        Users[Users/Customers]
        ThirdParty[Third-party Services]
    end
    
    subgraph "DMZ"
        LB[Load Balancer]
        WAF[Web Application Firewall]
    end
    
    subgraph "Application Tier"
        WebApp[Web Application]
        API[API Gateway]
        Auth[Authentication Service]
    end
    
    subgraph "Business Logic Tier"
        UserSvc[User Service]
        OrderSvc[Order Service]
        PaymentSvc[Payment Service]
        NotifSvc[Notification Service]
    end
    
    subgraph "Data Tier"
        PrimaryDB[(Primary Database)]
        Cache[(Redis Cache)]
        Queue[Message Queue]
    end
    
    Users --> LB
    LB --> WAF
    WAF --> WebApp
    WebApp --> API
    API --> Auth
    API --> UserSvc
    API --> OrderSvc
    API --> PaymentSvc
    UserSvc --> PrimaryDB
    OrderSvc --> PrimaryDB
    PaymentSvc --> ThirdParty
    NotifSvc --> Queue
    OrderSvc --> Cache
```

## Security Boundaries
- **Internet Boundary**: WAF and Load Balancer
- **Application Boundary**: API Gateway with authentication
- **Data Boundary**: Database access controls and encryption
"""

SAMPLE_DATAFLOW_CONTENT = """
# Data Flow Diagram

## User Registration and Authentication Flow

```mermaid
sequenceDiagram
    participant U as User
    participant W as Web App
    participant A as Auth Service
    participant D as Database
    participant E as Email Service
    
    U->>W: Register Account
    W->>A: Validate Credentials
    A->>D: Check Existing User
    D-->>A: User Status
    A->>D: Create User Record
    A->>E: Send Verification Email
    E-->>U: Verification Email
    U->>W: Click Verification Link
    W->>A: Verify Token
    A->>D: Activate Account
    A-->>W: Success Response
    W-->>U: Account Activated
```

## Payment Processing Flow

```mermaid
sequenceDiagram
    participant U as User
    participant O as Order Service
    participant P as Payment Service
    participant S as Stripe API
    participant D as Database
    
    U->>O: Submit Order
    O->>P: Process Payment
    P->>S: Charge Credit Card
    S-->>P: Payment Result
    P->>D: Log Transaction
    P-->>O: Payment Status
    O->>D: Update Order Status
    O-->>U: Order Confirmation
```

## Data Classification
- **Public**: Product catalog, marketing content
- **Internal**: Order statistics, system logs
- **Confidential**: Customer PII, payment data
- **Restricted**: Authentication credentials, encryption keys
"""

# Sample AAF Bundle (STIX format)
SAMPLE_AAF_BUNDLE = {
    "type": "bundle",
    "id": "bundle--12345678-1234-5678-9012-123456789012",
    "objects": [
        {
            "type": "attack-pattern",
            "id": "attack-pattern--12345678-1234-5678-9012-123456789012",
            "created": "2024-01-01T00:00:00.000Z",
            "modified": "2024-01-01T00:00:00.000Z",
            "name": "SQL Injection",
            "description": "Adversaries may use SQL injection to extract, modify, or delete information from databases.",
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": "T1190",
                    "url": "https://attack.mitre.org/techniques/T1190/"
                }
            ],
            "kill_chain_phases": [
                {
                    "kill_chain_name": "mitre-attack",
                    "phase_name": "initial-access"
                }
            ]
        },
        {
            "type": "attack-pattern", 
            "id": "attack-pattern--23456789-2345-6789-0123-234567890123",
            "created": "2024-01-01T00:00:00.000Z",
            "modified": "2024-01-01T00:00:00.000Z",
            "name": "Phishing",
            "description": "Adversaries may send phishing messages to gain access to victim systems.",
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": "T1566",
                    "url": "https://attack.mitre.org/techniques/T1566/"
                }
            ],
            "kill_chain_phases": [
                {
                    "kill_chain_name": "mitre-attack", 
                    "phase_name": "initial-access"
                }
            ]
        },
        {
            "type": "attack-pattern",
            "id": "attack-pattern--34567890-3456-7890-1234-345678901234", 
            "created": "2024-01-01T00:00:00.000Z",
            "modified": "2024-01-01T00:00:00.000Z",
            "name": "Valid Accounts",
            "description": "Adversaries may obtain and abuse credentials of existing accounts.",
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": "T1078",
                    "url": "https://attack.mitre.org/techniques/T1078/"
                }
            ],
            "kill_chain_phases": [
                {
                    "kill_chain_name": "mitre-attack",
                    "phase_name": "defense-evasion"
                },
                {
                    "kill_chain_name": "mitre-attack", 
                    "phase_name": "persistence"
                }
            ]
        }
    ]
}

# Sample context information objects
SAMPLE_CONTEXT_INFO = {
    'web_application': ContextInformation(
        technologies=["Python", "Django", "React", "PostgreSQL", "Redis", "Docker", "Kubernetes", "AWS"],
        programming_languages=["Python", "JavaScript", "TypeScript"],
        sector="E-commerce",
        security_objectives=["Confidentiality", "Integrity", "Availability"],
        architecture_type="Microservices",
        compliance_frameworks=["PCI DSS", "GDPR"],
        extracted_from=["README.md", "architecture.md"],
        validation_status="approved",
        confidence_score=0.92,
        timestamp=datetime.now()
    ),
    
    'financial_services': ContextInformation(
        technologies=["Java", "Spring Boot", "Oracle", "Angular", "Apache Camel", "VMware"],
        programming_languages=["Java", "TypeScript"],
        sector="Financial Services",
        security_objectives=["Confidentiality", "Integrity", "Availability"],
        architecture_type="Monolithic",
        compliance_frameworks=["SOX", "FFIEC", "PCI DSS"],
        extracted_from=["README.md", "architecture.md"],
        validation_status="approved", 
        confidence_score=0.88,
        timestamp=datetime.now()
    ),
    
    'healthcare': ContextInformation(
        technologies=["C#", ".NET Core", "SQL Server", "Blazor", "Azure", "HL7 FHIR"],
        programming_languages=["C#", "JavaScript"],
        sector="Healthcare",
        security_objectives=["Confidentiality", "Integrity", "Availability"],
        architecture_type="Service-Oriented",
        compliance_frameworks=["HIPAA", "HITECH"],
        extracted_from=["README.md", "architecture.md"],
        validation_status="approved",
        confidence_score=0.90,
        timestamp=datetime.now()
    )
}

# Sample attack trees in Mermaid format
SAMPLE_ATTACK_TREES = {
    'sql_injection_attack': """graph TD
    A[Attacker Goal: Extract Customer Payment Data] --> B[Identify SQL Injection Vulnerability]
    B --> C[Craft Malicious SQL Payload]
    C --> D[Inject Payload via Web Form]
    D --> E[Bypass Input Validation]
    E --> F[Execute Unauthorized SQL Commands]
    F --> G[Extract Database Schema]
    G --> H[Query Payment Tables]
    H --> I[Exfiltrate Customer Data]
    
    %% Mitigation nodes
    J[Input Validation] -.-> E
    K[Parameterized Queries] -.-> F
    L[Database Access Controls] -.-> H
    M[Data Encryption] -.-> I
    
    %% Styling
    classDef attack fill:#ffcccc,stroke:#ff0000,stroke-width:2px
    classDef mitigation fill:#ccffcc,stroke:#00ff00,stroke-width:2px
    classDef goal fill:#ffffcc,stroke:#ffaa00,stroke-width:3px
    
    class A goal
    class B,C,D,E,F,G,H,I attack
    class J,K,L,M mitigation""",
    
    'phishing_attack': """graph TD
    A[Attacker Goal: Gain System Access] --> B[Research Target Organization]
    B --> C[Craft Convincing Phishing Email]
    C --> D[Send Email to Employees]
    D --> E[Employee Clicks Malicious Link]
    E --> F[Credential Harvesting Page]
    F --> G[Capture Login Credentials]
    G --> H[Access Corporate Systems]
    H --> I[Lateral Movement]
    I --> J[Access Sensitive Data]
    
    %% Mitigation nodes
    K[Security Awareness Training] -.-> E
    L[Email Filtering] -.-> D
    M[Multi-Factor Authentication] -.-> H
    N[Network Segmentation] -.-> I
    
    %% Styling
    classDef attack fill:#ffcccc,stroke:#ff0000,stroke-width:2px
    classDef mitigation fill:#ccffcc,stroke:#00ff00,stroke-width:2px
    classDef goal fill:#ffffcc,stroke:#ffaa00,stroke-width:3px
    
    class A goal
    class B,C,D,E,F,G,H,I,J attack
    class K,L,M,N mitigation"""
}

# Sample threat statement objects
SAMPLE_THREAT_STATEMENTS = [
    ThreatStatement(
        id="T001",
        severity="high",
        threat_source="External attacker with web application knowledge",
        prerequisites="Application exposed to internet, SQL injection vulnerability exists",
        threat_action="Exploit SQL injection vulnerability to extract customer payment data",
        threat_impact="Confidential payment data exposed, PCI DSS compliance violation",
        impacted_assets=["Customer database", "Payment processing system"],
        impacted_goals=["Confidentiality", "Integrity"],
        raw_statement="SQL injection attack against payment system"
    ),
    ThreatStatement(
        id="T002", 
        severity="high",
        threat_source="Malicious actor or competitor",
        prerequisites="Public-facing web services, insufficient rate limiting",
        threat_action="Launch distributed denial of service (DDoS) attack",
        threat_impact="Service unavailability, revenue loss, customer dissatisfaction",
        impacted_assets=["Web application", "API endpoints"],
        impacted_goals=["Availability", "Integrity"],
        raw_statement="DDoS attack against web application"
    )
]