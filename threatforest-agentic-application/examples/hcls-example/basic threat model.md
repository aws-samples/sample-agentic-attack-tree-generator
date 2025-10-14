# Basic Threat Model - Healthcare Analytics Environment

## System Overview
This healthcare analytics platform processes sensitive healthcare data through a multi-stage pipeline involving data ingestion, storage, processing, and reporting across AWS services.

## Assets
- **PHI/PII Data**: Patient health information and personally identifiable information
- **Research Data**: Clinical research datasets and analytics
- **Business Intelligence**: Regulatory reports and business insights
- **ML Models**: Trained machine learning models for healthcare analytics
- **Infrastructure**: AWS cloud resources and configurations

## Trust Boundaries
1. **External to AWS**: SaaS applications, customer-hosted systems, external data sources
2. **AWS Perimeter**: VPN/Direct Connect entry points
3. **Data Lake Boundary**: Raw vs. curated data segregation
4. **User Access Boundaries**: Business users, regulators, providers, data scientists

## Threat Statements

### Data Flow 1: Ingestion (SaaS → AWS AppFlow)
**T1.1** - An attacker could intercept healthcare data during transmission from SaaS applications to AWS AppFlow, leading to PHI exposure.

**T1.2** - Compromised SaaS application credentials could allow unauthorized data extraction through AppFlow connectors.

**T1.3** - Insufficient data validation in AppFlow could allow malicious payloads to enter the analytics pipeline.

### Data Flow 2: Storage (S3 Data Lake)
**T2.1** - Misconfigured S3 bucket permissions could expose raw healthcare data to unauthorized users or public access.

**T2.2** - An attacker with AWS account access could exfiltrate large volumes of PHI from the S3 data lake.

**T2.3** - Inadequate encryption at rest could expose sensitive data if storage media is compromised.

### Data Flow 3: Processing (Glue/Redshift)
**T3.1** - SQL injection attacks against Redshift could allow unauthorized data access or modification.

**T3.2** - Compromised Glue ETL jobs could corrupt or exfiltrate data during processing.

**T3.3** - Insufficient access controls on Athena queries could allow unauthorized data analysis.

### Data Flow 4: Analytics & Reporting
**T4.1** - QuickSight dashboards could inadvertently expose aggregated PHI to unauthorized business users.

**T4.2** - Custom applications with weak authentication could provide unauthorized access to processed healthcare data.

**T4.3** - ML model inference endpoints could be exploited to extract training data through model inversion attacks.

### Cross-Cutting Threats
**T5.1** - Compromised IAM credentials could provide broad access across the entire healthcare analytics pipeline.

**T5.2** - Insufficient logging and monitoring could allow data breaches to go undetected for extended periods.

**T5.3** - Insider threats from privileged users could lead to unauthorized PHI access or data exfiltration.

**T5.4** - VPN/Direct Connect compromise could provide attackers with network-level access to the entire environment.

**T5.5** - Inadequate data retention policies could lead to unnecessary PHI exposure and compliance violations.

## High-Priority Mitigations
1. Implement end-to-end encryption for all data flows
2. Apply principle of least privilege for all IAM roles and policies
3. Enable comprehensive logging with AWS CloudTrail and CloudWatch
4. Implement data loss prevention (DLP) controls
5. Regular security assessments and penetration testing
6. Multi-factor authentication for all user access
7. Network segmentation and VPC security groups
8. Regular backup and disaster recovery testing

## Compliance Considerations
- HIPAA compliance for PHI handling
- SOC 2 Type II for service organization controls
- GDPR compliance for EU patient data
- FDA regulations for clinical research data
