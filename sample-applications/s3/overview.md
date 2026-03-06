# Amazon S3 Service Launch — Threat Assessment Overview

## Service Description

Amazon Simple Storage Service (Amazon S3) is an object storage service offering industry-leading scalability, data availability, security, and performance. This assessment evaluates the security posture of an S3 deployment supporting a multi-tenant SaaS platform that stores and serves customer data across multiple AWS regions.

## Architecture Overview

### Core Components

- **S3 Buckets**: Multiple buckets organized by data classification (public-assets, private-data, logs, backups)
- **S3 Access Points**: Per-tenant access points enforcing tenant isolation via access point policies
- **S3 Object Lambda**: Transforms objects on retrieval (PII redaction, format conversion)
- **CloudFront Distribution**: CDN layer for public asset delivery with Origin Access Control (OAC)
- **AWS KMS**: Customer-managed keys (CMKs) for server-side encryption (SSE-KMS)
- **IAM Roles & Policies**: Service roles, cross-account roles, and federated identity access
- **VPC Endpoints (Gateway)**: Private connectivity from VPCs to S3 without internet traversal
- **S3 Event Notifications**: Triggers to Lambda, SQS, and SNS for object lifecycle events
- **AWS CloudTrail**: Data event logging for all S3 API calls
- **S3 Inventory & Storage Lens**: Visibility into bucket contents and access patterns

### Data Flow

1. **Ingestion**: Applications upload objects via HTTPS using pre-signed URLs or IAM-authenticated SDK calls through VPC gateway endpoints.
2. **Storage**: Objects are encrypted at rest with SSE-KMS. Bucket versioning is enabled. Object Lock (governance mode) protects compliance-critical data.
3. **Retrieval**: Authorized principals retrieve objects via access points, pre-signed URLs, or CloudFront. S3 Object Lambda applies transformations before delivery.
4. **Replication**: Cross-region replication (CRR) copies objects to a disaster recovery region. Same-region replication (SRR) feeds the analytics pipeline.
5. **Lifecycle**: Intelligent-Tiering transitions infrequently accessed data. Expired objects are permanently deleted after a 90-day retention window.

### Data Classification

| Bucket | Classification | Encryption | Public Access |
|--------|---------------|------------|---------------|
| `prod-public-assets` | Public | SSE-S3 | CloudFront OAC only |
| `prod-customer-data` | Confidential | SSE-KMS (per-tenant CMK) | Blocked |
| `prod-audit-logs` | Restricted | SSE-KMS (audit CMK) | Blocked |
| `prod-backups` | Confidential | SSE-KMS + Object Lock | Blocked |

### Access Control Model

- **Bucket Policies**: Deny all access except from designated VPC endpoints and CloudFront OAC.
- **Access Point Policies**: Scope each tenant to their object prefix (`tenant-id/*`).
- **IAM Policies**: Least-privilege roles for application services; no wildcard resource grants.
- **S3 Block Public Access**: Enabled at the account level and on every bucket.
- **Pre-signed URLs**: Time-limited (15 min) for direct client uploads/downloads; generated server-side.

### Compliance & Governance

- **Object Lock**: Governance mode on audit logs and backups (WORM).
- **Bucket Versioning**: Enabled on all buckets; MFA Delete required on `prod-backups`.
- **CloudTrail Data Events**: Logged for `GetObject`, `PutObject`, `DeleteObject` across all buckets.
- **S3 Storage Lens**: Organization-level dashboard for anomaly detection on access patterns.
- **AWS Config Rules**: `s3-bucket-public-read-prohibited`, `s3-bucket-ssl-requests-only`, `s3-bucket-server-side-encryption-enabled`.

### Network Architecture

- All application traffic routes through VPC gateway endpoints; no internet-facing S3 access except via CloudFront.
- VPC endpoint policies restrict access to only the designated production buckets.
- DNS resolution uses private hosted zones to ensure S3 requests resolve to the VPC endpoint.

## Threat Landscape Context

This deployment handles sensitive customer data in a regulated industry. Key concerns include:

- Unauthorized data exposure through bucket misconfiguration or policy drift
- Insider threats from over-privileged IAM principals
- Data exfiltration via pre-signed URL abuse or replication hijacking
- Ransomware/data destruction attacks targeting versioning and Object Lock bypass
- Supply chain risks from compromised Lambda functions in the Object Lambda pipeline
- Cross-tenant data leakage through access point policy misconfiguration
