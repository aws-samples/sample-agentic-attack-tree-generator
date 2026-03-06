# Amazon S3 Service Launch — Threat Statements

## T001 - Unauthorized Data Exposure via Bucket Misconfiguration

A malicious external actor or negligent administrator with knowledge of S3 bucket naming conventions, can modify bucket policies or disable S3 Block Public Access settings to expose objects to the internet, which leads to large-scale unauthorized disclosure of confidential customer data, resulting in reduced confidentiality of customer data stored in `prod-customer-data` and `prod-audit-logs` buckets.

## T002 - Data Exfiltration via Pre-signed URL Abuse

A compromised application component or malicious insider with access to the pre-signed URL generation service, can generate long-lived or broadly-scoped pre-signed URLs and distribute them to unauthorized parties, which leads to uncontrolled data retrieval bypassing normal access controls, resulting in reduced confidentiality of customer objects served through pre-signed URL workflows.

## T003 - Cross-Tenant Data Leakage via Access Point Policy Misconfiguration

A malicious tenant or compromised tenant application with valid credentials scoped to one tenant prefix, can exploit overly permissive access point policies or prefix traversal flaws to read or write objects belonging to other tenants, which leads to unauthorized cross-tenant data access, resulting in reduced confidentiality and integrity of multi-tenant customer data isolated by S3 access point policies.

## T004 - Ransomware and Data Destruction via Versioning/Object Lock Bypass

A sophisticated external attacker or compromised administrator with elevated IAM privileges, can disable bucket versioning, remove Object Lock configurations, or delete all object versions including delete markers, which leads to permanent destruction or encryption of critical data, resulting in reduced availability of customer data, audit logs, and backup objects protected by versioning and Object Lock.

## T005 - Insider Threat via Over-Privileged IAM Roles

A malicious insider or compromised service account with broad S3 permissions (e.g., `s3:*` on `*`), can exfiltrate data to external accounts, modify bucket policies to grant unauthorized access, or delete critical objects, which leads to unauthorized data access, policy tampering, and data loss, resulting in reduced confidentiality, integrity, and availability of all S3-hosted assets.

## T006 - Data Interception via Missing or Downgraded Encryption

An attacker positioned on the network path or a misconfigured deployment pipeline, can intercept data in transit by exploiting missing TLS enforcement or access objects encrypted with weak or rotated-out KMS keys, which leads to exposure of plaintext customer data, resulting in reduced confidentiality of objects in transit and at rest across all production buckets.

## T007 - Supply Chain Attack via Compromised S3 Object Lambda

A supply chain attacker or malicious contributor with access to the Object Lambda function code or its dependencies, can inject malicious logic into the transformation pipeline to exfiltrate, modify, or corrupt objects during retrieval, which leads to data tampering and exfiltration at the application layer, resulting in reduced integrity and confidentiality of objects processed through S3 Object Lambda access points.

## T008 - Replication Hijacking and Data Exfiltration via CRR/SRR Misconfiguration

A compromised administrator or attacker with IAM permissions to modify replication configurations, can redirect cross-region or same-region replication to attacker-controlled buckets in external AWS accounts, which leads to continuous silent exfiltration of all newly created objects, resulting in reduced confidentiality of replicated customer data and audit logs.

## T009 - Logging Evasion and Forensic Tampering

An advanced attacker or compromised administrator with CloudTrail and S3 management permissions, can disable CloudTrail data event logging, delete or modify audit log objects, or suppress S3 event notifications, which leads to loss of forensic evidence and delayed incident detection, resulting in reduced integrity of the audit trail and security monitoring capabilities for all S3 operations.

## T010 - Denial of Service via S3 Request Flooding or Lifecycle Policy Abuse

An external attacker or compromised application with network access to S3 endpoints, can flood S3 with high-volume requests to exhaust request rate limits or manipulate lifecycle policies to prematurely delete or transition objects, which leads to service degradation and unintended data loss, resulting in reduced availability of S3-hosted assets and application functionality dependent on object storage.
