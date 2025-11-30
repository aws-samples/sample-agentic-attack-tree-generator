# ASH Security Scan Report

- **Report generated**: 2025-11-25T16:13:11+00:00
- **Time since scan**: 9 minutes

## Scan Metadata

- **Project**: ASH
- **Scan executed**: 2025-11-25T16:03:29+00:00
- **ASH version**: 3.1.2

## Summary

### Scanner Results

The table below shows findings by scanner, with status based on severity thresholds and dependencies:

- **Severity levels**:
  - **Suppressed (S)**: Findings that have been explicitly suppressed and don't affect scanner status
  - **Critical (C)**: Highest severity findings that require immediate attention
  - **High (H)**: Serious findings that should be addressed soon
  - **Medium (M)**: Moderate risk findings
  - **Low (L)**: Lower risk findings
  - **Info (I)**: Informational findings with minimal risk
- **Duration (Time)**: Time taken by the scanner to complete its execution
- **Actionable**: Number of findings at or above the threshold severity level that require attention
- **Result**:
  - **PASSED** = No findings at or above threshold
  - **FAILED** = Findings at or above threshold
  - **MISSING** = Required dependencies not available
  - **SKIPPED** = Scanner explicitly disabled
  - **ERROR** = Scanner execution error
- **Threshold**: The minimum severity level that will cause a scanner to fail
  - Thresholds: ALL, LOW, MEDIUM, HIGH, CRITICAL
  - Source: Values in parentheses indicate where the threshold is set:
    - `global` (global_settings section in the ASH_CONFIG used)
    - `config` (scanner config section in the ASH_CONFIG used)
    - `scanner` (default configuration in the plugin, if explicitly set)
- **Statistics calculation**:
  - All statistics are calculated from the final aggregated SARIF report
  - Suppressed findings are counted separately and do not contribute to actionable findings
  - Scanner status is determined by comparing actionable findings to the threshold

| Scanner | Suppressed | Critical | High | Medium | Low | Info | Actionable | Result | Threshold |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |
| bandit | 0 | 0 | 0 | 0 | 8 | 0 | 0 | PASSED | MEDIUM (global) |
| cdk-nag | 0 | 0 | 0 | 0 | 0 | 0 | 0 | PASSED | MEDIUM (global) |
| cfn-nag | 0 | 0 | 0 | 0 | 0 | 0 | 0 | MISSING | MEDIUM (global) |
| checkov | 0 | 0 | 0 | 0 | 0 | 0 | 0 | PASSED | MEDIUM (global) |
| detect-secrets | 0 | 4 | 0 | 0 | 0 | 0 | 4 | SKIPPED | MEDIUM (global) |
| grype | 0 | 0 | 0 | 0 | 0 | 0 | 0 | MISSING | MEDIUM (global) |
| npm-audit | 0 | 0 | 0 | 0 | 0 | 0 | 0 | PASSED | MEDIUM (global) |
| opengrep | 0 | 0 | 0 | 0 | 0 | 0 | 0 | MISSING | MEDIUM (global) |
| semgrep | 0 | 0 | 0 | 0 | 0 | 0 | 0 | PASSED | MEDIUM (global) |
| syft | 0 | 0 | 0 | 0 | 0 | 0 | 0 | MISSING | MEDIUM (global) |

### Top 2 Hotspots

Files with the highest number of security findings:

| Finding Count | File Location |
| ---: | --- |
| 2 | src/threatforest/data/threat-intelligence/enterprise-attack-18.0.json |
| 2 | .ash/ash_output/converted/archive/scan-holmes__zip/src/threatforest/data/threat-intelligence/enterprise-attack-18.0.json |

<h2>Detailed Findings</h2>

<details>
<summary>Show 4 actionable findings</summary>

### Finding 1: SECRET-ARTIFACTORY-CREDENTIALS

- **Severity**: HIGH
- **Scanner**: detect-secrets
- **Rule ID**: SECRET-ARTIFACTORY-CREDENTIALS
- **Location**: src/threatforest/data/threat-intelligence/enterprise-attack-18.0.json:292911

**Description**:
Secret of type 'Artifactory Credentials' detected in file 'src/threatforest/data/threat-intelligence/enterprise-attack-18.0.json' at line 292911

**Code Snippet**:
```
Secret of type Artifactory Credentials detected
```

---

### Finding 2: SECRET-ARTIFACTORY-CREDENTIALS

- **Severity**: HIGH
- **Scanner**: detect-secrets
- **Rule ID**: SECRET-ARTIFACTORY-CREDENTIALS
- **Location**: src/threatforest/data/threat-intelligence/enterprise-attack-18.0.json:292901

**Description**:
Secret of type 'Artifactory Credentials' detected in file 'src/threatforest/data/threat-intelligence/enterprise-attack-18.0.json' at line 292901

**Code Snippet**:
```
Secret of type Artifactory Credentials detected
```

---

### Finding 3: SECRET-ARTIFACTORY-CREDENTIALS

- **Severity**: HIGH
- **Scanner**: detect-secrets
- **Rule ID**: SECRET-ARTIFACTORY-CREDENTIALS
- **Location**: .ash/ash_output/converted/archive/scan-holmes__zip/src/threatforest/data/threat-intelligence/enterprise-attack-18.0.json:292901

**Description**:
Secret of type 'Artifactory Credentials' detected in file '.ash/ash_output/converted/archive/scan-holmes__zip/src/threatforest/data/threat-intelligence/enterprise-attack-18.0.json' at line 292901

**Code Snippet**:
```
Secret of type Artifactory Credentials detected
```

---

### Finding 4: SECRET-ARTIFACTORY-CREDENTIALS

- **Severity**: HIGH
- **Scanner**: detect-secrets
- **Rule ID**: SECRET-ARTIFACTORY-CREDENTIALS
- **Location**: .ash/ash_output/converted/archive/scan-holmes__zip/src/threatforest/data/threat-intelligence/enterprise-attack-18.0.json:292911

**Description**:
Secret of type 'Artifactory Credentials' detected in file '.ash/ash_output/converted/archive/scan-holmes__zip/src/threatforest/data/threat-intelligence/enterprise-attack-18.0.json' at line 292911

**Code Snippet**:
```
Secret of type Artifactory Credentials detected
```

</details>

---

*Report generated by [Automated Security Helper (ASH)](https://github.com/awslabs/automated-security-helper) at 2025-11-25T16:13:11+00:00*