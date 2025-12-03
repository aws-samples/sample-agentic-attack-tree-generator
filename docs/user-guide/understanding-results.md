# Understanding Your Results

After ThreatForest completes analysis, you'll have a comprehensive set of outputs. This guide explains what you get, how to explore it, and how to use the results effectively.

## Output Directory Structure

ThreatForest creates a `threatforest/` directory in your project:

```
project/
└── threatforest/
    └── attack_trees/
        ├── .threatforest_state.json          # State tracking
        ├── attack_tree_T001_sql_injection.md # Individual attack trees
        ├── attack_tree_T002_xss_attack.md
        ├── attack_tree_T003_auth_bypass.md
        ├── attack_trees_dashboard.html       # ⭐ Interactive visualization
        ├── threatforest_data.json            # JSON export
        └── threatforest_analysis_report.md   # Summary report
```

## Interactive Dashboard ⭐ PRIMARY INTERFACE

The HTML dashboard is your main way to explore results.

### Opening the Dashboard

```bash
# Mac
open ./project/threatforest/attack_trees/attack_trees_dashboard.html

# Linux
xdg-open ./project/threatforest/attack_trees/attack_trees_dashboard.html

# Windows
start ./project/threatforest/attack_trees/attack_trees_dashboard.html
```

### Dashboard Overview

The dashboard provides:

- **Visual Threat Overview** - See all threats at a glance
- **Interactive Network Graph** - Explore attack trees visually
- **Search and Filter** - Find specific threats or techniques
- **MITRE ATT&CK Integration** - View mapped techniques
- **Metrics and Statistics** - Understand threat landscape

### Main Sections

#### 1. Threat Overview Panel

![Executive Summary Threats](../assets/images/ExecutiveSummaryThreats.gif)

#### 2. Interactive Network Graph

![Explore Attack Steps](../assets/images/ExploreAttackSteps.gif)

**Center of dashboard** - Visual representation of all threats:

**Features:**
- Color-coded by severity (Red=High, Orange=Medium, Yellow=Low)
- Click nodes to view details
- Zoom and pan to navigate
- Hover for quick preview
- Drag to reposition

**Interactions:**

- **Click Node** - View threat details in side panel
- **Hover Node** - See quick preview
- **Drag Node** - Reposition for better view
- **Scroll** - Zoom in/out
- **Click Background** - Deselect and reset

#### 3. Threat Detail Panel

![Explore Mitigations and Navigate to MITRE](../assets/images/ExploreMitigationsNavigateToMitre.gif)

**Right sidebar** (appears when threat selected):

**Sections:**

- **Threat Information** - Full statement, severity, affected components
- **Attack Paths** - Step-by-step sequences with impact ratings
- **MITRE ATT&CK Mappings** - Technique IDs, tactics, confidence scores
- **Mitigations** - Security controls and implementation guidance

### Using the Dashboard

#### For Security Architects

**Workflow:**

1. Review overview to understand threat landscape
2. Focus on high-severity threats
3. Examine attack paths to understand vectors
4. Validate architecture controls
5. Export findings for documentation

**Key Features:**

- Network graph for architecture visualization
- Attack path analysis for control validation
- MITRE mapping for industry alignment

#### For Security Engineers

**Workflow:**

1. Filter by category for specific threat types
2. Review technical attack steps
3. Check MITRE techniques for detection alignment
4. Implement security control guidance
5. Track remediation progress

**Key Features:**

- Detailed attack steps
- Technical prerequisites
- Mitigation implementation guidance

#### For Developers

**Workflow:**
1. Search by component to find relevant threats
2. Understand how attacks work
3. Identify vulnerable conditions
4. Apply security fixes
5. Verify all threats are addressed

**Key Features:**

- Component-specific filtering
- Clear attack explanations
- Actionable mitigation steps

### Dashboard Performance

**Optimization for Large Threat Models:**

- Use filters to reduce visible threats
- Collapse details when not needed
- Export subsets for focused analysis

**Performance Metrics:**

- <10 threats: Instant loading
- 10-50 threats: <2 seconds
- 50-100 threats: <5 seconds
- 100+ threats: May require filtering

**Browser Compatibility:**

- ✅ Chrome 90+
- ✅ Firefox 88+
- ✅ Safari 14+
- ✅ Edge 90+

## Individual Attack Tree Files

Each threat gets a dedicated markdown file with complete details.

### File Pattern

`attack_tree_T###_*.md`

### Contents

**Threat Metadata:**

- ID and title
- Severity level
- STRIDE category
- Affected components

**Attack Paths:**

- Multiple paths per threat
- Step-by-step sequences
- Prerequisites for each step
- Impact and likelihood ratings

**MITRE ATT&CK Mappings:**

- Technique IDs and names
- Tactic categorization
- Confidence scores
- Technique descriptions

**Mitigations:**

- Security control recommendations
- Implementation guidance
- Best practices
- Priority rankings

**Mermaid Diagrams:**

- Visual attack tree representation
- Shows attack flow and dependencies

### Example Structure

```markdown
# Attack Tree: SQL Injection in User Login

**Threat ID:** T001
**Severity:** High
**Category:** Injection

## Description
Attacker exploits insufficient input validation in the login form...

## Attack Paths

### Path 1: Direct SQL Injection via Login Form

**Likelihood:** High | **Impact:** Critical

**Attack Steps:**

1. Identify login endpoint
   - **MITRE ATT&CK:** T1190 - Exploit Public-Facing Application
   - **Prerequisites:** Login form accessible
   - **Mitigation:** M1050 - Exploit Protection

2. Test for SQL injection
   - **MITRE ATT&CK:** T1190 - Exploit Public-Facing Application
   - **Prerequisites:** Input validation not implemented
   - **Mitigation:** M1027 - Password Policies

3. Craft bypass payload
   - **MITRE ATT&CK:** T1078 - Valid Accounts
   - **Prerequisites:** Error messages reveal structure
   - **Mitigation:** M1027 - Password Policies

...

## Mermaid Diagram
[Visual representation]
```

### Use Cases

- Security code reviews
- Developer training materials
- Penetration testing guidance
- Security documentation
- Version control tracking

## JSON Data Export

**File:** `threatforest_data.json`

**Purpose:** Structured data for programmatic access and tool integration.

### Schema

```json
{
  "metadata": {
    "analysis_date": "2025-11-28T14:30:00Z",
    "threatforest_version": "1.0.0",
    "project_name": "MyApp",
    "total_threats": 8,
    "high_severity_count": 3,
    "medium_severity_count": 4,
    "low_severity_count": 1
  },
  "threats": [
    {
      "id": "T001",
      "title": "SQL Injection in User Login",
      "severity": "High",
      "category": "Injection",
      "description": "...",
      "affected_components": ["Login API", "User Database"],
      "attack_paths": [...],
      "mitre_techniques": [...],
      "mitigations": [...]
    }
  ]
}
```

### Use Cases

- Custom reporting tools
- CI/CD integration
- Security dashboards
- Metrics tracking
- Data analysis

### Example Usage

```python
import json

# Load threat data
with open('threatforest_data.json', 'r') as f:
    data = json.load(f)

# Count high-severity threats
high_severity = [t for t in data['threats'] if t['severity'] == 'High']
print(f"High-severity threats: {len(high_severity)}")

# Extract MITRE techniques
techniques = set()
for threat in data['threats']:
    for tech in threat.get('mitre_techniques', []):
        techniques.add(tech['technique_id'])
print(f"Unique MITRE techniques: {len(techniques)}")
```

## Analysis Report

**File:** `threatforest_analysis_report.md`

**Purpose:** Executive summary with key findings and statistics.

### Contents

- Analysis overview
- Threat statistics
- Severity distribution
- Key findings
- Recommendations
- Coverage metrics

### Example

```markdown
# ThreatForest Analysis Report

**Project:** MyApp E-Commerce Platform
**Analysis Date:** 2025-11-28 14:30:00

## Executive Summary

Analysis identified 8 threats, with 3 classified as high severity 
requiring immediate attention.

## Threat Statistics

- Total Threats: 8
- High Severity: 3 (37.5%)
- Medium Severity: 4 (50%)
- Low Severity: 1 (12.5%)

## Key Findings

### Critical Threats

1. **T001: SQL Injection in User Login**
   - Impact: Database compromise
   - Recommendation: Implement parameterized queries

2. **T002: Authentication Bypass via JWT**
   - Impact: Unauthorized access
   - Recommendation: Strengthen JWT validation

...

## Recommendations

### Immediate Actions
1. Address all high-severity threats within 30 days
2. Implement input validation across all inputs
3. Review authentication mechanisms

...
```

### Use Cases

- Executive briefings
- Security review meetings
- Audit documentation
- Compliance reporting

## State File

**File:** `.threatforest_state.json`

**Purpose:** Tracks workflow progress for resume capability.

**Contains:**

- Processed threats
- Current progress
- Timestamp information
- Configuration snapshot

**Note:** Automatically managed by ThreatForest. Do not edit manually.

## Working with Results

### Version Control

**Recommended Approach:**

```bash
# Commit threat models
git add threats/*.tc.json
git commit -m "Update threat model"

# Commit generated outputs
git add threatforest/
git commit -m "Update threat analysis"

# Tag releases
git tag -a v1.0-threat-analysis -m "Initial threat analysis"
```

### Sharing Results

**Dashboard for Presentations:**

- Host on internal web server for team access
- Export to PDF for email distribution
- Screenshot key findings for reports

**JSON for Automation:**

- CI/CD integration
- Custom dashboards
- Metrics tracking

**Markdown for Documentation:**

- Include in security docs
- Version control friendly
- Easy to review in PRs

### Comparing Versions

```bash
# Compare attack trees
diff threatforest/attack_trees/attack_tree_T001.md \
     threatforest-old/attack_trees/attack_tree_T001.md

# Compare JSON data
jq -S . threatforest/attack_trees/threatforest_data.json > current.json
jq -S . threatforest-old/attack_trees/threatforest_data.json > previous.json
diff current.json previous.json
```

## Best Practices

### Organization

- Keep outputs in version control
- Use consistent naming conventions
- Archive old analyses with timestamps
- Document analysis dates in commit messages

### Maintenance

- Regenerate after threat model changes
- Review outputs quarterly
- Track remediation progress
- Update when architecture changes

### Security

- Don't expose outputs publicly (contains sensitive info)
- Use internal hosting only for dashboard
- Sanitize data before external sharing
- Encrypt archives if needed

## Need Help?

Having issues with results or the dashboard? Check the [FAQ Troubleshooting section](../faq.md#troubleshooting) for solutions.

## Next Steps

- **[Running ThreatForest](running-threatforest.md)** - Learn the analysis process
- **[Preparing Your Project](preparing-your-project.md)** - Optimize inputs
- **[How ThreatForest Works](../how-it-works.md)** - Technical deep dive
