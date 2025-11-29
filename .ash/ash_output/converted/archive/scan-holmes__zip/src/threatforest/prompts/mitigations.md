
## Mitigation Generation

Generate a separate CSV file with comprehensive mitigations:

```csv
Attack Step,Mitigation,Type,Description,TTC Reference
[attack_step_1],[mitigation_name],Preventative,[detailed_description],[relevant_ttc_id]
[attack_step_2],[mitigation_name],Detective,[detailed_description],[relevant_ttc_id]
```

### Mitigation Guidelines:
- **Minimum**: One mitigation per attack step
- **Types**: Preventative (blocks attack) or Detective (detects attack)
- **AWS Focus**: Leverage AWS security services and best practices
- **TTC Alignment**: Reference relevant TTC techniques where applicable

**Common AWS Mitigations:**
- **IAM**: Least privilege, MFA, role-based access
- **Monitoring**: CloudTrail, GuardDuty, Security Hub
- **Network**: VPC security groups, NACLs, WAF
- **Data**: Encryption at rest/transit, backup strategies
- **Compliance**: Config rules, compliance frameworks


## Output Requirements - PER THREAT STATEMENT

### 2. Mitigations CSV
**Filename**: `{threat-id}-mitigations.csv`
- Standard CSV format with headers
- One row per mitigation
- Include attack step, mitigation name, type, description, TTC reference
- Focus on AWS security best practices