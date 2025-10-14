## TTC Technique Mapping 

Following the attack tree creation, perform an analysis to identify potential alignments with AWS Threat Technique Catalog (TTC) techniques. This mapping should enhance rather than constrain the attack tree generation process. This data is in STIX format and stored in the stix-data folder threatforest-agentic-application/threatforest-strands/stix-data

### TTC Mapping Guidelines:

**Analysis Process:**
1. For each step in each attack tree, analyze its characteristics against available TTC techniques
2. Look for semantic alignment between the attack step's purpose and TTC technique descriptions
3. Only apply TTC mapping when there is a strong conceptual match (>80% alignment)
4. Preserve the original attack step description while incorporating the TTC reference

When a strong TTC alignment is identified, update the mermaid syntax for the attack step such as:
```
node_id["[TTC_ID] [TTC_Name] - [Original attack step description]"]
``` 
