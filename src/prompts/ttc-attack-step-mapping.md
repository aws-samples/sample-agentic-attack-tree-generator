You are a cybersecurity expert. Map these attack steps to the most relevant MITRE ATT&CK techniques.

**Instructions:**
For each attack step, identify the 1-2 most relevant techniques. Consider:
- Attack method similarity
- Tactic alignment
- Technical implementation

**Output Format (JSON):**
```json
[
  {
    "attack_step": "step description",
    "node_id": "step_id",
    "techniques": [
      {
        "technique_id": "T1234",
        "confidence": 0.85,
        "reasoning": "brief explanation"
      }
    ]
  }
]
```

Return only the JSON array.
