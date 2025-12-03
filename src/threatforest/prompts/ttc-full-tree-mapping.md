You are a cybersecurity expert. Analyze this attack tree and map each attack step to MITRE ATT&CK techniques.

For each attack step in the tree, identify the most relevant MITRE ATT&CK technique. Return a JSON response:

{
  "mappings": [
    {
      "attack_step": "description of the attack step",
      "technique_id": "T1234",
      "technique_name": "Technique Name", 
      "tactic": "Tactic Name",
      "confidence": 0.9
    }
  ]
}

Focus on specific techniques with high confidence scores (0.7+).
