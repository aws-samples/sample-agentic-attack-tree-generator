# Attack Tree to Mermaid Diagram Prompt

Convert the following attack tree data into a Mermaid flowchart diagram. Use this exact format:

## Structure Requirements:
- Use `graph TD` (top-down direction)
- Node format: `node_id["descriptive text"]`
- Connection format: `parent --> child`
- Include all relationships from the input data

## Color Coding (apply these exact CSS classes):
```
classDef attack fill:#ffcccc
classDef mitigation fill:#ccffcc  
classDef goal fill:#ffcc99
classDef fact fill:#ccccff

class node1,node2,node3 attack
class node4,node5,node6 mitigation
class node7,node8 goal
class node9,node10 fact
```

## Node Classification:
- **Facts**: Initial conditions, vulnerabilities, or starting points
- **Attacks**: Malicious actions, exploits, or threat vectors
- **Mitigations**: Security controls, defenses, or countermeasures
- **Goals**: Ultimate objectives or outcomes (what attackers/defenders achieve)

## Output Format:
1. Title as markdown header
2. Mermaid code block with the diagram
3. Apply color classes at the end




