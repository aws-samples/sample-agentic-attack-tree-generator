# Attack Tree: LLM01 Prompt Injection / LLM06 Excessive Agency

```mermaid
graph TD
    goal["Exfiltrate sensitive data and maintain persistent access to LLM system and connected resources"]
    
    fact1["LLM plugins lack input validation and sanitization mechanisms"]
    fact2["LLM agents have excessive permissions to access external systems and APIs"]
    fact3["System prompts and instructions are vulnerable to injection attacks"]
    fact4["Plugin communication channels lack proper authentication and authorization"]
    
    attack1["Craft malicious prompts with embedded system commands to bypass content filters"]
    attack2["Inject prompt instructions to manipulate plugin behavior and extract system information"]
    attack3["Exploit plugin API calls to access unauthorized databases and file systems"]
    attack4["Use indirect injection via compromised data sources to poison LLM responses"]
    attack5["Chain multiple plugin vulnerabilities to escalate privileges across connected systems"]
    attack6["Implement persistence through malicious prompt templates stored in system memory"]
    attack7["Exfiltrate training data and model parameters through crafted conversation flows"]
    
    mitigation1["Implement strict input validation and prompt sanitization filters"]
    mitigation2["Apply principle of least privilege to LLM agent permissions and API access"]
    mitigation3["Deploy real-time monitoring and anomaly detection for suspicious prompt patterns"]
    mitigation4["Establish secure plugin sandboxing with isolated execution environments"]
    
    fact1 --> attack1
    fact1 --> attack2
    fact2 --> attack3
    fact2 --> attack5
    fact3 --> attack1
    fact3 --> attack4
    fact4 --> attack3
    fact4 --> attack6
    
    attack1 --> attack2
    attack2 --> attack3
    attack3 --> attack5
    attack4 --> attack5
    attack5 --> attack6
    attack6 --> attack7
    attack7 --> goal
    
    mitigation1 -.-> attack1
    mitigation1 -.-> attack2
    mitigation1 -.-> attack4
    mitigation2 -.-> attack3
    mitigation2 -.-> attack5
    mitigation3 -.-> attack6
    mitigation3 -.-> attack7
    mitigation4 -.-> attack3
    mitigation4 -.-> attack5
    
    classDef attack fill:#ffcccc
    classDef mitigation fill:#ccffcc
    classDef goal fill:#ffcc99
    classDef fact fill:#ccccff
    
    class attack1,attack2,attack3,attack4,attack5,attack6,attack7 attack
    class mitigation1,mitigation2,mitigation3,mitigation4 mitigation
    class goal goal
    class fact1,fact2,fact3,fact4 fact
```