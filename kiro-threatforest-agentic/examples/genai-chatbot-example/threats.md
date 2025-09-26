## Threats

# LLM Security Threats

## Threat 1 - LLM01 Prompt Injection
An external threat actor with ability to interact with an LLM system can overwrite the system prompt with crafted prompts, including through adversarial suffixes and obfuscated text, which leads to force unintended actions from the LLM, resulting in reduced integrity and/or availability of LLM system and connected resources

## Threat 2 - LLM01 Prompt Injection
An external threat actor able to submit content to an LLM system can can embed malicious prompts in that content, including via indirect prompt injection and multi-stage attacks, which leads to manipulation of the LLM into undertaking harmful actions, resulting in reduced integrity and/or availability of LLM system and connected resources

## Threat 3 - LLM01 Prompt Injection / LLM06 Excessive Agency
[High]
An external threat actor who enables compromised LLM plugins or agents in an LLM system can manipulate it via indirect or direct prompt injection, which leads to access unauthorized functionality or data, resulting in reduced confidentiality and/or integrity of connected and downstream systems and data

## Threat 4 - LLM05 Improper Output Handling
An external threat actor able to interact with an LLM system can exploit insufficient output encoding, which leads to achieve XSS or code injection, resulting in reduced confidentiality and/or integrity of user data

## Threat 5 - LLM05 Improper Output Handling
An external threat actor who has access to an LLM with insufficient safeguards against harmful content generation can craft prompts that generate malicious outputs, which leads to exploiting vulnerabilities like command injections in integrated downstream functions when malicious outputs are passed to them, resulting in reduced confidentiality, integrity and/or availability of LLM system and connected resources

## Threat 6 - LLM05 Improper Output Handling
An external threat actor with ability to manipulate LLM outputs can craft payloads that exploit downstream function vulnerabilities, which leads to execution of unauthorized code, resulting in reduced integrity and/or confidentiality of connected and downstream systems and data

## Threat 7 - LLM04 Data/Model Poisoning
[High]
A malicious internal actor with access to upload training or fine tuning data can intentionally introduce manipulated, biased or malicious data, which leads to model poisoning or backdoors, resulting in reduced integrity and/or effectiveness of the LLM model

## Threat 9 - LLM04 Data/Model Poisoning
[High]
A malicious internal actor with access to manage training or fine tuning pipelines can inject malicious tools or processes, which leads to tampering with training data, resulting in reduced integrity of the LLM model

## Threat 10 - LLM10 Unbounded Consumption
[High]
An external threat actor able to submit requests to an LLM API can overwhelm it with expensive computing operations, which leads to denying service to legitimate users, resulting in reduced availability of the LLM inference API

## Threat 11 - LLM10 Unbounded Consumption
An external threat actor with access to submit LLM requests can abuse request batching systems, which leads to overwhelming resources with queued jobs, resulting in reduced availability of the LLM inference API

## Threat 12 - LLM10 Unbounded Consumption
An external threat actor who is able to access an LLM API can submit expensive requests in a denial-of-wallet attack pattern, which leads to high hosting costs, resulting in reduced availability and/or financial losses of the LLM service provider

## Threat 13 - LLM03 Supply Chain
[High]
An external or internal threat actor who has access to an LLM powered application using compromised upstream open source dependencies can enable exploits through vulnerabilities, which leads to unauthorized system access, resulting in reduced confidentiality, integrity and/or availability of LLM system and connected resources

## Threat 14 - LLM04 Data/Model Poisoning
An untrusted data supplier with questionable integrity can provide manipulated, biased, or malicious training data, which leads to degraded model performance and compromised training, resulting in reduced integrity and/or robustness of the LLM model

## Threat 15 - LLM03 Supply Chain
An external or internal threat actor who has access to an LLM powered application using a deprecated third-party LLM inference API can introduce vulnerabilities, which leads to successful exploitation of security weaknesses, resulting in reduced integrity and/or availability of connected and downstream systems and data

## Threat 16 - LLM02 SensitiveInfo Disclosure
A malicious internal actor who trains an LLM on confidential data without proper safeguards can expose that data, which leads to unfiltered model outputs or model inversion attacks, resulting in reduced confidentiality of sensitive user and training data

## Threat 17 - LLM02 SensitiveInfo Disclosure
[High]
A malicious internal actor who applies insufficient data anonymization to an LLM training or fine tuning dataset can allow sensitive data to remain identifiable, which leads to exposing it via model outputs, resulting in reduced confidentiality of impacted individuals and sensitive data

## Threat 18 - LLM02 SensitiveInfo Disclosure
A malicious internal actor who trains or fine-tunes an LLM model on sparse or sensitive data without proper regularization techniques can overfit the model, which leads to the LLM memorizing and potentially exposing confidential information through various attack vectors (e.g., membership inference, data reconstruction), resulting in reduced confidentiality of sensitive user and training data and reduced robustness of the LLM model

## Threat 19 - LLM06 Excessive Agency
An external threat actor permitted to enable third-party LLM plugins can exploit plugin vulnerabilities, which leads to remote code execution, resulting in reduced confidentiality, integrity and/or availability of connected and downstream systems and data

## Threat 20 - LLM06 Excessive Agency
[High]
A malicious internal actor who is using insecure coding practices can introduce vulnerabilities through unsafe plugin code execution, input validation, access controls, which leads to security control bypasses, resulting in reduced confidentiality, integrity and/or availability of connected and downstream systems and data

## Threat 21 - LLM06 Excessive Agency
An external threat actor with access to an overprivileged LLM plugins/tools can abuse those permissions to access unauthorized resources or functionality, which leads to privilege escalation, resulting in reduced confidentiality, integrity and/or availability of connected and downstream systems and data

## Threat 22 - LLM06 Excessive Agency
An external or internal threat actor who has access to LLM agents granted permissions to access external systems can abuse those permissions, which leads to damage connected systems when operating under ambiguous instructions or in multi-agent collaborative environments, resulting in reduced integrity and/or availability of connected and downstream systems and data

## Threat 23 - LLM09 Misinformation
A malicious actor who controls an automated system with direct access to unconstrained LLM outputs can execute impactful actions or make critical decisions based on potentially incorrect, biased, or manipulated data, which leads to automated propagation of errors or biases, resulting in reduced integrity and/or reliability of business systems and workflows

## Threat 24 - LLM06 Excessive Agency
An external or internal threat actor who has access to an LLM system with excessive functional capabilities can abuse those capabilities when operating under ambiguous instructions, which leads to unauthorized operations, resulting in reduced integrity and/or availability of connected and downstream systems and data

## Threat 25 - LLM09 Misinformation
A legitimate user who is over reliant on LLM recommendation can accept biased, unethical, or incorrect guidance and advice, which leads to discriminatory outcomes, reputational damage, financial loss, legal issues or cyber risks, resulting in reduced integrity and/or confidentiality of LLM system and connected resources

## Threat 26 - LLM09 Misinformation
[High]
An egitimate user who is overly dependent on LLM outputs can make unsupported decisions based on incorrect data or recommendations, which leads to leads to propagation of erroneous information, resulting in reduced integrity of connected and downstream systems and data

## Threat 28 - LLM03 Supply Chain / LLM10 Unbounded Consumption
An external threat actor who can infiltrate insecure environments can exfiltrate proprietary LLM models and artifacts, which leads to unauthorized competitive use, resulting in reduced confidentiality of intellectual property

## Threat 29 - LLM03 Supply Chain / LLM02 SensitiveInfo Disclosure
A malicious internal actor with access to model artifact repositories (for example, fine tuning data, model stores) can exfiltrate proprietary LLM data, which leads to competitive misuse or training of shadow models, resulting in reduced confidentiality and/or integrity of intellectual property

## Threat 30 - LLM02 SensitiveInfo Disclosure
[High]
An external threat actor who uses carefully crafted queries to call inference model APIs can retrieve sensitive information that they were not intended to access, which leads to to exfiltration of proprietary knowledge, resulting in reduced confidentiality of intellectual property

## Threat 31 - LLM08 VectorEmbedding Weakness
An internal or external actor with access to the knowledge base or its source documents can corrupt or manipulate the RAG knowledge base (e.g. Amazon OpenSearch Serverless, Internet lookup), which leads to AI system providing incorrect or malicious information, resulting in reduced integrity and/or trustworthiness of AI system's knowledge base and outputs

## Threat 32 - LLM02 SensitiveInfo Disclosure
A malicious internal actor who has access to production logs can read sensitive customer information contained in chatbot conversation logs, which leads to unauthorized exposure of personal customer details, resulting in reduced confidentiality of impacted individuals and sensitive data

## Threat 33 - LLM01 Prompt Injection
An external threat actor who can submit multimodal content to an LLM system can embed hidden instructions in non-text modalities (images, audio), which leads to bypassing text-based security controls, resulting in reduced integrity and/or confidentiality of LLM system and connected resources

## Threat 34 - LLM08 VectorEmbedding Weakness
An external threat actor who has access to vector embeddings can perform inversion attacks, which leads to extracting sensitive source information from the embedding space, resulting in reduced confidentiality of information in the knowledge base

## Threat 35 - LLM08 VectorEmbedding Weakness
An external threat actor with access to a multi-tenant vector database can exploit insufficient tenant isolation, which leads to cross-tenant data leakage during embedding similarity searches, resulting in reduced confidentiality of proprietary information

## Threat 36 - LLM07 System Prompt Leakage
An external threat actor who can interact with the LLM API can employ carefully crafted queries, which leads to extracting system prompt instructions and internal operation details, resulting in reduced confidentiality of system security configuration and implementation

## Threat 37 - LLM03 Supply Chain
An external threat actor who can contribute to model development pipelines can compromise a LoRA adapter, which leads to introducing backdoors or harmful behaviors when the adapter is integrated, resulting in reduced integrity of model responses

## Threat 38 - LLM03 Supply Chain
An external threat actor who has access to collaborative model development processes can inject malicious code during model merging or conversion, which leads to distribution of compromised models through legitimate channels, resulting in reduced integrity of downstream applications

## Threat 39 - LLM10 Unbounded Consumption
An external threat actor can issue strategic queries to an LLM API can harvest sufficient responses, which leads to replicating model functionality through distillation, resulting in reduced confidentiality of proprietary LLM algorithms and training data
