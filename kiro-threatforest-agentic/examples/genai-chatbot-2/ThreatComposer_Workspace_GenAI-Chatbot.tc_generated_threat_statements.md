# Generated Threat Statements

*This file was automatically generated from ThreatComposer file: ThreatComposer_Workspace_GenAI-Chatbot.tc.json*

## Application Context

**Application Name:** Sample Generative AI Chatbot Application 

**Description:** 

### Disclaimers

_**1. Motivation for externalizing this threat model:**_

_This example threat model for a 'Generative AI Chatbot Application' is informational only and provided "as is" with no representations or warranties whatsoever, and may change at any time due to a variety of factors, such as changes to AWS's services.  The provision of this example threat model does not create any warranties, representations, contractual commitments, conditions or assurances from AWS, its affiliates, suppliers or licensors. We've included this example threat model to show how you could use Threat Composer to create a threat model. This example threat model is a proof of concept and is not suitable for every possible interaction or use case. It aims to give the reader an example of what a set of threats, assumptions and mitigations could look like. We've chosen to share this example as it provides a common reference point for people who are starting off with a 'Generative AI Chatbot Application'. You may have different perspectives on the assumptions, threats, mitigations and prioritization. This is ok, and could be used to start conversations in your organization within the context of your risk appetite. You may want to use this example threat model as the base threat model or starting point to generate a contextualised threat model for your own specific needs and deployment of a 'Generative AI Chatbot Application'. This example threat model uses a reference architecture and is not a complete end-to-end solution. You are solely responsible for making your own independent assessment of this example threat model and its applicability to your organization._

_**2. Source used**_

_This example threat model based is on industry standards like the [Open Worldwide Application Security Project (OWASP) Top 10 for Large Language Models](https://owasp.org/www-project-top-10-for-large-language-model-applications/),  [AWS Well-Architected Framework](https://docs.aws.amazon.com/wellarchitected/latest/framework/welcome.html) and [AWS AWS Security Reference Architecture For Generative AI
](https://docs.aws.amazon.com/prescriptive-guidance/latest/security-reference-architecture/generative-ai.html)_

_**3. Criteria for prioritizing threats**_

_In this example threat model, the (hypothetical) chat-bot operator has explicitly determined that confidentiality of question-and-answer retrieval augmented generation (RAG) is their highest security priority. The chat-bot operator has determined that data integrity (and quality) of inference responses is of moderate security priority due to company training, and additional process controls to ensure chatbot users understand that responses may include inaccuracies and hallucinations. The chat-bot operator determined that availability of their service to be lowest-priority, as they are able to point users to other operational resources if the chat bot functionality has a service availability or degradation lasting several hours to a few days. Please note, these are examples of priorities based on which property ([C/I/A](https://www.nist.gov/image/cia-triad)) they impact. Customers should calculate priority using their own factors as part of any internal risk frameworks._

_**4. Agreement**_

_All use of AWS's services will be governed by the AWS Customer Agreement available at http://aws.amazon.com/agreement/ (or other definitive written agreement as may be agreed between the parties governing the use of AWS's services). If you use any artificial intelligence and machine learning Services, features, and functionality (including third-party models) that we provide, you will comply with the AWS Responsible AI Policy._

### Summary

This example threat model leverages a large language model (LLM) available in [Amazon Bedrock](https://aws.amazon.com/bedrock/) for natural language processing and other capacities, with the aim to deliver an intelligent conversational assistant. The example threat model is intended to  provide rapid, relevant responses to customer questions across diverse use cases like customer service, sales, and e-commerce. Integration with the [LangChain](https://www.langchain.com/)  framework can enable continuity by recalling previous interactions for personalized follow-ups. The goal is to provide an intelligent chatbot to transform customer experiences.

Previous generations of chatbots needed to be programmed for every possible customer interaction. But chatbots powered by LLMs that can access relevant documents can provide more natural conversations. These chatbots and virtual assistants are transforming customer engagements by understanding questions and responding swiftly. Backed by natural language processing and machine learning, the chatbots address customer queries across domains like customer service, sales, and e-commerce. This example threat modelutilizes Amazon Bedrock and other AWS services to boost chatbot capabilities. It offers configurations like basic, prompt-based, persona-based, and context-aware. The focus is delivering smooth, intelligent interactions to delight customers.

### Features

- Integration with Amazon Bedrock for advanced conversational capabilities
- Integration with Amazon Bedrock Guardrails for Responsible AI moderation
- LangChain framework for tracking chat history and context
- Flexible chatbot configurations: basic, prompt-based, persona, context-aware
- Workflow to embed user query, enable contextual search, provide relevant results
- Easy setup using Amazon Bedrock boto3 notebook
- Core natural language processing and machine learning
- Deployable across customer service, sales, and e-commerce etc.
- Integrates across websites, social media, and messaging platforms
- Focuses on contextual, personalized interactions
- Continued innovation for more natural conversations

### Sample architecture and documentation:

- Multi-Model and Multi-RAG Powered Chatbot CDK project, source code available [here](https://github.com/aws-samples/aws-genai-llm-chatbot/tree/main)
- Bedrock Claude Chat project, source code available [here](https://github.com/aws-samples/bedrock-claude-chat)
- A chatbot workshop and source code available [here](https://github.com/aws-samples/amazon-bedrock-workshop/blob/main/04_Chatbot/README.md#lab-4---conversational-interfaces-chatbots)
- Machine Learning Blog on how to use Retrieval Augmented Generation (RAG) is available [here](https://aws.amazon.com/blogs/machine-learning/simplify-access-to-internal-information-using-retrieval-augmented-generation-and-langchain-agents/)

**Technologies:** Not specified

**Total Threats:** 37
- **High Priority:** 17
- **Medium Priority:** 17  
- **Low Priority:** 3

## Threat Statements

### High Priority Threats

#### T001 - Insider Threat

**Threat Statement**: An external threat actor who can interact with the LLM API can employ carefully crafted queries, which leads to extracting system prompt instructions and internal operation details, resulting in reduced confidentiality of system security configuration and implementation

- **Threat Source**: external threat actor
- **Threat Action**: employ carefully crafted queries
- **Threat Impact**: extracting system prompt instructions and internal operation details
- **Priority**: High
- **Category**: Insider Threat

---

#### T002 - AI/ML Security

**Threat Statement**: An external threat actor who can submit multimodal content to an LLM system can embed hidden instructions in non-text modalities (images, audio), which leads to bypassing text-based security controls, resulting in reduced integrity and/or confidentiality of LLM system and connected resources

- **Threat Source**: external threat actor
- **Threat Action**: embed hidden instructions in non-text modalities (images, audio)
- **Threat Impact**: bypassing text-based security controls
- **Priority**: High
- **Category**: AI/ML Security

---

#### T003 - Data Breach

**Threat Statement**: A malicious internal actor who has access to production logs can read sensitive customer information contained in chatbot conversation logs, which leads to unauthorized exposure of personal customer details, resulting in reduced confidentiality of impacted individuals and sensitive data

- **Threat Source**: malicious internal actor
- **Threat Action**: read sensitive customer information contained in chatbot conversation logs
- **Threat Impact**: unauthorized exposure of personal customer details
- **Priority**: High
- **Category**: Data Breach

---

#### T004 - Insider Threat

**Threat Statement**: An internal or external actor with access to the knowledge base or its source documents can corrupt or manipulate the RAG knowledge base (e.g. Amazon OpenSearch Serverless, Internet lookup), which leads to AI system providing incorrect or malicious information, resulting in reduced integrity and/or trustworthiness of AI system's knowledge base and outputs.

- **Threat Source**: internal or external actor
- **Threat Action**: corrupt or manipulate the RAG knowledge base (e.g. Amazon OpenSearch Serverless, Internet lookup)
- **Threat Impact**: AI system providing incorrect or malicious information
- **Priority**: High
- **Category**: Insider Threat

---

#### T005 - Data Breach

**Threat Statement**: An external threat actor who uses carefully crafted queries to call inference model APIs can retrieve sensitive information that they were not intended to access, which leads to to exfiltration of proprietary knowledge, resulting in reduced confidentiality of intellectual property

- **Threat Source**: external threat actor
- **Threat Action**: retrieve sensitive information that they were not intended to access
- **Threat Impact**: to exfiltration of proprietary knowledge
- **Priority**: High
- **Category**: Data Breach

---

#### T006 - Data Breach

**Threat Statement**: A malicious internal actor with access to model artifact repositories (for example, fine tuning data, model stores) can exfiltrate proprietary LLM data, which leads to competitive misuse or training of shadow models, resulting in reduced confidentiality and/or integrity of intellectual property

- **Threat Source**: malicious internal actor
- **Threat Action**: exfiltrate proprietary LLM data
- **Threat Impact**: competitive misuse or training of shadow models
- **Priority**: High
- **Category**: Data Breach

---

#### T007 - Data Breach

**Threat Statement**: An external threat actor who can infiltrate insecure environments can exfiltrate proprietary LLM models and artifacts, which leads to unauthorized competitive use, resulting in reduced confidentiality of intellectual property

- **Threat Source**: external threat actor
- **Threat Action**: exfiltrate proprietary LLM models and artifacts
- **Threat Impact**: unauthorized competitive use
- **Priority**: High
- **Category**: Data Breach

---

#### T008 - AI/ML Security

**Threat Statement**: A legitimate user who is over reliant on LLM recommendation can accept biased, unethical, or incorrect guidance and advice, which leads to discriminatory outcomes, reputational damage, financial loss, legal issues or cyber risks, resulting in reduced integrity and/or confidentiality of LLM system and connected resources

- **Threat Source**: legitimate user
- **Threat Action**: accept biased, unethical, or incorrect guidance and advice
- **Threat Impact**: discriminatory outcomes, reputational damage, financial loss, legal issues or cyber risks
- **Priority**: High
- **Category**: AI/ML Security

---

#### T009 - Availability

**Threat Statement**: An external or internal threat actor who has access to an LLM system with excessive functional capabilities can abuse those capabilities when operating under ambiguous instructions, which leads to unauthorized operations, resulting in reduced integrity and/or availability of connected and downstream systems and data

- **Threat Source**: external or internal threat actor
- **Threat Action**: abuse those capabilities when operating under ambiguous instructions
- **Threat Impact**: unauthorized operations
- **Priority**: High
- **Category**: Availability

---

#### T010 - AI/ML Security

**Threat Statement**: A malicious actor who controls an automated system with direct access to unconstrained LLM outputs can execute impactful actions or make critical decisions based on potentially incorrect, biased, or manipulated data, which leads to automated propagation of errors or biases, resulting in reduced integrity and/or reliability of business systems and workflows

- **Threat Source**: malicious actor
- **Threat Action**: execute impactful actions or make critical decisions based on potentially incorrect, biased, or manipulated data
- **Threat Impact**: automated propagation of errors or biases
- **Priority**: High
- **Category**: AI/ML Security

---

#### T011 - Availability

**Threat Statement**: An external or internal threat actor who has access to LLM agents granted permissions to access external systems can abuse those permissions, which leads to damage connected systems when operating under ambiguous instructions or in multi-agent collaborative environments, resulting in reduced integrity and/or availability of connected and downstream systems and data

- **Threat Source**: external or internal threat actor
- **Threat Action**: abuse those permissions
- **Threat Impact**: damage connected systems when operating under ambiguous instructions or in multi-agent collaborative environments
- **Priority**: High
- **Category**: Availability

---

#### T012 - Insider Threat

**Threat Statement**: A malicious internal actor who trains an LLM on confidential data without proper safeguards can expose that data, which leads to unfiltered model outputs or model inversion attacks, resulting in reduced confidentiality of sensitive user and training data

- **Threat Source**: malicious internal actor
- **Threat Action**: expose that data
- **Threat Impact**: unfiltered model outputs  or model inversion attacks
- **Priority**: High
- **Category**: Insider Threat

---

#### T013 - AI/ML Security

**Threat Statement**: An untrusted data supplier with questionable integrity can provide manipulated, biased, or malicious training data, which leads to degraded model performance and compromised training, resulting in reduced integrity and/or robustness of the LLM model

- **Threat Source**: untrusted data supplier
- **Threat Action**: provide manipulated, biased, or malicious training data
- **Threat Impact**: degraded model performance and compromised training
- **Priority**: High
- **Category**: AI/ML Security

---

#### T014 - Injection Attack

**Threat Statement**: A malicious internal actor with access to manage training or fine tuning pipelines can inject malicious tools or processes, which leads to tampering with training data, resulting in reduced integrity of the LLM model

- **Threat Source**: malicious internal actor
- **Threat Action**: inject malicious tools or processes
- **Threat Impact**: tampering with training data
- **Priority**: High
- **Category**: Injection Attack

---

#### T015 - Malware

**Threat Statement**: A malicious internal actor with access to upload training or fine tuning data can intentionally introduce manipulated, biased or malicious data, which leads to model poisoning or backdoors, resulting in reduced integrity and/or effectiveness of the LLM model

- **Threat Source**: malicious internal actor
- **Threat Action**: intentionally introduce manipulated, biased or malicious data
- **Threat Impact**: model poisoning or backdoors
- **Priority**: High
- **Category**: Malware

---

#### T016 - Injection Attack

**Threat Statement**: An external threat actor who enables compromised LLM plugins or agents in an LLM system can manipulate it via indirect or direct prompt injection, which leads to access unauthorized functionality or data, resulting in reduced confidentiality and/or integrity of connected and downstream systems and data

- **Threat Source**: external threat actor
- **Threat Action**: manipulate it via indirect or direct prompt injection
- **Threat Impact**: access unauthorized functionality or data
- **Priority**: High
- **Category**: Injection Attack

---

#### T017 - Availability

**Threat Statement**: An external threat actor with ability to interact with an LLM system can overwrite the system prompt with crafted prompts, including through adversarial suffixes and obfuscated text, which leads to force unintended actions from the LLM, resulting in reduced integrity and/or availability of LLM system and connected resources

- **Threat Source**: external threat actor
- **Threat Action**: overwrite the system prompt with crafted prompts, including through adversarial suffixes and obfuscated text
- **Threat Impact**: force unintended actions from the LLM
- **Priority**: High
- **Category**: Availability

---

### Medium Priority Threats

#### T018 - Data Breach

**Threat Statement**: An external threat actor with access to a multi-tenant vector database can exploit insufficient tenant isolation, which leads to cross-tenant data leakage during embedding similarity searches, resulting in reduced confidentiality of proprietary information

- **Threat Source**: external threat actor
- **Threat Action**: exploit insufficient tenant isolation
- **Threat Impact**: cross-tenant data leakage during embedding similarity searches
- **Priority**: Medium
- **Category**: Data Breach

---

#### T019 - Security Threat

**Threat Statement**: An external threat actor who has access to vector embeddings can perform inversion attacks, which leads to extracting sensitive source information from the embedding space, resulting in reduced confidentiality of information in the knowledge base

- **Threat Source**: external threat actor
- **Threat Action**: perform inversion attacks
- **Threat Impact**: extracting sensitive source information from the embedding space
- **Priority**: Medium
- **Category**: Security Threat

---

#### T020 - AI/ML Security

**Threat Statement**: An egitimate user who is overly dependent on LLM outputs can make unsupported decisions based on incorrect data or recommendations, which leads to leads to propagation of erroneous information, resulting in reduced integrity of connected and downstream systems and data

- **Threat Source**: egitimate user
- **Threat Action**: make unsupported decisions based on incorrect data or recommendations
- **Threat Impact**: leads to propagation of erroneous information
- **Priority**: Medium
- **Category**: AI/ML Security

---

#### T021 - Authorization

**Threat Statement**: An external threat actor with access to an overprivileged LLM plugins/tools can abuse those permissions to access unauthorized resources or functionality, which leads to privilege escalation, resulting in reduced confidentiality, integrity and/or availability of connected and downstream systems and data

- **Threat Source**: external threat actor
- **Threat Action**: abuse those permissions to access unauthorized resources or functionality
- **Threat Impact**: privilege escalation
- **Priority**: Medium
- **Category**: Authorization

---

#### T022 - Authorization

**Threat Statement**: A malicious internal actor who is using insecure coding practices can introduce vulnerabilities through unsafe plugin code execution, input validation, access controls, which leads to security control bypasses, resulting in reduced confidentiality, integrity and/or availability of connected and downstream systems and data

- **Threat Source**: malicious internal actor
- **Threat Action**: introduce vulnerabilities through unsafe plugin code execution, input validation, access controls
- **Threat Impact**: security control bypasses
- **Priority**: Medium
- **Category**: Authorization

---

#### T023 - Availability

**Threat Statement**: An external threat actor permitted to enable third-party LLM plugins can exploit plugin vulnerabilities, which leads to remote code execution, resulting in reduced confidentiality, integrity and/or availability of connected and downstream systems and data

- **Threat Source**: external threat actor
- **Threat Action**: exploit plugin vulnerabilities
- **Threat Impact**: remote code execution
- **Priority**: Medium
- **Category**: Availability

---

#### T024 - Insider Threat

**Threat Statement**: A malicious internal actor who trains or fine-tunes an LLM model on sparse or sensitive data without proper regularization techniques can overfit the model, which leads to the LLM memorizing and potentially exposing confidential information through various attack vectors (e.g., membership inference, data reconstruction), resulting in reduced confidentiality of sensitive user and training data and reduced robustness of the LLM model.

- **Threat Source**: malicious internal actor
- **Threat Action**: overfit the model
- **Threat Impact**: the LLM memorizing and potentially exposing confidential information through various attack vectors (e.g., membership inference, data reconstruction)
- **Priority**: Medium
- **Category**: Insider Threat

---

#### T025 - Insider Threat

**Threat Statement**: A malicious internal actor who applies insufficient data anonymization to an LLM training or fine tuning dataset can allow sensitive data to remain identifiable, which leads to exposing it via model outputs, resulting in reduced confidentiality of impacted individuals and sensitive data

- **Threat Source**: malicious internal actor
- **Threat Action**: allow sensitive data to remain identifiable
- **Threat Impact**: exposing it via model outputs
- **Priority**: Medium
- **Category**: Insider Threat

---

#### T026 - Availability

**Threat Statement**: An external or internal threat actor who has access to an LLM powered application using a deprecated third-party LLM inference API can introduce vulnerabilities, which leads to successful exploitation of security weaknesses, resulting in reduced integrity and/or availability of connected and downstream systems and data

- **Threat Source**: external or internal threat actor
- **Threat Action**: introduce vulnerabilities
- **Threat Impact**: successful exploitation of security weaknesses
- **Priority**: Medium
- **Category**: Availability

---

#### T027 - Availability

**Threat Statement**: An external or internal threat actor who has access to an LLM powered application using compromised upstream open source dependencies can enable exploits through vulnerabilities, which leads to unauthorized system access, resulting in reduced confidentiality, integrity and/or availability of LLM system and connected resources

- **Threat Source**: external or internal threat actor
- **Threat Action**: enable exploits through vulnerabilities
- **Threat Impact**: unauthorized system access
- **Priority**: Medium
- **Category**: Availability

---

#### T028 - Availability

**Threat Statement**: An external threat actor who is able to access an LLM API can submit expensive requests in a denial-of-wallet attack pattern, which leads to high hosting costs, resulting in reduced availability and/or financial losses of the LLM service provider

- **Threat Source**: external threat actor
- **Threat Action**: submit expensive requests in a denial-of-wallet attack pattern
- **Threat Impact**: high hosting costs
- **Priority**: Medium
- **Category**: Availability

---

#### T029 - Availability

**Threat Statement**: An external threat actor with access to submit LLM requests can abuse request batching systems, which leads to overwhelming resources with queued jobs, resulting in reduced availability of the LLM inference API

- **Threat Source**: external threat actor
- **Threat Action**: abuse request batching systems
- **Threat Impact**: overwhelming resources with queued jobs
- **Priority**: Medium
- **Category**: Availability

---

#### T030 - Availability

**Threat Statement**: An external threat actor able to submit requests to an LLM API can overwhelm it with expensive computing operations, which leads to denying service to legitimate users, resulting in reduced availability of the LLM inference API

- **Threat Source**: external threat actor
- **Threat Action**: overwhelm it with expensive computing operations
- **Threat Impact**: denying service to legitimate users
- **Priority**: Medium
- **Category**: Availability

---

#### T031 - AI/ML Security

**Threat Statement**: An external threat actor with ability to manipulate LLM outputs can craft payloads that exploit downstream function vulnerabilities, which leads to execution of unauthorized code, resulting in reduced integrity and/or confidentiality of connected and downstream systems and data

- **Threat Source**: external threat actor
- **Threat Action**: craft payloads that exploit downstream function vulnerabilities
- **Threat Impact**: execution of unauthorized code
- **Priority**: Medium
- **Category**: AI/ML Security

---

#### T032 - Injection Attack

**Threat Statement**: An external threat actor who has access to an LLM with insufficient safeguards against harmful content generation can craft prompts that generate malicious outputs, which leads to exploiting vulnerabilities like command injections in integrated downstream functions when malicious outputs are passed to them, resulting in reduced confidentiality, integrity and/or availability of LLM system and connected resources

- **Threat Source**: external threat actor
- **Threat Action**: craft prompts that generate malicious outputs
- **Threat Impact**: exploiting vulnerabilities like command injections in integrated downstream functions when malicious outputs are passed to them
- **Priority**: Medium
- **Category**: Injection Attack

---

#### T033 - Injection Attack

**Threat Statement**: An external threat actor able to interact with an LLM system can exploit insufficient output encoding, which leads to achieve XSS or code injection, resulting in reduced confidentiality and/or integrity of user data

- **Threat Source**: external threat actor
- **Threat Action**: exploit insufficient output encoding
- **Threat Impact**: achieve XSS or code injection
- **Priority**: Medium
- **Category**: Injection Attack

---

#### T034 - Injection Attack

**Threat Statement**: An external threat actor able to submit content to an LLM system can can embed malicious prompts in that content, including via indirect prompt injection and multi-stage attacks, which leads to manipulation of the LLM into undertaking harmful actions, resulting in reduced integrity and/or availability of LLM system and connected resources

- **Threat Source**: external threat actor
- **Threat Action**: can embed malicious prompts in that content, including via indirect prompt injection and multi-stage attacks
- **Threat Impact**: manipulation of the LLM into undertaking harmful actions
- **Priority**: Medium
- **Category**: Injection Attack

---

### Low Priority Threats

#### T035 - AI/ML Security

**Threat Statement**: An external threat actor can issue strategic queries to an LLM API can harvest sufficient responses, which leads to replicating model functionality through distillation, resulting in reduced confidentiality of proprietary LLM algorithms and training data

- **Threat Source**: external threat actor
- **Threat Action**: harvest sufficient responses
- **Threat Impact**: replicating model functionality through distillation
- **Priority**: Low
- **Category**: AI/ML Security

---

#### T036 - Injection Attack

**Threat Statement**: An external threat actor who has access to collaborative model development processes can inject malicious code during model merging or conversion, which leads to distribution of compromised models through legitimate channels, resulting in reduced integrity of downstream applications

- **Threat Source**: external threat actor
- **Threat Action**: inject malicious code during model merging or conversion
- **Threat Impact**: distribution of compromised models through legitimate channels
- **Priority**: Low
- **Category**: Injection Attack

---

#### T037 - Malware

**Threat Statement**: An external threat actor who can contribute to model development pipelines can compromise a LoRA adapter, which leads to introducing backdoors or harmful behaviors when the adapter is integrated, resulting in reduced integrity of model responses

- **Threat Source**: external threat actor
- **Threat Action**: compromise a LoRA adapter
- **Threat Impact**: introducing backdoors or harmful behaviors when the adapter is integrated
- **Priority**: Low
- **Category**: Malware

---

