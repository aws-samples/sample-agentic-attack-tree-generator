# Sample GenAI Chatbot
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


## Architecture
This document outlines a sample reference architecture for an AI-powered assistant designed to provide rapid, accurate responses to queries about internal data. By leveraging AWS services, particularly Amazon Bedrock, this reference architecture demonstrates a secure, efficient, and intelligent solution for accessing organizational knowledge.
Key Benefits
Accelerated Insights: The system generates instant answers from internal documents using Amazon Bedrock models.
Convenient Knowledge Access: Users access information across various internal sources through a centralized interface.
Improved Productivity: The architecture significantly reduces time spent on manual document searches.
Natural Interactions: Amazon Bedrock powers a conversational interface for an intuitive user experience.
Historical Lookup: A centralized dashboard enables review of past queries and answers.
Enhanced Security and Compliance: The architecture implements responsible AI practices and robust data protection.
Architecture Components
1. Data Preparation Pipeline
Amazon S3: Stores the knowledge base data.
Amazon S3 Event Trigger: Initiates processing for new or updated objects.
AWS Lambda: Parses data, converts to embeddings, and loads into vector database.
Amazon Bedrock (Titan Embedding Model): Generates embeddings for efficient data retrieval. This model is crucial for Retrieval-Augmented Generation (RAG), enabling the system to efficiently search and retrieve relevant information from the knowledge base.
2. Application Stack
Frontend and Request Handling
Amazon Cognito: Manages user authentication.
AWS WAF: Provides web application firewall protection.
Application Load Balancer: Routes requests in the public subnet.
Amazon ECS with Fargate: Hosts the NextJS Web Application (Docker).
AWS Lambda Web Adapter (Python): Handles serverless processing.
Backend Services
Amazon OpenSearch Serverless: Serves as the vector database for efficient document search.
Amazon Bedrock Guardrail: Performs responsible AI checks and PII redaction.
Amazon Bedrock (Anthropic Claude Model): Powers natural language understanding and response generation.
Amazon DynamoDB: Stores chat history for future reference.
Networking and Security
Amazon VPC: Enhances overall system security through proper network design.
VPC Service Endpoints: Connect the application securely to Bedrock, OpenSearch, and DynamoDB within the VPC.
Workflow
Users submit queries through the web application.
The system authenticates requests using Amazon Cognito and routes them through AWS WAF and the Application Load Balancer.
The NextJS Web Application in ECS processes the request, utilizing the AWS Lambda Web Adapter for serverless capabilities.
The architecture searches the OpenSearch Serverless vector database for relevant information.
Amazon Bedrock Guardrail applies responsible AI checks and PII redaction.
The Anthropic Claude Model in Amazon Bedrock generates a natural language response.
The system returns the answer to the user through the application stack and logs the interaction in DynamoDB.
Key Features
Implementation of Amazon Bedrock Guardrail for PII redaction and responsible AI enforcement.
Utilization of a serverless architecture with ECS Fargate and Lambda for scalability and performance.
Integration of security measures through VPC design and AWS WAF.
Application of advanced AI models, including the Titan Embedding Model for RAG and the Anthropic Claude Model for natural language processing.
Disclaimer: This document describes a sample reference architecture. Actual implementation may require adjustments based on specific organizational needs, security requirements, and compliance standards.

## Dataflow
The data flows provide an in-depth look at how RAG chatbots operate. They outline the key processes and interactions that bring natural conversations to life. In below example, sample AWS services are used, you may or maybe not be using these services.

#### Entities:

| Entity                   | Description                                     |
| ------------------------ | ----------------------------------------------- |
| User                     | The individual who interacts with the system    |
| Web App                  | The frontend interface for input and output     |
| Amazon Cognito           | Handles user authentication                     |
| API Gateway              | Orchestrates API requests and responses         |
| Lambda                   | Serverless functions interacting with services  |
| Amazon Bedrock Guardrail | Performs responsible AI check and PII redaction |
| OpenSearch Serverless    | Retrieves relevant documents                    |
| Amazon Bedrock           | Generates responses to queries                  |
| DynamoDB                 | Stores question-answer pairs                    |

#### Data flows definition:

| Flow Identifier | Flow Description                       | Source Entity  | Target Entity            | Assets                                                                                   |
| --------------- | -------------------------------------- | -------------- | ------------------------ | ---------------------------------------------------------------------------------------- |
| DF1             | User asks a question                   | User           | Web App                  | User supplied prompt                                                                     |
| DF2             | Query is authenticated                 | Web App        | Amazon Cognito           | Credentials + Authentication tokens                                                      |
| DF3             | API request handled                    | Web App        | API Gateway              | User supplied prompt, Authentication tokens                                              |
| DF4             | Lambda function triggered              | API Gateway    | Lambda                   | User supplied prompt, LLM response                                                       |
| DF5             | Responsible AI check and PII redaction | Lambda         | Amazon Bedrock Guardrail | Unredacted user supplied prompt, Redacted prompts, Intellectual property, Sensitive data |
| DF6             | Relevant documents retrieved           | Lambda         | OpenSearch Serverless    | Intellectual property, Sensitive data                                                    |
| DF7             | Response generated                     | Lambda         | Amazon Bedrock           | User supplied prompt, LLM response                                                       |
| DF8             | Generated response returned            | Amazon Bedrock | Lambda                   | LLM response                                                                             |
| DF9             | Q and A stored                         | Lambda         | DynamoDB                 | User supplied prompt, LLM responses, Audit log                                           |

#### Trust boundaries:

| Boundary Identifier | Purpose                                                         | Source Entity | Target Entity            |
| ------------------- | --------------------------------------------------------------- | ------------- | ------------------------ |
| TB1                 | Validates input, ensures privacy                                | User          | Web App                  |
| TB2                 | Allows authorized backend access                                | Web App       | Amazon Cognito           |
| TB3                 | Triggers Lambda securely                                        | API Gateway   | Lambda                   |
| TB4                 | Enables responsible AI check and PII redaction without exposure | Lambda        | Amazon Bedrock Guardrail |
| TB5                 | Allows secure document retrieval                                | Lambda        | OpenSearch Serverless    |
| TB6                 | Provides secure inference endpoint                              | Lambda        | Amazon Bedrock           |

#### Possible threat sources:

The table below categorizes the various threat sources mentioned across the threat statements in the next section:

| Category                    | Description                                    | Examples                                                                                         |
| --------------------------- | ---------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| Legitimate Users            | Valid users who unintentionally trigger issues | An internal actor, An end user                                                                   |
| Malicious Internal Actors   | Trusted insiders who intentionally cause harm  | An overprivileged LLM plugin, An internal plugin or agent developer, An LLM developer or trainer |
| External Threat Actors      | External attackers targeting the system        | A threat actor, An external threat actor - A malicious user (with system access)                 |
| Untrusted Data Suppliers    | External data sources that provide bad data    | A third-party data supplier, A data supplier                                                     |
| Unauthorized External Users | External entities with no system access        | A malicious user (no system access)                                                              |


## Assumptions

1. The LLM training data does not contain sensitive personal information
2. Access to training or knowledge pipelines is restricted using authentication and authorization controls
3. The LLM system has limited network connectivity and access controls
4. End users are trained on properly interacting with the LLM system
5. The LLM application undergoes security testing and audit
6. Current prompt injection defenses represent best efforts but cannot guarantee complete protection against sophisticated attacks
7. Multimodal LLMs introduce additional attack surfaces that may not be fully understood or mitigated
8. Even with data sanitization processes, models may still memorize and potentially leak sensitive information
9. Third-party model and component security posture cannot be completely verified
10. Systems with excessive agency and autonomy may develop unexpected behaviors that aren't caught during testing
11. System prompt leakage countermeasures are protective but not guaranteed
12. Vector and embedding security are evolving fields with incomplete best practices
13. LLMs may still produce hallucinations or incorrect outputs despite content filtering and RAG implementation


## Threats

# LLM Security Threats

## Threat 1 - LLM01 Prompt Injection
An external threat actor with ability to interact with an LLM system can overwrite the system prompt with crafted prompts, including through adversarial suffixes and obfuscated text, which leads to force unintended actions from the LLM, resulting in reduced integrity and/or availability of LLM system and connected resources

## Threat 2 - LLM01 Prompt Injection
An external threat actor able to submit content to an LLM system can can embed malicious prompts in that content, including via indirect prompt injection and multi-stage attacks, which leads to manipulation of the LLM into undertaking harmful actions, resulting in reduced integrity and/or availability of LLM system and connected resources

## Threat 3 - LLM01 Prompt Injection / LLM06 Excessive Agency
An external threat actor who enables compromised LLM plugins or agents in an LLM system can manipulate it via indirect or direct prompt injection, which leads to access unauthorized functionality or data, resulting in reduced confidentiality and/or integrity of connected and downstream systems and data

## Threat 4 - LLM05 Improper Output Handling
An external threat actor able to interact with an LLM system can exploit insufficient output encoding, which leads to achieve XSS or code injection, resulting in reduced confidentiality and/or integrity of user data

## Threat 5 - LLM05 Improper Output Handling
An external threat actor who has access to an LLM with insufficient safeguards against harmful content generation can craft prompts that generate malicious outputs, which leads to exploiting vulnerabilities like command injections in integrated downstream functions when malicious outputs are passed to them, resulting in reduced confidentiality, integrity and/or availability of LLM system and connected resources

## Threat 6 - LLM05 Improper Output Handling
An external threat actor with ability to manipulate LLM outputs can craft payloads that exploit downstream function vulnerabilities, which leads to execution of unauthorized code, resulting in reduced integrity and/or confidentiality of connected and downstream systems and data

## Threat 7 - LLM04 Data/Model Poisoning
A malicious internal actor with access to upload training or fine tuning data can intentionally introduce manipulated, biased or malicious data, which leads to model poisoning or backdoors, resulting in reduced integrity and/or effectiveness of the LLM model

## Threat 9 - LLM04 Data/Model Poisoning
A malicious internal actor with access to manage training or fine tuning pipelines can inject malicious tools or processes, which leads to tampering with training data, resulting in reduced integrity of the LLM model

## Threat 10 - LLM10 Unbounded Consumption
An external threat actor able to submit requests to an LLM API can overwhelm it with expensive computing operations, which leads to denying service to legitimate users, resulting in reduced availability of the LLM inference API

## Threat 11 - LLM10 Unbounded Consumption
An external threat actor with access to submit LLM requests can abuse request batching systems, which leads to overwhelming resources with queued jobs, resulting in reduced availability of the LLM inference API

## Threat 12 - LLM10 Unbounded Consumption
An external threat actor who is able to access an LLM API can submit expensive requests in a denial-of-wallet attack pattern, which leads to high hosting costs, resulting in reduced availability and/or financial losses of the LLM service provider

## Threat 13 - LLM03 Supply Chain
An external or internal threat actor who has access to an LLM powered application using compromised upstream open source dependencies can enable exploits through vulnerabilities, which leads to unauthorized system access, resulting in reduced confidentiality, integrity and/or availability of LLM system and connected resources

## Threat 14 - LLM04 Data/Model Poisoning
An untrusted data supplier with questionable integrity can provide manipulated, biased, or malicious training data, which leads to degraded model performance and compromised training, resulting in reduced integrity and/or robustness of the LLM model

## Threat 15 - LLM03 Supply Chain
An external or internal threat actor who has access to an LLM powered application using a deprecated third-party LLM inference API can introduce vulnerabilities, which leads to successful exploitation of security weaknesses, resulting in reduced integrity and/or availability of connected and downstream systems and data

## Threat 16 - LLM02 SensitiveInfo Disclosure
A malicious internal actor who trains an LLM on confidential data without proper safeguards can expose that data, which leads to unfiltered model outputs or model inversion attacks, resulting in reduced confidentiality of sensitive user and training data

## Threat 17 - LLM02 SensitiveInfo Disclosure
A malicious internal actor who applies insufficient data anonymization to an LLM training or fine tuning dataset can allow sensitive data to remain identifiable, which leads to exposing it via model outputs, resulting in reduced confidentiality of impacted individuals and sensitive data

## Threat 18 - LLM02 SensitiveInfo Disclosure
A malicious internal actor who trains or fine-tunes an LLM model on sparse or sensitive data without proper regularization techniques can overfit the model, which leads to the LLM memorizing and potentially exposing confidential information through various attack vectors (e.g., membership inference, data reconstruction), resulting in reduced confidentiality of sensitive user and training data and reduced robustness of the LLM model

## Threat 19 - LLM06 Excessive Agency
An external threat actor permitted to enable third-party LLM plugins can exploit plugin vulnerabilities, which leads to remote code execution, resulting in reduced confidentiality, integrity and/or availability of connected and downstream systems and data

## Threat 20 - LLM06 Excessive Agency
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
An egitimate user who is overly dependent on LLM outputs can make unsupported decisions based on incorrect data or recommendations, which leads to leads to propagation of erroneous information, resulting in reduced integrity of connected and downstream systems and data

## Threat 28 - LLM03 Supply Chain / LLM10 Unbounded Consumption
An external threat actor who can infiltrate insecure environments can exfiltrate proprietary LLM models and artifacts, which leads to unauthorized competitive use, resulting in reduced confidentiality of intellectual property

## Threat 29 - LLM03 Supply Chain / LLM02 SensitiveInfo Disclosure
A malicious internal actor with access to model artifact repositories (for example, fine tuning data, model stores) can exfiltrate proprietary LLM data, which leads to competitive misuse or training of shadow models, resulting in reduced confidentiality and/or integrity of intellectual property

## Threat 30 - LLM02 SensitiveInfo Disclosure
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
