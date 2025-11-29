# Frequently Asked Questions (FAQ)

Get answers to common questions about ThreatForest, threat modeling, and attack tree generation.

---

## General Questions

### What is ThreatForest?

ThreatForest is an AI-driven threat modeling platform that automates the process of analyzing applications for security threats, generating attack trees, and mapping them to MITRE ATT&CK techniques. It uses autonomous AI agents powered by AWS Labs' Strands framework to explore your project, understand its architecture, and identify potential security vulnerabilities.

### What is an attack tree?

An **attack tree** is a hierarchical diagram that represents the various ways a system can be attacked. It starts with a root goal (the threat or security objective an attacker wants to achieve) and branches out into multiple attack paths showing the steps an attacker might take to reach that goal.

Each attack tree includes:

- **Root Node**: The high-level threat or attack goal (e.g., "Unauthorized access to customer data")
- **Attack Paths**: Different routes an attacker could take to achieve the goal
- **Attack Steps**: Specific actions within each path (e.g., "1. Reconnaissance", "2. Initial Access", "3. Privilege Escalation")
- **MITRE ATT&CK Mapping**: Links to known tactics and techniques (e.g., T1190: Exploit Public-Facing Application)
- **Mitigations**: Defensive measures to prevent or detect each attack step

**Example visualization:**
```
Root: SQL Injection Attack
├── Path 1: Direct Database Access
│   ├── Step 1: Identify input fields
│   ├── Step 2: Test for SQL injection
│   └── Step 3: Extract sensitive data
└── Path 2: Bypass Authentication
    ├── Step 1: Find login endpoint
    ├── Step 2: Craft malicious payload
    └── Step 3: Gain admin access
```

Attack trees help security teams:
- Visualize all possible attack scenarios
- Prioritize security controls
- Communicate risks to stakeholders
- Identify gaps in defenses
- Plan security testing strategies

### Who should use ThreatForest?

ThreatForest is designed for:

- **Security Teams**: Automating threat modeling for applications and systems
- **DevSecOps Engineers**: Integrating security analysis into CI/CD pipelines
- **Software Architects**: Understanding security implications of design decisions
- **Compliance Officers**: Documenting threat landscapes for regulatory requirements
- **Security Researchers**: Analyzing attack patterns and vulnerabilities

### Is ThreatForest free?

Yes, ThreatForest is an open-source project released under the MIT License. However, you'll need access to an LLM provider:

- **AWS Bedrock**: Requires an AWS account with Bedrock access
- **Anthropic/OpenAI/Gemini**: Requires API keys (paid services)
- **Ollama**: Free for local use (no API costs)

---

## Getting Started

### What are the prerequisites?

To use ThreatForest, you need:

- **Python 3.11+**: Modern Python runtime
- **LLM Provider Access**: One of:
  - AWS account with Bedrock access
  - Anthropic/OpenAI/Gemini API keys
  - Local Ollama installation
- **Project to Analyze**: Your application code, architecture docs, or threat model files

### How do I install ThreatForest?

The recommended installation method is using `pipx`:

```bash
pipx install threatforest
```

Or with `uv` for faster installation:

```bash
uv tool install threatforest
```

See the [Getting Started Guide](getting-started/index.md) for detailed instructions.

### Can I try ThreatForest without AWS?

Yes! ThreatForest supports multiple LLM providers:

- **Ollama**: Completely local, no cloud services required
- **Anthropic Claude**: Direct API access
- **OpenAI GPT**: Direct API access
- **Google Gemini**: Direct API access

Configure your preferred provider in the interactive wizard or `config.yaml`.

---

## Features & Functionality

### What file formats does ThreatForest support?

ThreatForest can parse threats from:

- **ThreatComposer**: `.tc.json` workspace files
- **JSON**: Structured threat definitions
- **YAML**: Human-readable threat configurations
- **Markdown**: Documentation with threat descriptions

If no threats exist, ThreatForest can generate them by analyzing your project files.

### Can ThreatForest analyze my existing threat model?

Yes! ThreatForest can:

- Import threats from ThreatComposer workspaces
- Parse existing threat documentation
- Enrich threats with MITRE ATT&CK mappings
- Generate attack trees for identified threats
- Add mitigation recommendations

### What is MITRE ATT&CK mapping?

MITRE ATT&CK is a globally recognized framework of adversary tactics and techniques. ThreatForest automatically maps each attack step to relevant MITRE ATT&CK techniques using:

- **Semantic Similarity**: AI-powered matching of attack descriptions to techniques
- **Vector Embeddings**: Understanding context and meaning beyond keywords
- **Confidence Scoring**: Multi-factor assessment of mapping accuracy

This helps you:
- Understand attacks in standardized terminology
- Compare threats across different systems
- Plan defenses using industry best practices
- Meet compliance requirements

### How accurate is the AI-generated content?

ThreatForest uses state-of-the-art LLMs (Claude 3 Sonnet, GPT-4, etc.) which are highly capable but not perfect. We recommend:

- **Review All Output**: Treat AI-generated content as a starting point
- **Validate Threats**: Ensure threats are relevant to your specific context
- **Verify Mappings**: Check MITRE ATT&CK mappings for accuracy
- **Customize Mitigations**: Adapt recommendations to your environment

The quality depends on:
- LLM model selection (Claude 3 Sonnet generally performs best)
- Quality of project documentation
- Completeness of threat descriptions

---

## Privacy & Security

### Is my code sent to the LLM provider?

Yes, ThreatForest sends relevant project context to your chosen LLM provider for analysis. This may include:

- Architecture diagrams and documentation
- Code snippets relevant to security
- Threat descriptions and configurations

**Privacy Options:**

- ✅ **Local Models (Ollama)**: Complete privacy, all processing on your machine
- ✅ **AWS Bedrock**: Enterprise data handling with AWS policies
- ✅ **Read Provider Policies**: Review data handling for Anthropic, OpenAI, Gemini

**Best Practices:**

- Use Ollama for sensitive projects
- Remove secrets before analysis
- Review provider data retention policies
- Consider on-premises deployment for highly sensitive systems

### How do I protect sensitive information?

1. **Use Local Models**: Run Ollama for complete data privacy
2. **Sanitize Input**: Remove secrets, credentials, PII before analysis
3. **Review Output**: Check generated files for leaked information
4. **Access Controls**: Restrict who can view threat models and attack trees
5. **Secure Storage**: Store outputs in protected directories with appropriate permissions

### Can I use ThreatForest in an air-gapped environment?

With Ollama, yes! Set up:

1. Install Ollama on an air-gapped machine
2. Download required models (qwen2.5 recommended)
3. Configure ThreatForest to use local Ollama endpoint
4. Run completely offline

See [Multi-Provider Setup](advanced/multi-provider.md) for details.

---

## Troubleshooting

### Why is ThreatForest slow?

Performance depends on several factors:

- **LLM Provider**: Bedrock/Claude typically fastest; Ollama slower on CPU
- **Model Size**: Larger models (70B+) take longer than smaller ones (7B-14B)
- **Project Complexity**: More threats = longer processing time
- **Hardware**: Local models require sufficient CPU/GPU resources

**Speed Optimization:**

- Use AWS Bedrock or Anthropic for fastest processing
- Select smaller models for quicker results
- Process threats incrementally
- Use the resume feature to avoid reprocessing

### ThreatForest fails with "API rate limit exceeded"

LLM providers have rate limits. Solutions:

- **Wait and Retry**: ThreatForest has built-in retry logic
- **Reduce Concurrency**: Process fewer threats simultaneously
- **Upgrade Plan**: Increase rate limits with your provider
- **Switch Providers**: Try a different LLM service

### The attack trees don't match my application

This can happen if:

- Project documentation is incomplete
- LLM lacks context about your tech stack
- Threat descriptions are too generic

**Improvements:**

- Add detailed architecture diagrams
- Include technology stack documentation
- Write specific, contextual threat descriptions
- Use the [Preparing Your Project](user-guide/preparing-your-project.md) guide

### Can I customize the output format?

Yes! ThreatForest generates:

- **Markdown Files**: Individual attack trees (easily customizable)
- **JSON Data**: Structured export for integration
- **HTML Dashboard**: Interactive visualization

You can:
- Modify markdown templates
- Parse JSON for custom reporting
- Extend visualization with custom HTML/CSS

See [Customization Guide](advanced/customization.md) for details.

---

## Integration & Advanced Usage

### Can I integrate ThreatForest into CI/CD?

ThreatForest is designed for interactive use via the wizard interface. For CI/CD integration, consider:

- Running the wizard in a containerized environment
- Using the JSON output for automated processing
- Reviewing generated attack trees as part of security gates

See [CI/CD Best Practices](advanced/customization.md) for integration patterns.

### Does ThreatForest support multiple languages?

The analysis is language-agnostic - ThreatForest works with any programming language because it analyzes:

- Architecture and design documents
- Threat descriptions (not code directly)
- Configuration files
- Data flow diagrams

LLM responses are in English, but threat descriptions can be in any language supported by the LLM.

### Can I contribute to ThreatForest?

Absolutely! ThreatForest is open source and welcomes contributions:

- **Bug Reports**: Submit issues on GitHub
- **Feature Requests**: Propose enhancements
- **Code Contributions**: Submit pull requests
- **Documentation**: Improve guides and examples

See the [Contributing Guide](contributing/index.md) to get started.

---

## Support

### Where can I get help?

- 📖 **Documentation**: Browse this site for comprehensive guides
- 🐛 **GitHub Issues**: Report bugs or request features
- 💬 **Discussions**: Ask questions in GitHub Discussions
- 🔍 **Examples**: Check [example projects](examples/index.md) for reference

### How do I report a security vulnerability?

Please report security issues responsibly:

1. **Do NOT** open a public GitHub issue
2. Email the maintainers directly (see [SECURITY.md](about/security.md))
3. Provide detailed information about the vulnerability
4. Allow time for assessment and patching

See [Security Policy](about/security.md) for full details.

### Is commercial support available?

ThreatForest is an open-source project. For enterprise support options, consulting, or custom development, contact the maintainers through the GitHub repository.

---

## Still Have Questions?

If you didn't find your answer here:

1. Browse [GitHub Discussions](https://github.com/aws-samples/sample-agentic-attack-tree-generator/discussions)
2. Review [example projects](examples/index.md)
3. Open a [GitHub Issue](https://github.com/aws-samples/sample-agentic-attack-tree-generator/issues)

We're here to help! 🌳
