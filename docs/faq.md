# Frequently Asked Questions (FAQ)

!!! tip "Quick Navigation"
    Use the tabs below to jump to specific topics, or scroll through all questions.

=== "General"
    - [What is ThreatForest?](#what-is-threatforest)
    - [What is an attack tree?](#what-is-an-attack-tree)
    - [Who should use ThreatForest?](#who-should-use-threatforest)
    - [Is ThreatForest free?](#is-threatforest-free)

=== "Getting Started"
    - [What are the prerequisites?](#what-are-the-prerequisites)
    - [How do I install?](#how-do-i-install-threatforest)
    - [Can I try without AWS?](#can-i-try-threatforest-without-aws)

=== "Features"
    - [What file formats?](#what-file-formats-does-threatforest-support)
    - [Analyze existing threats?](#can-threatforest-analyze-my-existing-threat-model)
    - [What is MITRE mapping?](#what-is-mitre-attck-mapping)
    - [How accurate is AI?](#how-accurate-is-the-ai-generated-content)

=== "Privacy"
    - [Is code sent to LLMs?](#is-my-code-sent-to-the-llm-provider)
    - [Protect sensitive info?](#how-do-i-protect-sensitive-information)
    - [Air-gapped use?](#can-i-use-threatforest-in-an-air-gapped-environment)

=== "Troubleshooting"
    - [Why slow?](#why-is-threatforest-slow)
    - [Rate limits?](#threatforest-fails-with-api-rate-limit-exceeded)
    - [Trees don't match?](#the-attack-trees-dont-match-my-application)

---

## General Questions

### What is ThreatForest?

!!! info "TL;DR"
    AI-powered threat modeling platform that generates attack trees mapped to MITRE ATT&CK using autonomous agents.

ThreatForest automates threat modeling by analyzing your project and generating comprehensive attack trees with MITRE ATT&CK mappings and mitigation strategies.

[→ Learn More](index.md)

### What is an attack tree?

!!! info "TL;DR"
    Hierarchical diagram showing all ways to attack a system, with step-by-step paths mapped to MITRE techniques.

An attack tree visualizes attack scenarios:

- **Root**: High-level threat (e.g., "Data breach")
- **Paths**: Different attack routes
- **Steps**: Specific actions per path
- **MITRE**: Technique IDs (e.g., T1190)
- **Mitigations**: Defensive controls

[→ See Examples](examples/index.md)

### Who should use ThreatForest?

ThreatForest is designed for security professionals, developers, and compliance teams:

- **Security Teams** - Automate threat modeling
- **DevSecOps** - Integrate into CI/CD
- **Architects** - Understand security implications
- **Compliance** - Document threat landscapes

### Is ThreatForest free?

Yes, open-source under MIT License. You need LLM provider access:

- **AWS Bedrock** - Requires AWS account
- **Anthropic/OpenAI** - Requires API keys (paid)
- **Ollama** - Free local use

---

## Getting Started

### What are the prerequisites?

!!! info "TL;DR"
    Python 3.11+, LLM provider access (AWS Bedrock recommended), project to analyze.

**Required:**

- Python 3.11 or higher
- LLM provider (AWS Bedrock, Anthropic, OpenAI, or Ollama)

**Recommended:**

- ThreatComposer file or documentation
- Architecture diagrams

[→ Installation Guide](getting-started/index.md)

### How do I install ThreatForest?

!!! info "TL;DR"
    `pipx install threatforest` then run `threatforest`

```bash
# Recommended: pipx
pipx install threatforest
threatforest

# Alternative: pip with venv
python3 -m venv venv
source venv/bin/activate
pip install threatforest
```

[→ Complete Installation](getting-started/index.md)

### Can I try ThreatForest without AWS?

Yes! ThreatForest supports multiple providers:

- **Ollama** - Completely local, no cloud
- **Anthropic** - Direct API access
- **OpenAI** - Direct API access
- **Google Gemini** - Direct API access

Configure in the wizard or `config.yaml`.

---

## Features & Functionality

### What file formats does ThreatForest support?

!!! info "TL;DR"
    ThreatComposer (.tc), JSON, YAML, Markdown for threats. PNG, PDF, Mermaid for diagrams.

**Threat Models:**

- ThreatComposer (`.tc`, `.tc.json`) ⭐ Recommended
- JSON, YAML, Markdown

**Diagrams:**

- PNG, JPG, PDF, Mermaid, Draw.io, PlantUML

**Documentation:**

- Markdown, PDF, text files

[→ Preparing Your Project](user-guide/preparing-your-project.md)

### Can ThreatForest analyze my existing threat model?

Yes! ThreatForest can:

- Import ThreatComposer workspaces
- Parse JSON/YAML/Markdown threats
- Enrich with MITRE ATT&CK mappings
- Generate attack trees
- Add mitigation recommendations

[→ Input Files Guide](user-guide/preparing-your-project.md#threat-models)

### What is MITRE ATT&CK mapping?

!!! info "TL;DR"
    Automatic mapping of attack steps to industry-standard MITRE techniques using AI-powered semantic matching.

MITRE ATT&CK is a framework of adversary tactics and techniques. ThreatForest maps each attack step to relevant techniques using:

- Semantic similarity matching
- Vector embeddings
- Confidence scoring (0.0-1.0)

This helps you understand attacks in standardized terminology and plan defenses using industry best practices.

[→ How It Works](how-it-works/index.md#phase-2-ttp-enrichment)

### How accurate is the AI-generated content?

!!! warning "Review Required"
    AI content is a starting point. Always review and validate outputs for your specific context.

**Quality depends on:**

- LLM model (Claude 3.5 Sonnet recommended)
- Documentation quality
- Threat description completeness

**Best practices:**

- Review all outputs
- Validate MITRE mappings
- Customize mitigations
- Iterate and refine

[→ Best Practices](how-it-works/index.md#best-practices-for-optimal-results)

---

## Privacy & Security

### Is my code sent to the LLM provider?

!!! warning "Data Sent to LLM"
    Yes, relevant project context is sent for analysis. Choose your provider carefully.

**Data sent:**

- Application details and architecture
- Threat descriptions
- Documentation content
- Diagram descriptions

**Privacy options:**

- ✅ **Ollama** - Complete privacy (local)
- ✅ **AWS Bedrock** - Enterprise data handling
- ⚠️ **Others** - Review provider policies

[→ Data Privacy Guide](index.md#data-privacy-considerations)

### How do I protect sensitive information?

!!! tip "Protection Strategies"
    1. Use Ollama for sensitive projects
    2. Sanitize input (remove secrets/PII)
    3. Review outputs for leaks
    4. Use access controls

**Best practices:**

- Remove credentials before analysis
- Use generic descriptions for demos
- Check provider data retention policies
- Store outputs securely

### Can I use ThreatForest in an air-gapped environment?

Yes, with Ollama:

```yaml
# config.yaml
ollama:
  enabled: true
  base_url: "http://localhost:11434"
  model_id: "qwen2.5:14b"
```

1. Install Ollama on air-gapped machine
2. Download models offline
3. Configure ThreatForest
4. Run completely offline

[→ Ollama Setup Guide](advanced/multi-provider.md)

---

## Troubleshooting

### Error: 'externally-managed-environment'

!!! question "Problem"
    Python prevents system-wide pip installs

**Solution:** Use pipx instead:

```bash
pipx install threatforest
```

### Error: 'Bedrock access failed'

!!! question "Problem"
    AWS credentials not configured or insufficient permissions

**Solution:**

```bash
# Configure AWS credentials
aws configure

# Verify access
aws bedrock list-foundation-models --region us-east-1

# Check IAM permissions include:
# - bedrock:InvokeModel
# - bedrock:InvokeModelWithResponseStream
```

### Very slow first run

!!! info "This is normal!"
    First run downloads:
    - sentence-transformers models (~500MB)
    - torch library
    - MITRE ATT&CK data
    
    Subsequent runs are much faster (seconds instead of minutes).

### Why is ThreatForest slow?

!!! info "Typical Duration"
    5-30 minutes depending on project size and model selection.

**Performance factors:**

- **Model** - Haiku (fast), Sonnet (balanced), Opus (slow)
- **Project size** - More threats = longer time
- **Network** - Latency to LLM provider
- **Hardware** - Local models need CPU/GPU

**Speed optimization:**

- Use AWS Bedrock or Anthropic
- Select Claude 3 Haiku for faster results
- Process threats incrementally

[→ Performance Guide](how-it-works/performance.md)

### ThreatForest fails with "API rate limit exceeded"

**Solutions:**

- Wait and retry (automatic retry logic)
- Reduce concurrency
- Upgrade provider plan
- Switch providers

### The attack trees don't match my application

**Common causes:**

- Incomplete documentation
- Generic threat descriptions
- Missing architecture context

**Improvements:**

- Add detailed architecture diagrams
- Include technology stack docs
- Write specific threat descriptions
- Use ThreatComposer format

[→ Preparing Your Project](user-guide/preparing-your-project.md)

### Dashboard Won't Open

**Solutions:**

1. Check file exists in output directory
2. Try different browser
3. Check file permissions
4. Clear browser cache (Cmd/Ctrl+Shift+R)

### Graph Not Displaying

**Solutions:**

1. Enable JavaScript in browser
2. Check browser console for errors (F12)
3. Verify `threatforest_data.json` exists
4. Clear browser cache

### Slow Dashboard Performance

**Solutions:**

1. Use filters to reduce visible threats
2. Close other browser tabs
3. Update to latest browser version
4. Reduce zoom level

### Missing Threat Details

**Solutions:**

1. Regenerate analysis
2. Check data file integrity
3. Verify analysis completed successfully
4. Review state file for errors

### Can I customize the output format?

Yes! ThreatForest generates:

- **Markdown** - Easily customizable
- **JSON** - For programmatic access
- **HTML** - Interactive dashboard

You can modify templates and parse JSON for custom reporting.

[→ Customization Guide](advanced/customization.md)

---

## Integration & Advanced

### Can I integrate into CI/CD?

ThreatForest is designed for interactive use. For CI/CD:

- Run wizard in containerized environment
- Use JSON output for automation
- Review attack trees as security gates

[→ CI/CD Patterns](advanced/customization.md)

### Does ThreatForest support multiple languages?

Analysis is language-agnostic. ThreatForest analyzes:

- Architecture and design (not code directly)
- Threat descriptions (any language supported by LLM)
- Configuration files
- Data flow diagrams

LLM responses are in English.

### Can I contribute to ThreatForest?

Absolutely! Contributions welcome:

- Bug reports on GitHub
- Feature requests
- Code contributions (pull requests)
- Documentation improvements

[→ Contributing Guide](about/contributing.md)

---

## Still Have Questions?

<div class="grid cards" markdown>

-   📖 __Documentation__

    ---

    Browse comprehensive guides

    [→ Read the docs](getting-started/index.md)

-   🐛 __GitHub Issues__

    ---

    Report bugs or request features

    [→ Open Issue](https://github.com/aws-samples/sample-agentic-attack-tree-generator/issues)

-   💬 __Discussions__

    ---

    Ask questions and share ideas

    [→ GitHub Discussions](https://github.com/aws-samples/sample-agentic-attack-tree-generator/discussions)

</div>
