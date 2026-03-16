# Release Notes

## Upgrading

To upgrade ThreatForest to the latest version:

**Using uv:**
```bash
uv tool upgrade threatforest
```

**Using pipx:**
```bash
pipx upgrade threatforest
```

**Using pip:**
```bash
pip install --upgrade threatforest
```

---

## Version 1.0.0

**Release Date:** TBD

### What's New

- **Web Console UI** — Browser-based interface for running analyses, viewing results, and managing configuration without touching the CLI
- **Langfuse tracing** — Optional observability integration for tracing agent runs, reviewing outputs, and building evaluation datasets
- **Agent verifiers** — Each pipeline stage now includes a verifier that checks output quality and automatically retries if the result is invalid, improving accuracy and consistency across runs

---

## Version 0.0.1

**Release Date:** December 4, 2024

### Features

- Initial release of ThreatForest
- AI-powered threat modeling and attack tree generation
- MITRE ATT&CK framework integration
- Support for multiple LLM providers (AWS Bedrock, Anthropic, OpenAI, Gemini, Ollama)
- Autonomous repository analysis using the Strands framework
- Multi-stage pipeline with state management
