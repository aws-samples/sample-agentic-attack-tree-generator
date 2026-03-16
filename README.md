# ThreatForest

<div align="center">

**AI-powered threat modeling and attack tree generation with MITRE ATT&CK integration**

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

[Documentation](https://aws-samples.github.io/sample-agentic-attack-tree-generator/) • [Getting Started](https://aws-samples.github.io/sample-agentic-attack-tree-generator/getting-started/) • [Contributing](CONTRIBUTING.md)

</div>

---

ThreatForest is an agentic threat modeling platform built on the [Strands](https://strandsagents.com/latest/) framework. Point it at a repository and it autonomously generates attack trees, maps attack steps to MITRE ATT&CK techniques, and produces actionable mitigation recommendations.

## Quick Start

```bash
# Clone and run with uv (recommended)
git clone https://github.com/aws-samples/sample-agentic-attack-tree-generator.git
cd sample-agentic-attack-tree-generator
uv run threatforest
```

See the [Getting Started guide](https://aws-samples.github.io/sample-agentic-attack-tree-generator/getting-started/) for full installation options and configuration.

## License

MIT — see [LICENSE](LICENSE).
