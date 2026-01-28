# 🌳 ThreatForest

<div align="center">

<img src="docs/assets/threatforest-logo.png" alt="ThreatForest Logo" width="200"/>

**AI-Driven Threat Modeling & Attack Tree Generation with MITRE ATT&CK Integration**

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

[Documentation](https://aws-samples.github.io/sample-agentic-attack-tree-generator/) • [Contributing](CONTRIBUTING.md)

</div>

---

## 🎯 Overview

ThreatForest is an AI-powered threat modeling platform built on [Strands Framework](https://strandsagents.com/latest/). It automatically generates comprehensive attack trees from your project documentation and threat models, mapping them to MITRE ATT&CK techniques with actionable mitigation strategies.

**Key Features:**

- 🤖 Autonomous AI agents explore and analyze your project
- 🌳 Generate detailed attack trees with multiple attack paths
- 🎯 Automatic MITRE ATT&CK technique mapping
- 📊 Interactive HTML dashboards for visualization
- 🔄 Seamless IDE integration with Kiro

📖 **[Read Full Documentation](http://aws-samples.github.io/sample-agentic-attack-tree-generator/)**

## 🚀 Quick Start

### Option 1: Install with pipx (recommended for regular use)

```bash
pipx install git+https://github.com/aws-samples/sample-agentic-attack-tree-generator.git

# Run the interactive wizard
threatforest
```

### Option 2: Run directly with uvx (no installation required)

```bash
# Run without installing - uv handles dependencies automatically
uvx --from git+https://github.com/aws-samples/sample-agentic-attack-tree-generator.git threatforest
```

**Prerequisites:** Python 3.11+, AWS Bedrock access (or other LLM provider)

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **[Strands Framework](https://strandsagents.com/latest/)** - Powerful agentic framework for orchestrating AI workflows
- **AWS ThreatComposer** - Excellent threat modeling tool and inspiration
- **MITRE ATT&CK** - Comprehensive threat intelligence framework
- **AWS Bedrock** - Powerful LLM infrastructure
- **vis-network** - Interactive graph visualization

---
