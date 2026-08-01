# ThreatForest

<div align="center">

<img src="https://raw.githubusercontent.com/aws-samples/sample-agentic-attack-tree-generator/main/docs/assets/logo.png" alt="ThreatForest logo" width="120">

**AI-powered threat modeling and attack tree generation with MITRE ATT&CK integration**

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Status](https://img.shields.io/badge/status-beta-orange.svg)](https://github.com/aws-samples/sample-agentic-attack-tree-generator)
[![arXiv](https://img.shields.io/badge/arXiv-2607.27528-b31b1b.svg)](https://arxiv.org/abs/2607.27528)

[Documentation](https://aws-samples.github.io/sample-agentic-attack-tree-generator/) • [Getting Started](https://aws-samples.github.io/sample-agentic-attack-tree-generator/getting-started/) • [Paper](https://arxiv.org/abs/2607.27528) • [Contributing](CONTRIBUTING.md)

📄 **Read the paper:** [*ThreatForest: Multi-Agent Attack Tree Generation with Pluggable TTP Framework Mapping*](https://arxiv.org/abs/2607.27528) (arXiv:2607.27528)

</div>

<!--
  HERO VIDEO — short loop of the interactive attack tree dashboard.
  Poster frame (JPG) shows while the video loads.
-->
<p align="center">
  <video
    src="https://github.com/user-attachments/assets/0496fc69-faf0-4bc4-8c00-6cc8cca2ef43"
    poster="docs/assets/images/attack-tree-dashboard-poster.jpg"
    autoplay loop muted playsinline
    width="85%">
    <img src="https://raw.githubusercontent.com/aws-samples/sample-agentic-attack-tree-generator/main/docs/assets/images/attack-tree-dashboard-poster.jpg" alt="Interactive attack tree dashboard with MITRE ATT&CK mappings" width="85%">
  </video>
</p>

---

ThreatForest is an agentic threat modeling platform built on the [Strands](https://strandsagents.com/latest/) agent framework. Point it at a repository and it autonomously generates attack trees, maps attack steps to MITRE ATT&CK techniques, and produces actionable mitigation recommendations.

Built for **security teams, architects, and DevSecOps engineers** who want to bring threat modeling into the development loop without turning it into a second full-time job.

- 🤖 **Autonomous agent pipeline** — scanner, threat identifier, attack tree generator, TTP mapper, and mitigation advisor run in sequence, analyzing threats in parallel
- 🛡️ **MITRE ATT&CK mapping** — attack steps are mapped to TTPs using ATTACK-BERT semantic embeddings
- 📊 **Interactive dashboard** — explore threats visually with a searchable graph, filters, and expandable mitigations

> **Privacy:** ThreatForest sends project context to your configured LLM provider. AWS Bedrock is recommended for production workloads.

## Quick Start

```bash
git clone https://github.com/aws-samples/sample-agentic-attack-tree-generator.git
cd sample-agentic-attack-tree-generator

# 1. Embeddings / MITRE TTP matching run in a small Python service
uv sync
uv run python -m ml_service          # binds 127.0.0.1:8770 — leave running

# 2. The pipeline, API, CLI and UI are TypeScript
cd ts
npm install
npm run dev                          # ML service + API (:8000) + UI (:3000)
```

Then open <http://localhost:3000>.

> The Python ML service is required — the engine pre-flights it and refuses to start a run when it is
> unreachable, rather than producing a threat model with silently missing attack paths.

See the [Getting Started guide](https://aws-samples.github.io/sample-agentic-attack-tree-generator/getting-started/) for full installation options and configuration.

## See it in action

<p align="center">
  <video
    src="https://github.com/user-attachments/assets/b8c1708d-a9c1-4f65-aa45-34a17d5f3404"
    poster="docs/assets/images/end-to-end-demo-poster.jpg"
    controls muted playsinline
    width="85%">
    <img src="https://raw.githubusercontent.com/aws-samples/sample-agentic-attack-tree-generator/main/docs/assets/images/end-to-end-demo-poster.jpg" alt="End-to-end walkthrough: launch wizard, analyze repository, then explore the interactive attack tree dashboard" width="85%">
  </video>
</p>

From a repository path to a fully mapped attack tree in a single run. For a deeper tour — including the dashboard, filtering, and mitigation details — see the [full walkthrough in the docs](https://aws-samples.github.io/sample-agentic-attack-tree-generator/user-guide/understanding-results/).

## Next steps

- 📚 [Read the documentation](https://aws-samples.github.io/sample-agentic-attack-tree-generator/) — full guides, architecture, and FAQ
- 🏗️ [How it works](https://aws-samples.github.io/sample-agentic-attack-tree-generator/how-it-works/) — the agent pipeline, phase by phase
- 🐛 [Report an issue](https://github.com/aws-samples/sample-agentic-attack-tree-generator/issues) — bug reports and feature requests welcome
- 🤝 [Contribute](CONTRIBUTING.md) — see the contributing guide to get involved

## Star history

<a href="https://star-history.com/#aws-samples/sample-agentic-attack-tree-generator&Date">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=aws-samples/sample-agentic-attack-tree-generator&type=Date&theme=dark">
    <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/svg?repos=aws-samples/sample-agentic-attack-tree-generator&type=Date">
    <img alt="Star history chart for aws-samples/sample-agentic-attack-tree-generator" src="https://api.star-history.com/svg?repos=aws-samples/sample-agentic-attack-tree-generator&type=Date">
  </picture>
</a>

## Citation

ThreatForest is described in [*ThreatForest: Multi-Agent Attack Tree Generation with Pluggable TTP
Framework Mapping*](https://arxiv.org/abs/2607.27528). If you use it in your research, please cite:

```bibtex
@misc{leo2026threatforest,
  title         = {ThreatForest: Multi-Agent Attack Tree Generation with Pluggable TTP Framework Mapping},
  author        = {Leo, Cristian and Dykyi, Anton and Cortegaca, Danny and Begimher, Daniel and Jha, Prakash},
  year          = {2026},
  eprint        = {2607.27528},
  archivePrefix = {arXiv},
  primaryClass  = {cs.CR},
  url           = {https://arxiv.org/abs/2607.27528}
}
```

## License

MIT — see [LICENSE](LICENSE).
