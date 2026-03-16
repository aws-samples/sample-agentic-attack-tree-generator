<div class="hero" markdown>

# 🌳 ThreatForest [samples-agentic-attack-tree-generator]
<p style="font-size: 1.5rem; opacity: 1; margin-top: 1rem;">AI powered threat modeling and attack tree generator</p> 


<div class="hero-content" markdown>

Get comprehensive threat models for your application, with autonomous AI agents that analyze, generate, and visualize attack trees mapped to MITRE ATT&CK

<div style="text-align: center; margin: 2rem auto;">
    <img src="assets/images/threatforest-landingpage.png" alt="ThreatForest Demo" style="max-width: 100%; border-radius: 0.5rem; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);">
</div>

[Get Started](getting-started/index.md){ .md-button .md-button--primary }

<p style="font-size: 1rem; opacity: 0.8; margin-top: 1rem;">
💻 <a href="https://github.com/aws-samples/sample-agentic-attack-tree-generator">GitHub Repository</a>
</p>

</div>

</div>

---

## ✨ What is ThreatForest?

<div class="expandable-cards-grid">
  <div class="expandable-card">
    <div class="card-title">🤖 Autonomous Agents</div>
    <div class="card-content">
      <p>A pipeline of specialized AI agents developed by threat modeling and data science experts, built on the Strands framework — scanner, threat identifier, attack tree generator, TTP mapper, and mitigation advisor — run automatically in sequence with parallel per-threat processing</p>
    </div>
  </div>

  <div class="expandable-card">
    <div class="card-title">🛡️ MITRE ATT&CK Integration</div>
    <div class="card-content">
      <p>Automatically maps attack steps to TTPs (Tactics, Techniques, and Procedures) using semantic similarity and vector embeddings</p>
    </div>
  </div>

  <div class="expandable-card">
    <div class="card-title">📊 Interactive Dashboards</div>
    <div class="card-content">
      <p>Explore threats visually with interactive dashboards, complete with filtering and real-time search</p>
    </div>
  </div>

  <div class="expandable-card">
    <div class="card-title">⚙️ AWS Bedrock Support</div>
    <div class="card-content">
      <p>Officially supports AWS Bedrock (Claude models). Other providers (Anthropic, OpenAI, Gemini, Ollama) are experimental and not fully tested</p>
    </div>
  </div>
</div>

## 🚀 Quick Example

Generate comprehensive attack trees in minutes:

!!! tip "Prerequisites"
    Before starting, ensure you have [Python 3.11+ and an LLM provider configured](getting-started/index.md). AWS Bedrock is fully supported and recommended.

<div style="text-align: center; margin: 2rem auto;">
    <img src="assets/images/ThreatForestE2E-short.gif" alt="ThreatForest Demo" style="max-width: 100%; border-radius: 0.5rem; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);">
</div>

---

## 🎯 Key Features

**Intelligent Analysis**

<div class="feature-grid" markdown>

!!! success "Repository Scanning"
    **Scanner Agent** autonomously navigates your project using Strands tools to discover:

    - Architecture diagrams and documentation
    - Technology stack and cloud provider
    - Data flows and trust boundaries
    - Auth mechanisms and entry points

!!! info "Threat Identification"
    **Threat Agent** reads scanner context and produces a structured threat list from:

    - ThreatComposer workspaces (`.tc.json`)
    - JSON, YAML, and Markdown formats
    - AI-generated threats when no file exists

!!! tip "Parallel Analysis"
    **Per-threat pipeline** runs concurrently for every identified threat:

    - Attack tree generation
    - MITRE ATT&CK TTP mapping (ATTACK-BERT embeddings)
    - Mitigation recommendations

</div>

---

## 💼 Use Cases

<div class="grid cards" markdown>

-   🛡️ __Security Teams__

    ---

    Automate threat modeling, generate attack trees, map to MITRE ATT&CK for compliance

-   🔄 __DevSecOps__

    ---

    Integrate into CI/CD, analyze changes, generate security documentation

-   🏗️ __Architects & Developers__

    ---

    Understand security implications, identify vulnerabilities early, learn attack patterns

-   📋 __Compliance & Auditors__

    ---

    Document threats, demonstrate due diligence, generate compliance reports

</div>

---

## 📊 What You Get

**⭐ Interactive Dashboard**

<div class="screenshot-container" markdown>

![ThreatForest Dashboard](assets/images/InteractiveDashboardOutputWalkthrough.gif)
*Interactive dashboard with graph visualization*

**Features:**

- Visual network graph with pan/zoom
- Interactive node exploration
- Real-time filtering and search
- MITRE ATT&CK technique details
- Expandable mitigation strategies
- Export and sharing capabilities

</div>

---

## 🔒 Privacy & Security

!!! warning "Data Privacy"
    ThreatForest sends application context to your configured LLM provider for analysis. AWS Bedrock provides enterprise-grade data handling. For other providers, review their data policies.

**Best Practices:**

- Use AWS Bedrock for production workloads (officially supported)
- Remove secrets and credentials from project files before analysis
- Review generated output for any sensitive information
- Store outputs in secure, access-controlled locations

---

## 🆘 Need Help?

<div class="grid cards" markdown>

-   📚 __Documentation__

    ---

    Browse comprehensive guides and API references

    [→ Read the docs](getting-started/index.md)

-   🐛 __Report Issues__

    ---

    Found a bug? Have a feature request?

    [→ GitHub Issues](https://github.com/aws-samples/sample-agentic-attack-tree-generator/issues)

-   ❓ __FAQ__

    ---

    Frequently asked questions

    [→ FAQ](faq.md)

</div>
