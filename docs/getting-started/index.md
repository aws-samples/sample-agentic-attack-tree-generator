# Getting Started with ThreatForest

Welcome to ThreatForest! This guide will help you get up and running with AI-powered threat modeling in minutes.

## 📋 Prerequisites

Before installing ThreatForest, ensure you have:

### Required

- [x] **Python 3.11 or higher** - Check with `python3 --version`
- [x] **Git** - For cloning the repository
- [x] **LLM Provider Access** - At least one of:
    - AWS Account with Bedrock access
    - Anthropic API key
    - OpenAI API key  
    - Google Gemini API key
    - Local Ollama installation

### Recommended

- [x] **Virtual Environment Tool** - `venv`, `pipx`, or `uv`
- [x] **IDE** - VSCode, PyCharm, or Kiro IDE for best experience
- [x] **Git Repository** - For version controlling your threat models

!!! tip "First Time with AI Tools?"
    If you're new to using AI/LLM providers, we recommend starting with **AWS Bedrock** for its comprehensive documentation and enterprise support.

---

## 🎯 What You'll Learn

By the end of this guide, you'll be able to:

1. Install ThreatForest on your system
2. Configure your preferred LLM provider
3. Run your first threat analysis
4. Understand the generated outputs
5. Navigate the interactive dashboard

---

## ⚡ Quick Start Options

Choose your preferred installation method:

<div class="grid cards" markdown>

-   :material-package-variant:{ .lg .middle } __pipx (Recommended)__

    ---

    Install ThreatForest as a global command accessible from anywhere

    ```bash
    pipx install threatforest
    threatforest
    ```

    [:octicons-arrow-right-24: Detailed steps](installation.md#pipx-installation)

-   :material-speedometer:{ .lg .middle } __uv (Modern & Fast)__

    ---

    Lightning-fast installation with modern Python tooling

    ```bash
    uv tool install threatforest
    threatforest
    ```

    [:octicons-arrow-right-24: Detailed steps](installation.md#uv-installation)

-   :material-code-braces:{ .lg .middle } __Development Mode__

    ---

    For contributors - editable install with instant code updates

    ```bash
    git clone <repo>
    pip install -e ".[dev]"
    threatforest
    ```

    [:octicons-arrow-right-24: Development setup](../contributing/development.md)

-   :material-docker:{ .lg .middle } __Docker (Coming Soon)__

    ---

    Containerized deployment for isolated environments

    ```bash
    docker run threatforest
    ```

    [:octicons-arrow-right-24: Stay tuned](#)

</div>

---

## 🚦 Installation Steps

### Step 1: Install ThreatForest

=== "pipx (Recommended)"

    ```bash
    # Install pipx if you don't have it
    python3 -m pip install --user pipx
    python3 -m pipx ensurepath
    
    # Install ThreatForest
    git clone https://github.com/YOUR-ORG/ThreatForest.git
    cd ThreatForest
    pipx install .
    
    # Verify installation
    threatforest --help
    ```

=== "uv (Modern)"

    ```bash
    # Install uv
    curl -LsSf https://astral.sh/uv/install.sh | sh
    
    # Install ThreatForest
    git clone https://github.com/YOUR-ORG/ThreatForest.git
    cd ThreatForest
    uv tool install .
    
    # Verify installation
    threatforest --help
    ```

=== "pip (Traditional)"

    ```bash
    # Clone repository
    git clone https://github.com/YOUR-ORG/ThreatForest.git
    cd ThreatForest
    
    # Create virtual environment
    python3 -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    
    # Install
    pip install .
    
    # Verify installation
    threatforest --help
    ```

### Step 2: Configure LLM Provider

Choose your AI provider and configure credentials:

=== "AWS Bedrock"

    ```bash
    # Configure AWS credentials
    aws configure
    # AWS Access Key ID: [your-access-key]
    # AWS Secret Access Key: [your-secret-key]
    # Default region name: us-east-1
    # Default output format: json
    
    # Test Bedrock access
    aws bedrock list-foundation-models --region us-east-1
    ```
    
    [:octicons-arrow-right-24: AWS Bedrock Setup Guide](configuration.md#aws-bedrock)

=== "Anthropic"

    ```bash
    # Set API key
    export ANTHROPIC_API_KEY="your-api-key-here"
    
    # Or add to .env file
    echo "ANTHROPIC_API_KEY=your-api-key-here" >> .env
    ```
    
    [:octicons-arrow-right-24: Anthropic Setup Guide](configuration.md#anthropic)

=== "OpenAI"

    ```bash
    # Set API key
    export OPENAI_API_KEY="your-api-key-here"
    
    # Or add to .env file
    echo "OPENAI_API_KEY=your-api-key-here" >> .env
    ```
    
    [:octicons-arrow-right-24: OpenAI Setup Guide](configuration.md#openai)

=== "Ollama (Local)"

    ```bash
    # Install Ollama
    curl -fsSL https://ollama.ai/install.sh | sh
    
    # Pull a model
    ollama pull llama3:70b
    
    # Verify it's running
    ollama list
    ```
    
    [:octicons-arrow-right-24: Ollama Setup Guide](configuration.md#ollama)

### Step 3: Prepare Your Project

ThreatForest works best with proper project structure:

```
your-project/
├── README.md                    # Application description
├── ARCHITECTURE.md              # System architecture (optional)
├── threats.tc.json              # Threat model (optional)
└── diagrams/                    # Architecture diagrams (optional)
    ├── system-architecture.png
    └── data-flow.mmd
```

!!! tip "No Threat Model Yet?"
    That's okay! ThreatForest can generate threats automatically by analyzing your documentation and architecture. Just ensure you have:
    
    - A README.md describing your application
    - Some architecture documentation or diagrams
    - Clear indication of technologies used

### Step 4: Run Your First Analysis

```bash
# Launch the interactive wizard
threatforest

# Or specify project directly
threatforest --project-path /path/to/your/project
```

The wizard will guide you through:

1. **Workflow Selection** - Choose Full Analysis, Enrichment, or Mitigation
2. **Project Location** - Specify project directory path
3. **AWS Configuration** - Select AWS profile (if using Bedrock)
4. **Model Selection** - Choose AI model
5. **Execution** - Watch real-time progress
6. **Results** - View summary and output files

---

## ✅ Verify Installation

Test your installation with these commands:

```bash
# Check ThreatForest is installed
threatforest --version

# View help
threatforest --help

# Check configuration
threatforest config show

# Test AWS access (if using Bedrock)
aws bedrock list-foundation-models --region us-east-1
```

**Expected Output:**
```
ThreatForest v1.0.0
Python 3.11.x
AWS Bedrock: ✓ Connected
Model: Claude 3 Sonnet
```

---

## ⏱️ First Run: What to Expect

!!! info "Initial Startup Time"
    **First run takes 2-3 minutes** while ThreatForest downloads AI model dependencies:
    
    - `sentence-transformers` models (~500MB)
    - `torch` library
    - MITRE ATT&CK embeddings graph
    
    **Subsequent runs are much faster** (seconds), as dependencies are cached.

**Progress Indicators:**

```
🌳 ThreatForest Analysis
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 

✓ Setup & Validation (5s)
✓ Context Analysis (15s)
✓ Information Extraction (30s)
✓ Attack Tree Generation (60s)
✓ TTP Enrichment (20s)
✓ Report Generation (10s)

📊 Analysis Complete! (140s total)
```

---

## 🎓 Next Steps

Now that you have ThreatForest installed, explore these guides:

<div class="grid cards" markdown>

-   :material-rocket-launch:{ .lg .middle } __Quick Start Tutorial__

    ---

    Complete walkthrough of your first threat analysis

    [:octicons-arrow-right-24: Start Tutorial](quick-start.md)

-   :material-cog-outline:{ .lg .middle } __Configuration Guide__

    ---

    Customize ThreatForest for your environment

    [:octicons-arrow-right-24: Configure](configuration.md)

-   :material-file-tree:{ .lg .middle } __First Analysis__

    ---

    Step-by-step guide to analyzing your first project

    [:octicons-arrow-right-24: Analyze Project](first-analysis.md)

-   :material-book-open:{ .lg .middle } __User Guide__

    ---

    Learn about workflows, inputs, and outputs

    [:octicons-arrow-right-24: User Guide](../user-guide/workflows.md)

</div>

---

## 🆘 Troubleshooting

Having issues? Check these common problems:

??? question "Error: 'externally-managed-environment'"
    
    **Problem:** Python prevents system-wide pip installs
    
    **Solution:** Use pipx or uv instead:
    ```bash
    pipx install threatforest
    # or
    uv tool install threatforest
    ```

??? question "Error: 'Bedrock access failed'"
    
    **Problem:** AWS credentials not configured or insufficient permissions
    
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

??? question "Error: 'No threat models found'"
    
    **Problem:** ThreatForest can't find threat statements
    
    **Solution:** Either:
    1. Add a ThreatComposer file (`*.tc.json`)
    2. Create `threats.json` in project root
    3. Let ThreatForest generate threats automatically (just have good documentation)

??? question "Very slow first run"
    
    **Problem:** Downloading large AI models
    
    **Solution:** This is normal! First run downloads:
    - sentence-transformers models (~500MB)
    - torch library
    - MITRE ATT&CK data
    
    Subsequent runs are much faster (seconds instead of minutes).

[:octicons-arrow-right-24: Full Troubleshooting Guide](../advanced/troubleshooting.md)

---

## 📚 Additional Resources

- [Installation Methods](installation.md) - Detailed installation options
- [Configuration](configuration.md) - Complete configuration reference
- [CLI Reference](../user-guide/cli-reference.md) - All commands and options
- [Architecture Overview](../architecture/overview.md) - How ThreatForest works
- [Examples](../examples/index.md) - Real-world demonstrations

---

<div class="cta-section" markdown>

## Ready to Dive Deeper?

Continue your ThreatForest journey with our comprehensive guides.

[Run Your First Analysis](quick-start.md){ .md-button .md-button--primary }
[Explore Examples](../examples/index.md){ .md-button }

</div>
