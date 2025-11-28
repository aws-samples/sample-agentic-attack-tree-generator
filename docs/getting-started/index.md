# Getting Started with ThreatForest

Welcome to ThreatForest! This guide will help you get up and running with AI-powered threat modeling in minutes.

## 📋 Prerequisites

Before installing ThreatForest, ensure you have:

### Required

- [x] **Python 3.11 or higher** - Check with `python3 --version`
- [x] **Git** - For cloning the repository
- [x] **LLM Provider Access** - At least one of:
    - AWS Account with Bedrock access (Recommended - fully tested and supported)
        - Requires AWS Profile with IAM permissions for:
            - `bedrock:Converse`
            - `bedrock:ConverseStream`
            - `bedrock:InvokeModel`
    - Anthropic API key (Experimental - outputs not fully tested)
    - OpenAI API key (Experimental - outputs not fully tested)
    - Google Gemini API key (Experimental - outputs not fully tested)
    - Local Ollama installation (Experimental - outputs not fully tested)

### Recommended

- [x] **Virtual Environment Tool** - `venv`, `pipx`, or `uv`
- [x] **IDE** - VSCode, PyCharm, or Kiro IDE for best experience
- [x] **Git Repository** - For version controlling your threat models

!!! tip "Recommended Provider"
    **AWS Bedrock is the recommended and fully supported provider.** ThreatForest has been extensively tested with Bedrock models. Other providers (Anthropic, OpenAI, Google Gemini, Ollama) are experimental and their outputs have not been fully tested or validated.

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

-   :material-speedometer:{ .lg .middle } __uv (Modern & Fast)__

    ---

    Lightning-fast installation with modern Python tooling

    ```bash
    uv tool install threatforest
    threatforest
    ```

-   :material-code-braces:{ .lg .middle } __Development Mode__

    ---

    For contributors - editable install with instant code updates

    ```bash
    git clone <repo>
    pip install -e ".[dev]"
    threatforest
    ```

-   :material-docker:{ .lg .middle } __Docker (Coming Soon)__

    ---

    Containerized deployment for isolated environments

    ```bash
    docker run threatforest
    ```

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
    git clone https://github.com/aws-samples/sample-agentic-attack-tree-generator.git
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
    git clone https://github.com/aws-samples/sample-agentic-attack-tree-generator.git
    cd ThreatForest
    uv tool install .
    
    # Verify installation
    threatforest --help
    ```

=== "pip (Traditional)"

    ```bash
    # Clone repository
    git clone https://github.com/aws-samples/sample-agentic-attack-tree-generator.git
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

    **Option 1: AWS Profile (Recommended)**
    
    Configure an AWS profile that the ThreatForest wizard will use:
    
    ```bash
    # Configure AWS profile
    aws configure --profile your-profile-name
    # AWS Access Key ID: [your-access-key]
    # AWS Secret Access Key: [your-secret-key]
    # Default region name: us-east-1
    # Default output format: json
    
    # Test Bedrock access
    aws bedrock list-foundation-models --region us-east-1 --profile your-profile-name
    ```
    
    When you run `threatforest`, the wizard will prompt you to:
    - Select your AWS profile name
    - Specify the AWS region (e.g., us-east-1)
    
    **Option 2: AWS Access Keys (Alternative)**
    
    Alternatively, you can provide AWS access keys directly when prompted by the wizard.

=== "Anthropic"

    ```bash
    # Set API key
    export ANTHROPIC_API_KEY="your-api-key-here"
    
    # Or add to .env file
    echo "ANTHROPIC_API_KEY=your-api-key-here" >> .env
    ```
    
=== "Ollama (Local)"

    ```bash
    # Install Ollama
    curl -fsSL https://ollama.ai/install.sh | sh
    
    # Pull a model
    ollama pull llama3:70b
    
    # Verify it's running
    ollama list
    ```

### Step 3: Prepare Your Project

At minimum, ThreatForest needs one of the following in your project directory:

- **ThreatComposer file** (`.tc.json`) - Recommended, created at [threat-composer](https://awslabs.github.io/threat-composer/)
- **README.md** - Application description and architecture overview
- **Architecture diagrams** - PNG, PDF, Mermaid, or other diagram formats

**Quick Setup:**

```
your-project/
├── README.md              # Describes your application
└── MyApp.tc.json         # Your threat model
```

!!! tip "Learn More"
    See the [User Guide → Preparing Your Project](../user-guide/preparing-your-project.md) for complete details on supported formats and best practices.

### Step 4: Run Your First Analysis

```bash
# Launch the interactive wizard
threatforest
```

The wizard will guide you through:

1. **Workflow Selection** - Choose Full Analysis, Enrichment, or Mitigation
2. **Project Location** - Specify project directory path
3. **AWS Configuration** - Select AWS profile (if using Bedrock)
4. **Model Selection** - Choose AI model
5. **Execution** - Watch real-time progress
6. **Results** - View summary and output files

---

##  Next Steps

Now that you have ThreatForest installed, explore these guides:

<div class="grid cards" markdown>

-   :material-rocket-launch:{ .lg .middle } __Running ThreatForest__

    ---

    Learn to use the interactive wizard and manage your workflow

    [:octicons-arrow-right-24: Learn More](../user-guide/running-threatforest.md)

-   :material-file-tree:{ .lg .middle } __Preparing Your Project__

    ---

    Optimize inputs for better threat analysis results

    [:octicons-arrow-right-24: Prepare Project](../user-guide/preparing-your-project.md)

-   :material-chart-box:{ .lg .middle } __Understanding Results__

    ---

    Explore outputs and use the interactive dashboard

    [:octicons-arrow-right-24: Explore Results](../user-guide/understanding-results.md)

-   :material-cog:{ .lg .middle } __How It Works__

    ---

    Technical deep dive into the analysis pipeline

    [:octicons-arrow-right-24: Technical Details](../how-it-works.md)

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
