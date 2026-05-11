# Getting Started with ThreatForest

Welcome to ThreatForest! This guide will help you get up and running with AI-powered threat modeling in minutes.

## Installation Steps

### Step 1: Install ThreatForest

=== "uv (Recommended)"

    ```bash
    # Install uv if you don't have it
    curl -LsSf https://astral.sh/uv/install.sh | sh

    # Clone and run — uv handles the environment automatically
    git clone https://github.com/aws-samples/sample-agentic-attack-tree-generator.git
    cd sample-agentic-attack-tree-generator
    uv run threatforest
    ```

=== "pipx"

    ```bash
    # Install pipx if you don't have it
    python3 -m pip install --user pipx
    python3 -m pipx ensurepath

    # Install ThreatForest
    git clone https://github.com/aws-samples/sample-agentic-attack-tree-generator.git
    cd sample-agentic-attack-tree-generator
    pipx install .

    # Run ThreatForest
    threatforest
    ```

=== "pip"

    ```bash
    # Clone repository
    git clone https://github.com/aws-samples/sample-agentic-attack-tree-generator.git
    cd sample-agentic-attack-tree-generator

    # Create virtual environment
    python3 -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate

    # Install
    pip install .

    # Run ThreatForest
    threatforest
    ```

### Step 2: Configure your LLM provider

!!! warning "AWS Bedrock recommended"
    AWS Bedrock is fully tested and supported. Other providers (Anthropic, OpenAI, Gemini, Ollama, SageMaker) are experimental.

=== "AWS Bedrock"

    Configure an AWS profile with IAM permissions for:

    - `bedrock:InvokeModel`
    - `bedrock:InvokeModelWithResponseStream`

    ```bash
    aws configure --profile your-profile-name
    aws bedrock list-foundation-models --region us-east-1 --profile your-profile-name
    ```

=== "Other providers"

    Set your API key for Anthropic, OpenAI, or Gemini — or point to a local Ollama instance.
    See [Configuration](configuration.md) for all provider options.

Run the configuration wizard (or use the **Configure** page in the web console):

```bash
threatforest config init
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

=== "Web Console (default)"

    ```bash
    threatforest
    ```

    Opens the web console at `http://localhost:8000` automatically. From there:

    1. On the **Home** page, click **Add application**
    2. Fill in the wizard — application name, project path, and business context (regulatory frameworks, data sensitivity, main CIA risk). The business context steers threat generation, so it's worth filling in.
    3. From the application overview, click **New run** to start an analysis
    4. Watch real-time progress on the **Run** page
    5. View results in the threat model summary and version detail pages when complete

=== "Terminal (TUI)"

    ```bash
    threatforest --tui
    ```

    Launches the interactive terminal wizard. Follow the prompts to select a project path and start the analysis.

---

## Next Steps

Now that you have ThreatForest installed, explore these guides:

<div class="grid cards" markdown>

-   🚀 __Running ThreatForest__

    ---

    Web console, terminal mode, and CLI options

    [→ Learn More](../user-guide/running-threatforest.md)

-   📁 __Preparing Your Project__

    ---

    Optimize inputs for better threat analysis results

    [→ Prepare Project](../user-guide/preparing-your-project.md)

-   📊 __Understanding Results__

    ---

    Explore outputs and use the interactive dashboard

    [→ Explore Results](../user-guide/understanding-results.md)

-   ⚙️ __Configuration__

    ---

    LLM providers, config file, and advanced settings

    [→ Configure](configuration.md)

</div>

---

## Need Help?

Having issues? Check the [FAQ Troubleshooting section](../faq.md#troubleshooting) for common problems and solutions.
