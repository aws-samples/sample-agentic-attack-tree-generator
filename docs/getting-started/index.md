# Getting Started with ThreatForest

Welcome to ThreatForest! This guide will help you get up and running with AI-powered threat modeling in minutes.

## Installation Steps

### Step 1: Install ThreatForest

ThreatForest has two parts:

- the **pipeline, API, CLI and web console** — TypeScript, under `ts/` (requires Node.js 20+)
- the **embeddings / MITRE TTP-matching service** — a small Python service under `src/ml_service`
  (requires Python 3.11+). It is **required**: the engine pre-flights it and refuses to start a run
  when it is unreachable, rather than producing a threat model with silently missing attack paths.

```bash
git clone https://github.com/aws-samples/sample-agentic-attack-tree-generator.git
cd sample-agentic-attack-tree-generator

# 1. Python ML service dependencies
uv sync                     # or: python3 -m venv .venv && .venv/bin/pip install .

# 2. TypeScript workspace
cd ts && npm install
```

Then start everything with one command:

```bash
cd ts
npm run dev                 # ML service (:8770) + API (:8000) + web console (:3000)
```

Open <http://localhost:3000>.

??? note "Running the pieces separately"

    ```bash
    # Terminal 1 — the ML service (from the repo root)
    uv run python -m ml_service          # binds 127.0.0.1:8770

    # Terminal 2 — the CLI / web console (from ts/)
    cd ts
    npx threatforest                     # serves the console on 127.0.0.1:8000
    ```

    `npm install` links the `threatforest` binary into `ts/node_modules/.bin`, so `npx threatforest`
    works without a global install. Every `threatforest …` command in these docs can be run that way.

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
cd ts && npx threatforest config init
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
    cd ts && npx threatforest
    ```

    Opens the web console at `http://localhost:8000` automatically. From there:

    1. On the **Home** page, click **Add application**
    2. Fill in the wizard — application name, project path, and business context (regulatory frameworks, data sensitivity, CIA priority ranking). The business context steers threat generation, so it's worth filling in.
    3. From the application overview, click **New run** to start an analysis
    4. Watch real-time progress on the **Run** page
    5. View results in the threat model summary and version detail pages when complete

=== "Terminal (TUI)"

    ```bash
    cd ts && npx threatforest --tui
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
