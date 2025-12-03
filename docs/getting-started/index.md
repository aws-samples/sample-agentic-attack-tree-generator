# Getting Started with ThreatForest

Welcome to ThreatForest! This guide will help you get up and running with AI-powered threat modeling in minutes.

## Installation Steps

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
    
    # Run ThreatForest
    threatforest
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
    
    # Run ThreatForest
    threatforest
    ```

### Step 2: Configure AWS Bedrock

!!! warning "Prerequisites"
    **AWS Account with Bedrock access (Recommended - fully tested and supported)**
    
    Requires AWS Profile with IAM permissions for:
    
    - `bedrock:Converse`
    - `bedrock:ConverseStream`
    - `bedrock:InvokeModel`
    
    **Note:** Other providers (Anthropic, OpenAI, Google Gemini, Ollama) are experimental and not fully validated.

Configure your AWS credentials for Bedrock access:

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

## Next Steps

Now that you have ThreatForest installed, explore these guides:

<div class="grid cards" markdown>

-   🚀 __Running ThreatForest__

    ---

    Learn to use the interactive wizard and manage your workflow

    [→ Learn More](../user-guide/running-threatforest.md)

-   📁 __Preparing Your Project__

    ---

    Optimize inputs for better threat analysis results

    [→ Prepare Project](../user-guide/preparing-your-project.md)

-   📊 __Understanding Results__

    ---

    Explore outputs and use the interactive dashboard

    [→ Explore Results](../user-guide/understanding-results.md)

-   ⚙️ __How It Works__

    ---

    Technical deep dive into the analysis pipeline

    [→ Technical Details](../how-it-works.md)

</div>

---

## Need Help?

Having issues? Check the [FAQ Troubleshooting section](../faq.md#troubleshooting) for common problems and solutions.
