# ThreatForest

ThreatForest is a Python application that automatically generates attack trees from threat statements found in application context files, enhanced with MITRE ATT&CK technique mappings.

## Features

- **Automated Context Analysis**: Scans directories for README files, architecture diagrams, data flow diagrams, and threat statements
- **LLM-Powered Information Extraction**: Uses Large Language Models to extract key application information
- **Interactive Validation**: Allows users to review and correct extracted information
- **Threat Statement Parsing**: Supports multiple formats including ThreatComposer JSON exports and markdown files
- **High-Severity Filtering**: Focuses on high-priority threats for attack tree generation
- **Mermaid Attack Trees**: Generates visual attack trees in Mermaid diagram format
- **MITRE ATT&CK Integration**: Maps attack steps to MITRE ATT&CK techniques using STIX data
- **Comprehensive Reporting**: Creates summary reports with links to generated attack trees

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd ThreatForest
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Install the package:
```bash
pip install -e .
```

## Configuration

ThreatForest uses AWS Bedrock by default. Configure your AWS credentials using one of these methods:

### Option 1: AWS CLI (Recommended)
```bash
aws configure
```

### Option 2: Environment Variables
```bash
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
export AWS_DEFAULT_REGION="us-east-1"
```

### Option 3: IAM Roles
If running on EC2 or other AWS services, use IAM roles for authentication.

### Alternative LLM Providers
You can also use other providers by setting:

```bash
# For OpenAI
export OPENAI_API_KEY="your-openai-api-key"
export TF_LLM_PROVIDER="openai"

# For Anthropic Claude (direct)
export ANTHROPIC_API_KEY="your-anthropic-api-key"
export TF_LLM_PROVIDER="anthropic"
```

## Quick Start

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Configure AWS credentials:**
   ```bash
   aws configure
   # or set environment variables
   export AWS_ACCESS_KEY_ID="your-key"
   export AWS_SECRET_ACCESS_KEY="your-secret"
   export AWS_DEFAULT_REGION="us-east-1"
   ```

3. **Test the installation:**
   ```bash
   python test_complete.py
   ```

4. **Run ThreatForest:**
   ```bash
   python main.py
   ```

## Usage

### Basic Usage

Run ThreatForest in a directory containing your application context files:

```bash
threat-forest
```

### Advanced Usage

```bash
# Analyze specific directory
threat-forest /path/to/project

# Specify output directory
threat-forest --output-dir ./security-analysis

# Skip user validation (automated mode)
threat-forest --no-user-validation

# Enable debug logging
threat-forest --log-level DEBUG

# Use configuration file
threat-forest --config config.yaml
```

### Required Files

ThreatForest looks for the following files in your project directory:

- **README.md** (required): Application description, technologies, architecture
- **Threat statements** (required): Files containing threat information with severity levels
  - `threats.md`, `security.md`, or ThreatComposer JSON exports
- **Architecture diagrams** (optional): Visual representations of system architecture
- **Data flow diagrams** (optional): Diagrams showing data movement through the system

### Example Directory Structure

```
my-application/
├── README.md                    # Application overview
├── threats.md                   # Threat statements with severity
├── architecture.png             # System architecture diagram
├── dataflow.mmd                 # Data flow diagram
└── threat_forest_output/        # Generated output
    ├── extracted_info.md         # Validated application info
    ├── attack_trees/             # Generated attack trees
    │   ├── threat-001-attack-tree.md
    │   └── threat-002-attack-tree.md
    ├── summary.md                # Analysis summary
    └── logs/
        └── threat_forest.log     # Application logs
```

## Configuration File

Create a `config.yaml` file for advanced configuration:

```yaml
llm:
  provider: "bedrock"  # bedrock, openai, or anthropic
  model: "anthropic.claude-3-sonnet-20240229-v1:0"
  max_tokens: 4000
  temperature: 0.1
  region: "us-east-1"

stix:
  bundle_path: "aaf-bundle.json"
  confidence_threshold: 0.8
  enable_mapping: true

output:
  include_timestamps: true
  mermaid_theme: "default"
  generate_summary: true
```

### Supported Bedrock Models

- **Claude 3**: `anthropic.claude-3-opus-20240229-v1:0`, `anthropic.claude-3-sonnet-20240229-v1:0`, `anthropic.claude-3-haiku-20240307-v1:0`
- **Claude 2**: `anthropic.claude-v2:1`, `anthropic.claude-v2`
- **Titan**: `amazon.titan-text-express-v1`, `amazon.titan-text-lite-v1`
- **Jurassic**: `ai21.j2-ultra-v1`, `ai21.j2-mid-v1`
- **Command**: `cohere.command-text-v14`
- **Llama**: `meta.llama2-13b-chat-v1`, `meta.llama2-70b-chat-v1`

## Development Status

This is a complete implementation with full functionality:

- ✅ File discovery and parsing
- ✅ AWS Bedrock integration (primary LLM provider)
- ✅ LLM-powered information extraction
- ✅ User validation system
- ✅ Threat statement parsing and filtering
- ✅ Attack tree generation with Mermaid diagrams
- ✅ MITRE ATT&CK technique mapping using STIX data
- ✅ Attack tree enhancement with technique references
- ✅ Comprehensive summary reporting (Markdown + JSON)
- ✅ Configuration management
- ✅ CLI interface with full functionality

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

MIT License - see LICENSE file for details.