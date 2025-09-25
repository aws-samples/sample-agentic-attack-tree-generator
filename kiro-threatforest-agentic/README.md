# ThreatForest

ThreatForest is an advanced agentic AI application that automatically generates comprehensive attack trees from threat statements using AWS Bedrock models. The application analyzes application context files, extracts key security information, and produces Mermaid-formatted attack trees enhanced with STIX-formatted threat intelligence.

## 🚀 Features

- **🤖 Enhanced AI Integration**: Advanced AWS Bedrock model support with intelligent model selection and validation
- **📊 Automated Context Analysis**: Scans directories for README files, architecture diagrams, and threat statements
- **🧠 AI-Powered Information Extraction**: Uses state-of-the-art language models for security analysis
- **🌳 Attack Tree Generation**: Creates detailed Mermaid-formatted attack trees for threat visualization
- **🛡️ STIX Enhancement**: Integrates AWS Threat Technique Catalog (TTC) mappings for comprehensive threat intelligence
- **⚙️ Interactive Setup Wizard**: Guided configuration with automatic AWS credential detection and model recommendations
- **🔧 Comprehensive CLI**: Enhanced command-line interface with detailed help, examples, and troubleshooting guidance
- **📈 Advanced Configuration**: Flexible configuration system with validation, multiple sources, and real-time testing
- **🔍 Intelligent Diagnostics**: Built-in system health checks, connectivity testing, and configuration validation

## 📦 Installation

### Prerequisites

- **Python 3.9+**: Required for modern language features and AWS SDK compatibility
- **AWS Account**: With Amazon Bedrock service access enabled
- **AWS Credentials**: Configured via AWS CLI, environment variables, or IAM roles
- **Network Access**: Internet connectivity for AWS Bedrock API calls
- **System Resources**: Minimum 2GB RAM, 1GB free disk space

### 🔒 Virtual Environment (Strongly Recommended)

Using a virtual environment isolates ThreatForest's dependencies from your system Python, preventing conflicts:

**Benefits:**
- ✅ **Dependency isolation**: Prevents conflicts with other Python projects
- ✅ **Clean uninstall**: Easy to remove by deleting the virtual environment
- ✅ **Version control**: Lock specific dependency versions for reproducibility
- ✅ **System protection**: Keeps your system Python installation clean

**Quick Setup:**
```bash
# Create virtual environment
python -m venv threatforest-env

# Activate it
source threatforest-env/bin/activate  # Linux/macOS
# OR
threatforest-env\Scripts\activate     # Windows

# Install ThreatForest
python install.py

# Deactivate when done (optional)
deactivate
```

### Installation Methods

#### Option 1: Quick Installation with Virtual Environment (Recommended)

Use the included installation script with a virtual environment for isolated setup:

```bash
# Clone or extract the ThreatForest package
git clone https://github.com/threatforest/threatforest.git
cd threatforest

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Run the quick installer
python install.py
```

The `install.py` script will:
- ✅ Check Python version compatibility
- ✅ Create virtual environment if not already active
- ✅ Install ThreatForest in development mode
- ✅ Install development dependencies (optional)
- ✅ Verify the installation works
- ✅ Provide next steps guidance

#### Option 2: Manual Virtual Environment Setup

For users who prefer manual control over the installation process:

```bash
# Create virtual environment
python -m venv threatforest-env
source threatforest-env/bin/activate  # On Windows: threatforest-env\Scripts\activate

# Upgrade pip
pip install --upgrade pip

# Install ThreatForest
pip install -e .

# Or install with development dependencies
pip install -e ".[dev]"
```

#### Option 3: Standard Python Installation

Using the setup.py script (virtual environment still recommended):

```bash
# Create and activate virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install from source
python setup.py install

# Or install in development mode
python setup.py develop
```

#### Option 4: System-wide Installation (Not Recommended)

For advanced users who prefer system-wide installation:

```bash
# Direct pip installation (may require sudo/admin privileges)
pip install -e .

# Install with development dependencies
pip install -e ".[dev]"

# Install with test dependencies only
pip install -e ".[test]"
```

#### Option 4: Docker Installation

```bash
# Pull and run with Docker
docker pull threatforest/tf:latest
docker run -v $(pwd):/workspace \
  -e AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY \
  -e AWS_DEFAULT_REGION \
  threatforest/tf analyze /workspace
```

### Installation Scripts

#### `install.py` - Quick Installer (Recommended)
Automated installation script that handles the complete setup process:

- ✅ **Automatic setup**: Handles all installation steps
- ✅ **Virtual environment detection**: Checks for and offers to create virtual environments
- ✅ **Dependency management**: Installs required and optional dependencies  
- ✅ **Validation**: Verifies installation works correctly
- ✅ **Guidance**: Provides clear next steps after installation
- ✅ **Error handling**: Shows helpful messages if issues occur

```bash
# Recommended: Use with virtual environment
python -m venv threatforest-env
source threatforest-env/bin/activate  # Linux/macOS
python install.py

# Or run directly (will prompt about virtual environment)
python install.py
```

#### `setup.py` - Standard Python Setup
Traditional Python package installation following standard conventions:

- ✅ **Standard compliance**: Follows Python packaging standards
- ✅ **Flexible installation**: Supports various pip installation modes
- ✅ **Dependency specification**: Defines all package dependencies
- ✅ **Entry points**: Configures CLI commands (`tf`, `threatforest`)
- ✅ **Distribution ready**: Suitable for PyPI and package managers

```bash
# Standard installation
python setup.py install

# Development installation  
python setup.py develop

# Or with pip
pip install .           # Standard mode
pip install -e .        # Development mode
```

### Package Contents

When you install ThreatForest, you get:

```
threatforest/
├── 🐍 threatforest/           # Main application package
├── 🧪 tests/                 # Comprehensive test suite  
├── 🔧 scripts/               # Utility scripts
│   ├── validation/           # Setup validation tools
│   ├── testing/              # Test runners
│   └── demo/                 # Feature demonstrations
├── 📚 docs/                  # Documentation
├── 🎯 examples/              # Example projects
└── 📄 Configuration files    # Setup and project files
```

### Installation Verification

After installation with any method, verify your setup:

```bash
# Check installation
tf --version

# Quick system status
tf status

# Comprehensive diagnostics
tf config doctor

# Run setup wizard
tf setup
```

## 🚀 Quick Start

### 1. Install ThreatForest

**Recommended approach with virtual environment:**

```bash
# Create and activate virtual environment
python -m venv threatforest-env
source threatforest-env/bin/activate  # Linux/macOS
# OR: threatforest-env\Scripts\activate  # Windows

# Install ThreatForest
python install.py
```

**Alternative:** Choose your preferred method from the [Installation](#-installation) section above.

### 2. Configure AWS Credentials

Set up your AWS credentials using one of these methods:

```bash
# Option A: AWS CLI (recommended)
aws configure

# Option B: Environment variables
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export AWS_DEFAULT_REGION=us-east-1

# Option C: IAM roles (when running on AWS)
# No additional setup needed
```

### 3. Run Interactive Setup

Use the setup wizard for guided configuration:

```bash
# Basic setup wizard
tf setup

# Verbose setup with detailed information
tf setup --verbose

# User-level configuration (personal settings)
tf setup --user
```

The setup wizard will:
- ✅ Detect and validate your AWS credentials
- ✅ Test connectivity to AWS Bedrock service
- ✅ Discover available models in your region
- ✅ Help you select the optimal model for your use case
- ✅ Configure processing and output settings
- ✅ Validate the complete configuration

### 4. Prepare Your Project

Create or navigate to your project directory with these files:

**Required Files:**
- `README.md` - Project description, technologies, and architecture
- `threats.md` - Structured threat statements

**Optional Files:**
- `architecture.*` - Architecture diagrams (PNG, SVG, Mermaid)
- `dataflow.*` - Data flow diagrams

**Example Project Structure:**
```
your-project/
├── README.md              # Project overview and tech stack
├── threats.md             # Threat statements
├── architecture.png       # System architecture diagram
└── dataflow.mmd          # Data flow in Mermaid format
```

### 5. Run Your First Analysis

```bash
# Navigate to your project directory
cd /path/to/your/project

# Basic analysis
tf analyze

# With verbose output
tf analyze --verbose

# Custom output directory
tf analyze --output ./security-analysis
```

### 6. Review Results

Check the generated files in your output directory (default: `./tf-output/`):

```
tf-output/
├── threat_analysis_summary.md    # Comprehensive analysis summary
├── attack_tree_T001.mmd          # Attack tree for threat T001
├── attack_tree_T002.mmd          # Attack tree for threat T002
└── threatforest.log              # Detailed execution log
```

### 7. Verify Everything Works

```bash
# Quick system health check
tf status

# Comprehensive validation
tf config validate --verbose

# View current configuration
tf config show --detailed
```

## 💡 Usage Examples

### Analysis Commands
```bash
# Basic analysis
tf analyze

# Analyze specific directory
tf analyze /path/to/project --output ./security-analysis

# Preview without execution
tf analyze --dry-run

# Detailed progress output
tf analyze --verbose

# Automation mode
tf analyze --non-interactive --auto-approve
```

### Configuration Commands
```bash
# View configuration
tf config show
tf config show --detailed

# Set configuration values
tf config set bedrock.region us-west-2
tf config set processing.severity_threshold medium

# Validate setup
tf config validate --verbose
tf config doctor
```

### Model Management
```bash
# List available models
tf config model --list

# Get recommendations
tf config model --recommend analysis

# Set specific model
tf config model --set anthropic.claude-3-sonnet-20240229-v1:0

# Test configuration
tf config model --set claude-3-haiku --test
```

### Logging and Debugging
```bash
# Global verbose logging
tf --verbose analyze

# Specific log level
tf --log-level DEBUG config validate

# Log to file
tf --log-file ./debug.log analyze
```

### Project Initialization
```bash
# Initialize new project
tf init

# With specific template
tf init --template web-app

# In custom directory
tf init ./my-project --template microservices
```

## 📁 Project Structure and Configuration

### Project Structure

ThreatForest is flexible with project structures but looks for these files:

```
your-project/
├── README.md                    # Project description and tech stack
├── threats.md                   # Structured threat statements
├── architecture.png             # System architecture (optional)
├── dataflow.mmd                 # Data flow diagrams (optional)
├── .tf/                         # ThreatForest configuration
│   └── config.yaml              # Project-specific settings
└── tf-output/                   # Generated analysis results
    ├── threat_analysis_summary.md
    ├── attack_tree_*.mmd
    └── threatforest.log
```

### Configuration Hierarchy

ThreatForest loads configuration from multiple sources in order of precedence:

1. **Command line arguments** (highest priority)
2. **Project config** (`.tf/config.yaml`)
3. **User config** (`~/.tf/config.yaml`)
4. **Environment variables** (`TF_*`, `AWS_*`)
5. **Built-in defaults** (lowest priority)

### Configuration Examples

**Project-level configuration** (`.tf/config.yaml`):
```yaml
bedrock:
  region: us-east-1
  model: anthropic.claude-3-sonnet-20240229-v1:0
  temperature: 0.7
  max_tokens: 4000

processing:
  severity_threshold: high
  max_concurrent_agents: 4
  timeout_seconds: 600

output:
  directory: ./tf-output
  format: mermaid
  include_summary: true

logging:
  level: INFO
  file: ./tf-output/threatforest.log
  include_console: true
```

**Environment variables**:
```bash
export TF_BEDROCK_REGION=us-west-2
export TF_BEDROCK_MODEL=anthropic.claude-3-haiku-20240307-v1:0
export TF_OUTPUT_DIRECTORY=./security-analysis
export TF_LOG_LEVEL=DEBUG
```

## 🔧 CLI Commands Reference

### Main Commands

| Command | Description | Example |
|---------|-------------|---------|
| `tf setup` | Interactive setup wizard | `tf setup --verbose` |
| `tf analyze` | Analyze project for threats | `tf analyze --verbose` |
| `tf status` | Show system health status | `tf status --check-models` |
| `tf init` | Initialize new project | `tf init --template web-app` |

### Configuration Commands

| Command | Description | Example |
|---------|-------------|---------|
| `tf config show` | Display current configuration | `tf config show --detailed` |
| `tf config validate` | Test configuration and connectivity | `tf config validate --verbose` |
| `tf config doctor` | Comprehensive system diagnostics | `tf config doctor --fix` |
| `tf config model` | Manage Bedrock models | `tf config model --list --region us-west-2` |
| `tf config set` | Update configuration values | `tf config set bedrock.region us-east-1` |

### Global Options

| Option | Description | Example |
|--------|-------------|---------|
| `--verbose, -v` | Enable verbose logging | `tf --verbose analyze` |
| `--log-level` | Set logging level | `tf --log-level DEBUG config validate` |
| `--log-file` | Log to specific file | `tf --log-file ./debug.log analyze` |

### Getting Help

```bash
# Main help with quick start guide
tf --help

# Detailed command help
tf analyze --help
tf config model --help

# Show comprehensive usage examples
tf analyze --examples
```

## 🛠️ System Requirements

### Minimum Requirements
- **Operating System**: Linux, macOS, or Windows 10+
- **Python**: 3.9 or higher
- **Memory**: 2GB RAM available
- **Storage**: 1GB free disk space
- **Network**: Stable internet connection for AWS API calls

### Recommended Specifications
- **Python**: 3.11+ for optimal performance
- **Memory**: 4GB+ RAM for large projects
- **Storage**: 2GB+ for caching and logs
- **AWS Region**: Choose region closest to your location for best performance

### AWS Requirements
- **AWS Account**: With Bedrock service enabled
- **IAM Permissions**: `bedrock:*` actions (or specific permissions)
- **Supported Regions**: us-east-1, us-west-2, eu-west-1, ap-southeast-1, etc.
- **Model Access**: Request access to desired Bedrock models if needed

## 📄 Supported File Formats

### Input Files (Context Analysis)
- **Documentation**: `README.md`, `README.txt`, `*.md`
- **Architecture**: `architecture.*`, `arch.*`, `*.png`, `*.svg`, `*.mmd`
- **Data Flow**: `dataflow.*`, `dfd.*`, flow diagrams
- **Threats**: `threats.md`, `threat-*.md`, `security-*.json`
- **Configuration**: `*.yaml`, `*.json`, `*.toml`

### Output Formats
- **Attack Trees**: Mermaid (`.mmd`) format for visualization
- **Reports**: Markdown (`.md`) with structured analysis
- **Logs**: Structured logging in text format
- **Configuration**: YAML format for settings

## 🚨 Troubleshooting

### Quick Diagnostics

```bash
# Check system status
tf status

# Run comprehensive diagnostics
tf config doctor --verbose

# Validate configuration
tf config validate
```

### Common Issues

| Issue | Solution |
|-------|----------|
| **Package/Dependency Conflicts** | Use virtual environment: `python -m venv venv && source venv/bin/activate` |
| **AWS Credentials Not Found** | Run `aws configure` or set environment variables |
| **Bedrock Access Denied** | Check IAM permissions for `bedrock:*` actions |
| **Model Not Available** | Use `tf config model --list` to see available models |
| **Configuration Errors** | Run `tf setup --force` to reconfigure |
| **Analysis Fails** | Use `tf analyze --verbose --log-file debug.log` |
| **Command Not Found** | Ensure virtual environment is activated and ThreatForest is installed |

### Getting Help

- **Built-in Help**: `tf COMMAND --help` for detailed guidance
- **System Diagnostics**: `tf config doctor --verbose` for troubleshooting
- **Verbose Logging**: Add `--verbose` to any command for detailed output
- **Examples**: `tf analyze --examples` for usage examples

## 📚 Documentation and Examples

### Quick References
- **[CLI Command Reference](#-cli-commands-reference)** - Complete command documentation
- **[Configuration Guide](#-project-structure-and-configuration)** - Setup and configuration options
- **[Troubleshooting Guide](#-troubleshooting)** - Common issues and solutions
- **[Virtual Environments Guide](docs/VIRTUAL_ENVIRONMENTS.md)** - Detailed virtual environment setup and management

### Example Projects
- **[GenAI Chatbot](genai-chatbot-example/)** - AI chatbot security analysis
- **Web Application** - OWASP Top 10 threat analysis
- **Microservices** - Container and API security
- **IoT Platform** - Device and communication security

### Advanced Topics
- **Model Selection**: Choosing the right Bedrock model for your use case
- **Configuration Management**: Multi-environment setup and best practices
- **CI/CD Integration**: Automated security analysis in pipelines
- **Custom Templates**: Creating project-specific threat templates
- **Virtual Environment Management**: Isolated Python environments for development

## 🤝 Contributing

We welcome contributions! Here's how to get started:

### Development Setup

```bash
# Fork and clone the repository
git clone https://github.com/your-username/threatforest.git
cd threatforest

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in development mode
pip install -e ".[dev]"

# Verify installation
tf --version
python -m pytest tests/ -v
```

### Development Workflow

1. **Fork** the repository on GitHub
2. **Create** a feature branch: `git checkout -b feature/amazing-feature`
3. **Make** your changes with tests
4. **Test** your changes: `python -m pytest tests/ -v`
5. **Lint** your code: `black threatforest/ && flake8 threatforest/`
6. **Commit** your changes: `git commit -m 'Add amazing feature'`
7. **Push** to your fork: `git push origin feature/amazing-feature`
8. **Create** a Pull Request

### Testing

```bash
# Run all tests
python -m pytest tests/ -v

# Run specific test categories
python -m pytest tests/test_cli.py -v
python -m pytest tests/test_config.py -v

# Run with coverage
python -m pytest tests/ --cov=threatforest --cov-report=html
```

### Code Quality

```bash
# Format code
black threatforest/

# Check style
flake8 threatforest/

# Type checking
mypy threatforest/

# Security scanning
bandit -r threatforest/
```

## 📋 Recent Updates

### Enhanced Model Provider Integration
- ✅ **Advanced Bedrock Integration**: Intelligent model selection and validation
- ✅ **Real-time Model Discovery**: Automatic detection of available models by region
- ✅ **Model Recommendations**: AI-powered suggestions based on use case
- ✅ **Configuration Validation**: Comprehensive testing of AWS connectivity and permissions
- ✅ **Enhanced Error Handling**: Detailed error messages with troubleshooting guidance

### Improved CLI Experience
- ✅ **Interactive Setup Wizard**: Guided configuration with automatic detection
- ✅ **Comprehensive Help System**: Detailed help text with examples and troubleshooting
- ✅ **Advanced Logging**: Flexible logging levels and file output options
- ✅ **System Diagnostics**: Built-in health checks and connectivity testing
- ✅ **Configuration Management**: Multi-source configuration with validation

### Enhanced User Experience
- ✅ **Project Templates**: Pre-configured templates for different project types
- ✅ **Verbose Progress Reporting**: Detailed progress indicators and status updates
- ✅ **Automated Troubleshooting**: Self-diagnostic capabilities with fix suggestions
- ✅ **CI/CD Integration**: Non-interactive modes for automation pipelines

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support and Community

### Self-Service Resources
- **Built-in Help**: `tf --help` and `tf COMMAND --help` for comprehensive guidance
- **System Diagnostics**: `tf config doctor --verbose` for troubleshooting
- **Configuration Validation**: `tf config validate` to test your setup
- **Status Monitoring**: `tf status` for quick health checks

### Community Support
- **[GitHub Issues](https://github.com/threatforest/threatforest/issues)** - Bug reports and feature requests
- **[GitHub Discussions](https://github.com/threatforest/threatforest/discussions)** - Community Q&A and support
- **[Documentation](docs/)** - Comprehensive guides and API reference
- **[Examples](examples/)** - Working examples and tutorials

### Professional Support
For enterprise users and professional support options, please contact the ThreatForest team.

---

**🌳 ThreatForest** - Automated AI-powered threat analysis and attack tree generation.

*Built with ❤️ for the security community*