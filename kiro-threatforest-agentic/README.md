# ThreatForest

ThreatForest (TF) is an agentic AI application that automatically generates attack trees from threat statements using the Strand framework. The application analyzes application context files, extracts key security information, and produces Mermaid-formatted attack trees enhanced with STIX-formatted threat intelligence from the AAF bundle.

## Features

- **Automated Context Analysis**: Scans directories for README files, architecture diagrams, and threat statements
- **AI-Powered Information Extraction**: Uses Amazon Bedrock to extract security-relevant information
- **Attack Tree Generation**: Creates Mermaid-formatted attack trees for high-severity threats
- **STIX Enhancement**: Integrates AWS Threat Technique Catalog (TTC) mappings
- **Multi-Agent Architecture**: Built on the Strand framework for scalable processing

## Installation

### Prerequisites

Before installing ThreatForest, ensure you have:

- Python 3.9 or higher
- AWS account with Amazon Bedrock access
- AWS CLI configured or AWS credentials available
- At least 2GB of available RAM

### From PyPI (when available)
```bash
pip install threatforest
```

### From Source
```bash
git clone https://github.com/threatforest/threatforest.git
cd threatforest
pip install -e .
```

### Development Installation
```bash
git clone https://github.com/threatforest/threatforest.git
cd threatforest
pip install -e ".[dev]"
```

### Docker Installation
```bash
# Pull the image
docker pull threatforest/tf:latest

# Run with mounted directory
docker run -v $(pwd):/workspace -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY threatforest/tf analyze /workspace
```

## Quick Start

### 1. Set up AWS Credentials

Choose one of the following methods:

**Option A: Environment Variables**
```bash
export AWS_ACCESS_KEY_ID=your_key
export AWS_SECRET_ACCESS_KEY=your_secret
export AWS_DEFAULT_REGION=us-east-1
```

**Option B: AWS CLI Configuration**
```bash
aws configure
```

**Option C: IAM Roles (for EC2/ECS)**
No additional configuration needed if running on AWS with appropriate IAM roles.

### 2. Prepare Your Project Directory

ThreatForest looks for specific files in your project directory:

- `README.md` - Project description and architecture information
- `threats.md` - Threat statements in the required format
- `dataflow.mmd` or similar - Data flow diagrams (optional)
- Architecture diagrams (PNG, SVG, or Mermaid files)

### 3. Run ThreatForest

```bash
# Navigate to your project directory
cd /path/to/your/project

# Run analysis
threatforest analyze
# or use the short alias
tf analyze
```

### 4. Review Results

Check the `tf-output/` directory for:
- `summary.md` - Analysis summary and file listings
- `extracted_information.md` - Key information extracted from context files
- `attack_tree_*.mmd` - Mermaid attack tree files for each high-severity threat
- `enhanced_attack_tree_*.mmd` - Attack trees with STIX/TTC enhancements

## Usage Examples

### Basic Analysis
```bash
# Analyze current directory
tf analyze

# Analyze specific directory
tf analyze /path/to/project

# Specify custom output directory
tf analyze --output ./security-analysis

# Use specific Bedrock region
tf analyze --region us-west-2
```

### Advanced Configuration
```bash
# Set default Bedrock region
tf config --set bedrock.region us-west-2

# Set severity threshold (only process high-severity threats)
tf config --set processing.severity_threshold high

# Configure custom file patterns
tf config --set files.threat_patterns "threat*.md,security*.json"

# Set custom AAF bundle path
tf config --set ttc.aaf_bundle_path ./custom-aaf-bundle.json

# View current configuration
tf config --show

# Reset configuration to defaults
tf config --reset
```

### Interactive Mode
```bash
# Run with interactive prompts for validation
tf analyze --interactive

# Skip user validation (batch mode)
tf analyze --no-validation
```

### Debugging and Logging
```bash
# Enable verbose logging
tf analyze --verbose

# Enable debug mode
tf analyze --debug

# Save logs to file
tf analyze --log-file ./tf-analysis.log
```

## Project Structure Requirements

ThreatForest expects your project to follow this structure:

```
your-project/
├── README.md                    # Project description (required)
├── threats.md                   # Threat statements (required)
├── dataflow.mmd                 # Data flow diagram (optional)
├── architecture.png             # Architecture diagram (optional)
├── .tf/                         # ThreatForest configuration (auto-created)
│   └── config.yaml
└── tf-output/                   # Generated outputs (auto-created)
    ├── summary.md
    ├── extracted_information.md
    └── attack_tree_*.mmd
```

## System Requirements

- **Operating System**: Linux, macOS, or Windows
- **Python**: 3.9 or higher
- **Memory**: Minimum 2GB RAM (4GB recommended for large projects)
- **Storage**: 1GB free space for models and cache
- **Network**: Internet access for Amazon Bedrock API calls
- **AWS**: Valid AWS credentials with Bedrock permissions

## Supported File Formats

### Context Files
- **README files**: `README.md`, `README.txt`, `readme.*`
- **Architecture diagrams**: `*.png`, `*.svg`, `*.mmd` (with architecture keywords)
- **Data flow diagrams**: `dataflow.*`, `dfd.*`, files containing "data flow"
- **Threat statements**: `threats.md`, `threat-*.json`

### Output Formats
- **Attack Trees**: Mermaid (`.mmd`) format
- **Reports**: Markdown (`.md`) format
- **Configuration**: YAML (`.yaml`) format

## Documentation

### Core Documentation
- **[API Reference](docs/API.md)** - Complete API documentation for all classes and methods
- **[Troubleshooting Guide](TROUBLESHOOTING.md)** - Solutions for common issues and debugging
- **[Examples](examples/README.md)** - Sample projects and usage examples

### Example Projects
- **[GenAI Chatbot](genai-chatbot-example/)** - AI chatbot with comprehensive threat analysis
- **[E-commerce Platform](examples/ecommerce-platform/)** - Multi-tier web application security
- **[IoT Device Management](examples/iot-device-management/)** - IoT platform security threats
- **[Microservices API](examples/microservices-api/)** - Container and API security

### Configuration Files
- **[Configuration Schema](docs/configuration.md)** - Complete configuration options
- **[File Patterns](docs/file-patterns.md)** - Supported file types and naming conventions

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup

```bash
# Clone and setup development environment
git clone https://github.com/threatforest/threatforest.git
cd threatforest
pip install -e ".[dev]"

# Run tests
python -m pytest tests/

# Run linting
black threatforest/
flake8 threatforest/
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- **[Troubleshooting Guide](TROUBLESHOOTING.md)** - Self-service debugging and solutions
- **[API Documentation](docs/API.md)** - Complete technical reference
- **[Examples](examples/)** - Working examples and tutorials
- **[GitHub Issues](https://github.com/threatforest/threatforest/issues)** - Bug reports and feature requests
- **[GitHub Discussions](https://github.com/threatforest/threatforest/discussions)** - Community support and questions