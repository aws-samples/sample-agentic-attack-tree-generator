# 🌳 ThreatForest Interactive Wizard

The ThreatForest Wizard provides a user-friendly, step-by-step interface for running automated threat modeling and attack tree generation.

## 🚀 Quick Start

```bash
# Navigate to the ThreatForest directory
cd threatforest-strands

# Activate virtual environment
source ../venv/bin/activate

# Run the interactive wizard
python threatforest_wizard.py
```

## 🎯 What the Wizard Does

The wizard guides you through 5 simple steps:

### 📋 Step 1: AWS Configuration
- **Checks existing AWS credentials**
- **Lists available AWS profiles**
- **Tests Bedrock access permissions**
- **Provides setup guidance if needed**

### 🤖 Step 2: AI Model Selection
Choose from 4 Bedrock models:
- **Claude Sonnet 4** ⭐ (Recommended - Best balance)
- **Claude Opus 4.1** 🚀 (Most powerful)
- **Claude 3.5 Sonnet** ⚡ (Fast)
- **Claude 3 Haiku** 💨 (Fastest)

### 📁 Step 3: Project Path Selection
- **Scans your project directory**
- **Identifies README files, threat statements, diagrams**
- **Provides file count preview**
- **Warns about missing files**

### 📋 Step 4: Configuration Review
- **Shows all selected settings**
- **Allows final confirmation**
- **Option to restart if needed**

### 🚀 Step 5: Analysis Execution
Runs the complete ThreatForest workflow:
1. **Context Analysis** - Scans project files
2. **Information Extraction** - AI analysis with Bedrock
3. **Attack Tree Generation** - Creates Mermaid diagrams
4. **TTC Mapping** - Maps to MITRE ATT&CK
5. **Report Generation** - Creates comprehensive reports

## 📊 Example Output

```
🎉 ThreatForest Analysis Complete!

📊 Results Summary:
• Application: Sample GenAI Chatbot
• Technologies: 18 identified
• Threats analyzed: 9
• Attack trees generated: 5
• MITRE ATT&CK mappings: 43

📁 Output Directory: ./threatforest_output/sample_genai_chatbot

📄 Generated Files:
• threatforest_analysis_report.md
• ttc_mapping_report.md
• threatforest_data.json
• attack_tree_T3.md
• attack_tree_T7.md
```

## 🔧 Prerequisites

### Required
- **Python 3.9+**
- **AWS credentials configured**
- **Bedrock access in us-east-1**

### AWS Setup Options
```bash
# Option 1: AWS CLI
aws configure

# Option 2: Environment variables
export AWS_ACCESS_KEY_ID=your_key
export AWS_SECRET_ACCESS_KEY=your_secret

# Option 3: IAM roles (if on EC2)
# Automatically detected
```

### Bedrock Permissions
Ensure your AWS account has access to:
- `bedrock:InvokeModel`
- `bedrock:ListFoundationModels`

## 📁 Project Structure Requirements

ThreatForest works best with projects containing:

### Essential Files
- **README.md** - Project description and technologies
- **threats.md** or **security.md** - Threat statements

### Optional Files
- **Architecture diagrams** (.mmd, .drawio)
- **Documentation files**
- **Configuration files**

### Example Project Structure
```
my-project/
├── README.md                 # ✅ Project overview
├── threats.md               # ✅ Threat statements
├── architecture.mmd         # ✅ System diagram
├── docs/
│   └── security.md          # ✅ Security documentation
└── src/
    └── ...                  # Application code
```

## 🎨 Features

### User-Friendly Interface
- **Rich console output** with colors and formatting
- **Progress indicators** for long-running operations
- **Clear error messages** with helpful suggestions
- **Interactive prompts** with sensible defaults

### Smart Configuration
- **Auto-detects AWS profiles**
- **Validates file paths**
- **Previews project files**
- **Tests Bedrock connectivity**

### Comprehensive Analysis
- **AI-powered project analysis**
- **Cybersecurity expert knowledge**
- **MITRE ATT&CK integration**
- **Professional reporting**

## 🚨 Troubleshooting

### Common Issues

**❌ "AWS credentials not found"**
```bash
# Solution: Configure AWS credentials
aws configure
```

**❌ "Bedrock access failed"**
```bash
# Solution: Check permissions and region
aws sts get-caller-identity
aws bedrock list-foundation-models --region us-east-1
```

**❌ "No README files found"**
- Add a README.md with project description
- Include technology stack information
- Describe the application architecture

**❌ "No threat files found"**
- Create threats.md with threat statements
- Use format: `T1: [High] Threat description`
- Include multiple severity levels

### Getting Help
- Check AWS credentials: `aws sts get-caller-identity`
- Test Bedrock access: `aws bedrock list-foundation-models --region us-east-1`
- Verify Python environment: `python --version`

## 🎯 Tips for Best Results

### Project Documentation
- **Detailed README** with technology stack
- **Clear threat statements** with severity levels
- **Architecture diagrams** showing system components

### AWS Configuration
- **Use appropriate regions** (us-east-1 for Bedrock)
- **Ensure sufficient permissions** for Bedrock models
- **Consider cost implications** of AI model usage

### Analysis Scope
- **Start with high-severity threats** (automatically filtered)
- **Review generated attack trees** for accuracy
- **Validate MITRE ATT&CK mappings** against your environment

---

🌳 **Ready to secure your applications with AI-powered threat modeling!**
