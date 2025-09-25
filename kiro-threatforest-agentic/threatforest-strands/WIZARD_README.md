# 🌳 ThreatForest Interactive Wizard

The ThreatForest Wizard provides a user-friendly, step-by-step interface for running automated threat modeling and attack tree generation with enhanced support for various threat model formats.

## 🚀 Quick Start

### Step 1: Setup Virtual Environment

```bash
# Navigate to the ThreatForest directory
cd threatforest-strands

# Create virtual environment (required to avoid externally-managed-environment error)
python3 -m venv venv

# Activate virtual environment
# On macOS/Linux:
source venv/bin/activate
# On Windows:
# venv\Scripts\activate

# Verify you're in the virtual environment (should show venv path)
which python

# Install dependencies
pip install -r requirements.txt
```

### Step 2: Run the Wizard

```bash
# Make sure virtual environment is activated (you should see (venv) in your prompt)
python threatforest_wizard.py
```

## 📁 Recommended Context Files

ThreatForest works best with structured threat information. Here's what to include in your project directory:

### 🎯 **Threat Models (Highest Priority)**

#### ThreatComposer Workspace Files ⭐ **RECOMMENDED**
- **Create at**: https://awslabs.github.io/threat-composer/
- **File**: `*.tc` or `*ThreatComposer*.json`
- **Best for**: Comprehensive threat modeling with priorities
- **Example**: `ThreatComposer_Workspace_MyApp.tc`
- **Contains**: Threat statements, priorities (High/Medium/Low), application context

**How to create:**
1. Visit https://awslabs.github.io/threat-composer/
2. Create new workspace with your application details
3. Add threat statements with High/Medium/Low priorities
4. Export workspace as `.tc` file
5. Place in your project directory for ThreatForest analysis

#### Generic Threat Model Files
- **Files**: `threats.json`, `security.yaml`, `risk-assessment.json`
- **Format**: JSON/YAML with threat statements and severity levels
- **Example**:
```json
{
  "application_info": {"name": "My App", "technologies": ["AWS", "React"]},
  "threats": [
    {"description": "SQL injection", "severity": "high", "category": "injection"}
  ]
}
```

### 📖 **Application Documentation**

#### README Files
- **Files**: `README.md`, `README.txt`
- **Should include**: 
  - Application description and purpose
  - Technology stack and dependencies
  - Architecture overview
  - Security considerations

#### Architecture Documentation
- **Files**: `architecture.md`, `system-design.md`
- **Diagrams**: `*.mmd` (Mermaid), `*.drawio`, `*.puml` (PlantUML)
- **Should include**: System components, data flows, trust boundaries

### 🏗️ **Architecture Diagrams**

#### Supported Formats
- **Mermaid**: `architecture.mmd`, `dataflow.mmd`
- **Draw.io**: `system-diagram.drawio`
- **PlantUML**: `architecture.puml`
- **Images**: `*.png`, `*.jpg`, `*.svg` (with descriptive names)

#### Recommended Diagram Types
- System architecture diagrams
- Data flow diagrams (DFD)
- Network topology diagrams
- Deployment diagrams

### 📄 **Additional Context Files**

#### Security Documentation
- `security-requirements.md`
- `compliance-checklist.md`
- `penetration-test-results.md`

#### Technical Specifications
- `api-documentation.md`
- `database-schema.md`
- `deployment-guide.md`

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

### 📁 Step 3: Enhanced Project Path Selection
- **Smart file discovery** with format detection
- **Threat model prioritization** (ThreatComposer, JSON, YAML)
- **File preview** showing discovered threat models and formats
- **Validation guidance** for optimal analysis

### 📋 Step 4: Configuration Review
- **Summary of all settings**
- **File discovery results**
- **Threat model preview**
- **Final confirmation**

### 🚀 Step 5: Analysis Execution
- **Step 1**: Enhanced context analysis with flexible file handling
- **Step 2**: AI-powered information extraction
- **Step 3**: Attack tree generation for high-priority threats
- **Step 4**: MITRE ATT&CK technique mapping
- **Step 5**: Comprehensive report generation

## 📊 File Discovery Examples

### Optimal Project Structure
```
my-application/
├── README.md                                    # Application overview
├── ThreatComposer_Workspace_MyApp.tc           # Threat model (priority)
├── architecture.mmd                            # System diagram
├── docs/
│   ├── security-requirements.md               # Security context
│   └── api-documentation.md                   # Technical details
└── diagrams/
    ├── data-flow.drawio                       # Data flow diagram
    └── deployment-architecture.png            # Deployment view
```

### What ThreatForest Discovers
```
🎯 Found 1 threat model files:
   • ThreatComposer_Workspace_MyApp.tc (ThreatComposer)
📖 Found 1 README files
🏗️ Found 3 diagram files
✅ Threat models found - analysis will be comprehensive!
```

## 💡 Pro Tips

### For Best Results
1. **🌟 Use ThreatComposer**: Create workspace at https://awslabs.github.io/threat-composer/ and export as `.tc` file
2. **Include priorities**: Ensure threats have High/Medium/Low priority assignments
3. **Add context**: Include README with technology stack and architecture overview
4. **Use diagrams**: Visual representations help AI understand system boundaries

### File Naming Conventions
- Use descriptive names: `ecommerce-threats.json` vs `threats.json`
- Include format hints: `ThreatComposer_Workspace_*.tc`
- Group by category: `security/`, `architecture/`, `docs/`

### Common Issues
- **No threat models found**: Add ThreatComposer export or create `threats.json`
- **Limited analysis**: Include README with application description
- **Missing priorities**: Ensure threat statements have severity/priority levels

## 🔧 Advanced Usage

### Recommended: Use ThreatComposer
For the best ThreatForest experience, create your threat model using AWS ThreatComposer:

1. **Visit**: https://awslabs.github.io/threat-composer/
2. **Create workspace** with your application information
3. **Add threat statements** with proper priorities (High/Medium/Low)
4. **Export workspace** as `.tc` file
5. **Use with ThreatForest** for comprehensive analysis

### Custom Threat Model Format (Alternative)
If you prefer JSON format, use this structure:
```json
{
  "application_info": {
    "name": "My Application",
    "description": "E-commerce platform",
    "technologies": ["Node.js", "PostgreSQL", "AWS"]
  },
  "threats": [
    {
      "id": "T001",
      "statement": "Attacker could perform SQL injection",
      "priority": "high",
      "category": "injection",
      "impact": "data breach",
      "mitigation": "Use parameterized queries"
    }
  ]
}
```

### Command Line File Testing
```bash
# Test threat file extraction
./threatforest/tools/threat_jq.sh your-threats.tc summary

# Preview high priority threats
./threatforest/tools/threat_jq.sh your-threats.tc high

# Get structured data for processing
./threatforest/tools/threat_jq.sh your-threats.tc extract
```

## 🌳 Ready to Start?

With your context files prepared, run the wizard:

```bash
source venv/bin/activate
python threatforest_wizard.py
```

The enhanced ThreatForest will automatically discover and process your threat models, creating comprehensive attack trees and security reports!
