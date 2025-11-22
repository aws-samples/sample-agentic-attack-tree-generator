# 🌳 ThreatForest Interactive UI

ThreatForest provides a React-based terminal UI for automated threat modeling and attack tree generation with three workflow options that can be run independently or sequentially.

## 🚀 Quick Start

### Prerequisites
- **AWS Account** with Bedrock access (us-east-1 region)
- **AWS CLI** configured with appropriate credentials
- **Python 3.8+** installed

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

### Step 2: Prepare Your Project

**Before running the wizard**, prepare your project directory with threat model files:

#### Option A: Use ThreatComposer (Recommended)
1. Visit https://awslabs.github.io/threat-composer/
2. Create a new workspace with your application details
3. Add threat statements with High/Medium/Low priorities
4. Export workspace as `.tc` file to your project directory

#### Option B: Create Custom Threat Model
Create a `threats.json` file in your project directory:
```json
{
  "application_info": {
    "name": "My Application",
    "technologies": ["AWS", "React", "Node.js"]
  },
  "threats": [
    {"description": "SQL injection attack", "priority": "high"}
  ]
}
```

### Step 3: Build and Run ThreatForest

```bash
# Build the React UI (first time only)
cd ui
npm install
npm run build:cli
cd ..

# Run ThreatForest
python threatforest.py
```

### Step 4: Follow the Interactive Steps

The UI will guide you through:
1. **Mode Selection** - Choose workflow option (Full/Enrich/Mitigate)
2. **Configuration** - AWS profile, Bedrock model, project path
3. **Analysis** - Run selected workflow with progress tracking
4. **Continue Options** - After Option 1, optionally continue to Options 2 & 3

## 📋 Expected Workflow

### Typical Session
```bash
$ source venv/bin/activate
$ python threatforest.py

🌳 Welcome to ThreatForest!

Select Mode:
1. 🌳 Full Analysis - Generate attack trees from project
2. 🎯 Enrich - Add TTC technique mappings to existing attack trees
3. 🛡️ Mitigate - Add mitigation recommendations to enriched trees

> 1

[Configuration screen...]
[Analysis runs...]

✅ Option 1 complete! Continue with TTC Enrichment (Option 2)?
> Yes

[Option 2 runs...]

✅ Option 2 complete! Continue with Mitigation Mapping (Option 3)?
> Yes

[Option 3 runs...]

✅ Complete workflow finished
📁 Output Location: /path/to/project/threatforest/mitigated
```

## 📁 Recommended Context Files

ThreatForest is flexible and works with various input combinations. **Threat models are recommended but not required** - ThreatForest can generate threats using AI analysis of your documentation and diagrams.

### 🎯 **Threat Models (Recommended, Not Required)**

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

### 📖 **Minimal Required Files (AI Will Generate Threats)**

#### Architecture Diagrams ⭐ **HIGHLY VALUABLE**
- **Files**: `*.png`, `*.pdf`, `*.jpg`, `*.jpeg`, `*.drawio`, `*.mmd`, `*.puml`
- **Should include**: System components, data flows, network topology
- **AI Analysis**: ThreatForest will analyze diagrams to identify attack surfaces

#### Documentation Files
- **Files**: Any `.md` files (doesn't have to be README), `*.txt`
- **Should include**: 
  - Application description and purpose
  - Technology stack and dependencies
  - Architecture overview
  - Any security considerations

### 🏗️ **Architecture Diagrams (Expanded Support)**

#### Supported Formats
- **Images**: `*.png`, `*.pdf`, `*.jpg`, `*.jpeg` (any architecture diagrams)
- **Mermaid**: `architecture.mmd`, `dataflow.mmd`
- **Draw.io**: `system-diagram.drawio`
- **PlantUML**: `architecture.puml`

#### What ThreatForest Extracts from Diagrams
- System components and services
- Data flow patterns
- Network boundaries and trust zones
- External dependencies
- Potential attack surfaces

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

## 🎯 Workflow Options

ThreatForest offers three workflow options that can be run independently or sequentially:

### Option 1: 🌳 Full Analysis
Generate attack trees from your project:
- Analyzes project context (documentation, diagrams, threat models)
- Extracts threats using AI
- Generates attack trees for high-priority threats
- **Output**: `project/threatforest/attack_trees/`

### Option 2: 🎯 TTC Enrichment
Add MITRE ATT&CK TTC technique mappings to existing attack trees:
- Reads attack trees from Option 1 output
- Maps attack paths to TTC techniques
- Enriches trees with technique IDs and descriptions
- **Input**: `project/threatforest/attack_trees/`
- **Output**: `project/threatforest/enriched/`

### Option 3: 🛡️ Mitigation Mapping
Add mitigation recommendations to enriched trees:
- Reads enriched attack trees from Option 2 output
- Adds mitigation strategies for each TTC technique
- Provides actionable security recommendations
- **Input**: `project/threatforest/enriched/`
- **Output**: `project/threatforest/mitigated/`

### Sequential Workflow
After completing Option 1, you'll be prompted to continue with Option 2, then Option 3. You can:
- Run all three sequentially for complete analysis
- Stop after any option to review intermediate results
- Run options independently by selecting them from the main menu

## 📊 File Discovery Examples

### Optimal Project Structure (With Threat Models)
```
my-application/
├── README.md                                    # Application overview
├── ThreatComposer_Workspace_MyApp.tc           # Threat model (optimal)
├── architecture.png                            # System diagram
├── docs/
│   ├── security-requirements.md               # Security context
│   └── api-documentation.md                   # Technical details
└── diagrams/
    ├── data-flow.drawio                       # Data flow diagram
    └── deployment-architecture.pdf            # Deployment view
```

### Minimal Project Structure (AI Will Generate Threats)
```
my-application/
├── overview.md                                 # Any markdown with app info
├── system-architecture.png                    # Architecture diagram
└── network-diagram.pdf                        # Network layout
```

### What ThreatForest Discovers

#### With Threat Models:
```
🎯 Found 1 threat model files:
   • ThreatComposer_Workspace_MyApp.tc (ThreatComposer)
📖 Found 1 README files
🏗️ Found 3 diagram files
✅ Threat models found - analysis will be comprehensive!
```

#### Without Threat Models (AI Generation):
```
🤖 No threat models found - will generate threats using AI analysis
📋 ThreatForest will analyze your diagrams and documentation to create threat models
📖 Found 1 documentation files
🏗️ Found 2 diagram files
🤖 AI will generate threats based on available context
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

## 🔗 IDE Integration

### Kiro IDE Hook Integration

ThreatForest integrates with [Kiro IDE](https://kiro.dev) to automatically trigger threat analysis when ThreatComposer files are saved.

#### Quick Setup

1. **Configure Kiro Hook** in Kiro IDE:
   - Navigate to **Agent Hooks** section
   - Create new hook with pattern `**/*.tc.json`
   - Set command: `/path/to/ThreatForest-internal/src/modules/utils/kiro_wrapper.sh {file_path}`

2. **Enable in config.yaml**:
```yaml
kiro_integration:
  enabled: true
  auto_run_on_save: true
```

3. **Use it**: Edit and save any `.tc.json` file - ThreatForest runs automatically!

#### Benefits
- ✅ Automatic analysis on every save
- ✅ Immediate feedback on threat models
- ✅ No manual CLI invocation needed
- ✅ Results in `{project_dir}/threatforest/attack_trees/`

**📖 Full Documentation**: See [docs/KIRO_INTEGRATION.md](docs/KIRO_INTEGRATION.md) for complete setup guide, troubleshooting, and advanced configuration.

#### Manual Testing
```bash
# Test the hook directly
./src/modules/utils/kiro_wrapper.sh /path/to/your/threats.tc.json

# Or use Python handler
python3 src/modules/utils/kiro_hook.py /path/to/your/threats.tc.json
```

## 🔧 Troubleshooting

### Common Issues

#### "No threat models found"
```bash
⚠️  No threat model files found
💡 ThreatForest works best with:
   • ThreatComposer workspace files (.tc)
   • Threat statement files (threat.json, security.yaml)
   • README files with project description
```
**Solution**: Add a ThreatComposer export or create `threats.json` in your project directory

#### "Bedrock access failed"
```bash
❌ Bedrock access failed: UnauthorizedOperation
💡 Make sure you have Bedrock permissions in us-east-1 region
```
**Solution**: 
1. Check AWS credentials: `aws sts get-caller-identity`
2. Verify Bedrock permissions in us-east-1
3. Request Bedrock model access in AWS Console

#### "externally-managed-environment"
```bash
error: externally-managed-environment
```
**Solution**: Always use virtual environment as shown in setup steps

#### Virtual Environment Issues
```bash
# If venv activation fails, recreate it:
rm -rf venv
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Getting Help
- Check AWS credentials: `aws configure list`
- Test Bedrock access: `aws bedrock list-foundation-models --region us-east-1`
- Validate threat files: `./threatforest/tools/threat_jq.sh your-file.tc summary`

## 🌳 Ready to Start?

With your context files prepared, run the wizard:

```bash
source venv/bin/activate
python threatforest.py
```

The enhanced ThreatForest will automatically discover and process your threat models, creating comprehensive attack trees and security reports!
