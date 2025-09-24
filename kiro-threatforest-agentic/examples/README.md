# ThreatForest Examples

This directory contains example projects that demonstrate how to use ThreatForest for automated threat modeling and attack tree generation.

## Available Examples

### 1. GenAI Chatbot Example (`genai-chatbot-example/`)
A comprehensive example of a GenAI chatbot application with:
- Complete architecture documentation
- Data flow diagrams
- Comprehensive threat statements
- Expected ThreatForest outputs

### 2. E-commerce Platform (`ecommerce-platform/`)
An example e-commerce application demonstrating:
- Multi-tier architecture threats
- Payment processing security concerns
- User data protection requirements

### 3. IoT Device Management (`iot-device-management/`)
An IoT platform example showing:
- Device authentication threats
- Network communication security
- Data collection and privacy concerns

### 4. Microservices API (`microservices-api/`)
A microservices architecture example featuring:
- Service-to-service communication threats
- API gateway security concerns
- Container and orchestration threats

## How to Use Examples

### 1. Navigate to Example Directory
```bash
cd examples/genai-chatbot-example/
```

### 2. Run ThreatForest Analysis
```bash
tf analyze
```

### 3. Review Generated Outputs
```bash
ls tf-output/
cat tf-output/summary.md
```

### 4. View Attack Trees
Open the generated `.mmd` files in a Mermaid viewer:
- [Mermaid Live Editor](https://mermaid.live/)
- VS Code with Mermaid extension
- GitHub (renders Mermaid automatically)

## Example File Structure

Each example follows this structure:
```
example-name/
├── README.md                    # Project description and architecture
├── threats.md                   # Threat statements
├── dataflow.mmd                 # Data flow diagram (optional)
├── architecture.png             # Architecture diagram (optional)
├── expected-outputs/            # Expected ThreatForest outputs
│   ├── summary.md
│   ├── extracted_information.md
│   └── attack_tree_*.mmd
└── .tf/                         # Example configuration
    └── config.yaml
```

## Creating Your Own Example

### 1. Create Directory Structure
```bash
mkdir my-example
cd my-example
```

### 2. Create Required Files

**README.md** - Project description:
```markdown
# My Application

## Architecture
Describe your application architecture, technologies used, and key components.

## Security Objectives
- Confidentiality: Protect user data
- Integrity: Ensure data accuracy
- Availability: Maintain service uptime
```

**threats.md** - Threat statements:
```markdown
## Threat 1 - Data Breach
[High]
An external threat actor who gains unauthorized access to the database can extract sensitive user information, which leads to data exfiltration, resulting in reduced confidentiality of user personal data

## Threat 2 - Service Disruption  
[High]
A malicious actor who can overwhelm the API endpoints can cause service unavailability, which leads to denial of service, resulting in reduced availability of the application
```

### 3. Run Analysis
```bash
tf analyze
```

### 4. Validate Results
- Check that attack trees are generated for high-severity threats
- Verify Mermaid syntax is valid
- Ensure extracted information is accurate

## Best Practices for Examples

### Threat Statement Format
- Use clear, specific threat descriptions
- Include threat actor, attack vector, and impact
- Mark severity levels appropriately: `[High]`, `[Medium]`, `[Low]`
- Follow the pattern: "Actor who can X can do Y, which leads to Z, resulting in W"

### README Content
- Describe the application purpose and architecture
- List key technologies and frameworks
- Identify security objectives (CIA triad)
- Include relevant compliance requirements

### File Organization
- Keep files focused and concise
- Use descriptive filenames
- Include both required and optional files
- Provide clear documentation

## Testing Examples

### Automated Testing
```bash
# Test all examples
for example in examples/*/; do
    echo "Testing $example"
    cd "$example"
    tf analyze --no-validation
    cd ..
done
```

### Manual Validation
1. **Check file detection**: Verify all context files are found
2. **Review extraction**: Ensure key information is correctly extracted
3. **Validate trees**: Check that attack trees render properly in Mermaid
4. **Test enhancements**: Verify STIX/TTC mappings are applied when available

## Contributing Examples

### Guidelines
1. **Real-world relevance**: Base examples on realistic applications
2. **Educational value**: Include diverse threat scenarios
3. **Complete documentation**: Provide thorough README and threat statements
4. **Tested outputs**: Verify examples work with current ThreatForest version

### Submission Process
1. Create example following the standard structure
2. Test with ThreatForest to ensure it works
3. Include expected outputs in `expected-outputs/` directory
4. Submit pull request with clear description

## Troubleshooting Examples

### Common Issues
- **No threats found**: Check threat statement format and severity levels
- **Extraction errors**: Verify README contains sufficient technical details
- **Rendering issues**: Validate Mermaid syntax in generated files

### Debug Commands
```bash
# Run with verbose output
tf analyze --verbose

# Save debug logs
tf analyze --debug --log-file example-debug.log
```

For more troubleshooting help, see [TROUBLESHOOTING.md](../TROUBLESHOOTING.md).