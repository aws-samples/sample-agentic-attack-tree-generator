# ThreatForest Troubleshooting Guide

This guide helps you resolve common issues when using ThreatForest.

## Common Issues

### Authentication and AWS Setup

#### Issue: "NoCredentialsError: Unable to locate credentials"

**Cause**: AWS credentials are not properly configured.

**Solutions**:
1. **Set environment variables**:
   ```bash
   export AWS_ACCESS_KEY_ID=your_access_key
   export AWS_SECRET_ACCESS_KEY=your_secret_key
   export AWS_DEFAULT_REGION=us-east-1
   ```

2. **Configure AWS CLI**:
   ```bash
   aws configure
   ```

3. **Use IAM roles** (for EC2/ECS instances):
   - Ensure your instance has an IAM role with Bedrock permissions
   - No additional configuration needed

4. **Check credentials file**:
   ```bash
   cat ~/.aws/credentials
   cat ~/.aws/config
   ```

#### Issue: "AccessDenied: User is not authorized to perform bedrock:InvokeModel"

**Cause**: Your AWS user/role lacks Bedrock permissions.

**Solution**: Add the following IAM policy to your user/role:
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "bedrock:InvokeModel",
                "bedrock:InvokeModelWithResponseStream",
                "bedrock:ListFoundationModels"
            ],
            "Resource": "*"
        }
    ]
}
```

#### Issue: "Region not supported for Bedrock"

**Cause**: Bedrock is not available in your configured region.

**Solution**: Use a supported region:
```bash
tf analyze --region us-east-1
# or
tf config --set bedrock.region us-east-1
```

Supported regions: `us-east-1`, `us-west-2`, `eu-west-1`, `ap-southeast-1`

### File and Directory Issues

#### Issue: "No context files found in directory"

**Cause**: ThreatForest cannot find required files.

**Solutions**:
1. **Ensure required files exist**:
   - `README.md` (required)
   - `threats.md` (required)

2. **Check file naming patterns**:
   ```bash
   # Valid README patterns
   README.md, README.txt, readme.md
   
   # Valid threat file patterns  
   threats.md, threat-statements.md, security-threats.json
   ```

3. **Verify file content**:
   - README should contain project description
   - threats.md should contain properly formatted threat statements

#### Issue: "Malformed threat statements"

**Cause**: Threat statements don't follow the expected format.

**Solution**: Ensure threats.md follows this format:
```markdown
## Threat 1 - Category
[High]
An external threat actor who can access X can perform Y, which leads to Z, resulting in impact W

## Threat 2 - Category  
[Medium]
A malicious internal actor with access to A can exploit B, which leads to C, resulting in impact D
```

#### Issue: "Permission denied when writing output files"

**Cause**: Insufficient permissions to write to output directory.

**Solutions**:
1. **Check directory permissions**:
   ```bash
   ls -la tf-output/
   ```

2. **Use custom output directory**:
   ```bash
   tf analyze --output ~/my-analysis
   ```

3. **Run with appropriate permissions**:
   ```bash
   sudo tf analyze  # Use with caution
   ```

### Processing and Performance Issues

#### Issue: "Analysis takes too long or times out"

**Cause**: Large files, slow network, or API rate limits.

**Solutions**:
1. **Increase timeout**:
   ```bash
   tf config --set processing.timeout_seconds 600
   ```

2. **Reduce concurrent processing**:
   ```bash
   tf config --set processing.max_concurrent_agents 2
   ```

3. **Check network connectivity**:
   ```bash
   curl -I https://bedrock.us-east-1.amazonaws.com
   ```

#### Issue: "Out of memory errors"

**Cause**: Insufficient RAM for processing large STIX files.

**Solutions**:
1. **Increase available memory** (minimum 2GB recommended)

2. **Disable TTC enhancement** if not needed:
   ```bash
   tf config --set ttc.enable_enhancement false
   ```

3. **Process smaller batches**:
   ```bash
   tf analyze --max-threats 5
   ```

#### Issue: "API rate limit exceeded"

**Cause**: Too many requests to Bedrock API.

**Solutions**:
1. **Reduce concurrent requests**:
   ```bash
   tf config --set processing.max_concurrent_agents 1
   ```

2. **Add delays between requests**:
   ```bash
   tf config --set processing.request_delay_seconds 2
   ```

3. **Use exponential backoff** (enabled by default)

### Output and Results Issues

#### Issue: "No attack trees generated"

**Cause**: No high-severity threats found or processing errors.

**Solutions**:
1. **Check threat severity levels**:
   - Ensure threats are marked as `[High]`
   - Lower severity threshold: `tf config --set processing.severity_threshold medium`

2. **Review processing logs**:
   ```bash
   tf analyze --verbose --log-file analysis.log
   cat analysis.log
   ```

3. **Validate threat format**:
   - Ensure proper threat statement structure
   - Check for parsing errors in logs

#### Issue: "Mermaid files won't render"

**Cause**: Invalid Mermaid syntax in generated files.

**Solutions**:
1. **Validate Mermaid syntax**:
   - Use online Mermaid editor: https://mermaid.live/
   - Check for special characters or formatting issues

2. **Regenerate with different model**:
   ```bash
   tf config --set bedrock.model anthropic.claude-3-haiku
   tf analyze
   ```

3. **Report syntax issues** if consistently occurring

#### Issue: "STIX enhancement not working"

**Cause**: Missing or invalid AAF bundle file.

**Solutions**:
1. **Check AAF bundle path**:
   ```bash
   tf config --show | grep aaf_bundle_path
   ls -la ./aaf-bundle.json
   ```

2. **Download AAF bundle**:
   ```bash
   # Download from AWS (example URL)
   wget https://example.com/aaf-bundle.json
   ```

3. **Validate bundle format**:
   ```bash
   python -m json.tool aaf-bundle.json > /dev/null
   ```

4. **Disable if not needed**:
   ```bash
   tf config --set ttc.enable_enhancement false
   ```

## Debugging Commands

### Enable Verbose Logging
```bash
tf analyze --verbose
```

### Save Detailed Logs
```bash
tf analyze --debug --log-file debug.log
```

### Check Configuration
```bash
tf config --show
```

### Validate Environment
```bash
# Check Python version
python --version

# Check AWS CLI
aws --version
aws sts get-caller-identity

# Check Bedrock access
aws bedrock list-foundation-models --region us-east-1
```

### Test Basic Functionality
```bash
# Test with example project
cd genai-chatbot-example/
tf analyze --verbose
```

## Getting Help

### Log Analysis
When reporting issues, include:
1. **Error messages** from console output
2. **Log files** with `--debug` enabled
3. **Configuration** from `tf config --show`
4. **Environment details** (OS, Python version, AWS region)

### Example Debug Session
```bash
# Run with full debugging
tf analyze --debug --verbose --log-file full-debug.log

# Check configuration
tf config --show > config-dump.txt

# Test AWS connectivity
aws bedrock list-foundation-models --region us-east-1 > bedrock-test.txt

# Package all debug info
tar -czf tf-debug-$(date +%Y%m%d).tar.gz full-debug.log config-dump.txt bedrock-test.txt
```

### Support Channels
- **GitHub Issues**: [Report bugs and feature requests](https://github.com/threatforest/threatforest/issues)
- **Discussions**: [Community support and questions](https://github.com/threatforest/threatforest/discussions)
- **Documentation**: [Full documentation](https://threatforest.readthedocs.io)

## Performance Optimization

### For Large Projects
```bash
# Optimize for large directories
tf config --set processing.max_concurrent_agents 4
tf config --set processing.timeout_seconds 900
tf config --set files.max_file_size_mb 50
```

### For Limited Resources
```bash
# Optimize for limited memory/CPU
tf config --set processing.max_concurrent_agents 1
tf config --set ttc.enable_enhancement false
tf config --set processing.batch_size 1
```

### For Fast Processing
```bash
# Optimize for speed (requires good network/resources)
tf config --set processing.max_concurrent_agents 8
tf config --set processing.request_delay_seconds 0.1
tf config --set bedrock.model anthropic.claude-3-haiku
```