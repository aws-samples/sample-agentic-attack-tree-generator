# Security Policy

## 🐛 Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability, please follow these steps:

### 1. **Do Not** Open a Public Issue

Please do not create public GitHub issues for security vulnerabilities, as this could put users at risk.

### 2. Report Privately

Send a detailed report to: **crisleoo@amazon.com**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)
- Your contact information for follow-up

### 3. Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Fix Timeline**: Depends on severity (see below)

### Severity Levels

| Severity | Response Time | Example |
|----------|--------------|---------|
| **Critical** | 24-48 hours | Remote code execution, data breach |
| **High** | 7 days | Authentication bypass, privilege escalation |
| **Medium** | 30 days | Information disclosure, DoS |
| **Low** | 90 days | Minor issues with limited impact |

## 🛡️ Security Best Practices

### For Users

1. **API Keys & Credentials**
   - Never commit `.env` files
   - Use AWS IAM roles when possible
   - Rotate credentials regularly
   - Use least privilege access

2. **Dependencies**
   - Keep dependencies updated
   - Run `pip install --upgrade -r requirements.txt` regularly
   - Review security advisories

3. **Execution Environment**
   - Run in isolated environments (containers/VMs)
   - Limit network access if processing sensitive data
   - Monitor log files for unusual activity

### For Contributors

1. **Code Review**
   - All PRs require review before merge
   - Security-related changes need extra scrutiny
   - Test for injection vulnerabilities

2. **Dependencies**
   - Only add necessary dependencies
   - Verify package authenticity
   - Check for known vulnerabilities

3. **Data Handling**
   - Never log sensitive information
   - Sanitize user inputs
   - Use secure file operations

## 🔐 Known Security Considerations

### AI Model Interactions

- **Prompt Injection**: User-provided content is sent to AI models. Sanitize inputs appropriately.
- **Data Privacy**: Threat models may contain sensitive information. Choose your AI provider accordingly.
- **API Keys**: Store in `.env` files, never in code.

### File Operations

- **Path Traversal**: File discovery sanitizes paths to prevent directory traversal
- **File Types**: Binary files are handled securely
- **Permissions**: Output files created with appropriate permissions

### Network Operations

- **AWS Credentials**: Use IAM roles or temporary credentials when possible
- **HTTPS Only**: All API communications use encrypted connections
- **Timeout Handling**: Network operations have appropriate timeouts

## 📢 Security Updates

Security updates will be:
- Released as patch versions
- Announced in GitHub Security Advisories
- Documented in CHANGELOG.md
- Tagged with `[SECURITY]` in commit messages

## 🙏 Acknowledgments

We appreciate responsible disclosure and will acknowledge security researchers who report valid vulnerabilities (with permission).

## 📞 Contact

For security concerns, contact: **crisleoo@amazon.com**

For general questions, use [GitHub Issues](https://github.com/aws-samples/sample-agentic-attack-tree-generator/issues).

---

**Last Updated**: November 2024
