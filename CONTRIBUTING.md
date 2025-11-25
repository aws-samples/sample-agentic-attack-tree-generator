# Contributing to ThreatForest

Thank you for your interest in contributing to ThreatForest! We welcome contributions from the community.

## 🤝 How to Contribute

### Reporting Bugs

If you find a bug, please create an issue with:
- Clear description of the problem
- Steps to reproduce
- Expected vs actual behavior
- Environment details (Python version, OS, provider used)
- Relevant log outputs

### Suggesting Enhancements

We love new ideas! When suggesting enhancements:
- Check existing issues to avoid duplicates
- Clearly describe the feature and its benefits
- Provide use cases or examples
- Consider implementation complexity

### Pull Requests

1. **Fork the repository**
2. **Create a feature branch** (`git checkout -b feature/amazing-feature`)
3. **Make your changes**
4. **Test thoroughly**
5. **Commit with clear messages** (`git commit -m 'Add amazing feature'`)
6. **Push to your branch** (`git push origin feature/amazing-feature`)
7. **Open a Pull Request**

## 💻 Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR-USERNAME/ThreatForest.git
cd ThreatForest

# Add upstream remote
git remote add upstream https://github.com/YOUR-ORG/ThreatForest.git

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install development dependencies (if any)
pip install pytest black flake8
```

## 📝 Coding Standards

### Python Style Guide

- Follow [PEP 8](https://pep8.org/) style guidelines
- Use [Black](https://github.com/psf/black) for code formatting
- Maximum line length: 100 characters
- Use type hints where appropriate

### Code Organization

- Keep functions focused and single-purpose
- Add docstrings to all public functions/classes
- Use meaningful variable and function names
- Comment complex logic

### Example

```python
def extract_threats(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract threat statements from parsed data.
    
    Args:
        data: Parsed threat model data
        
    Returns:
        List of threat dictionaries with standardized format
    """
    threats = []
    # Implementation here
    return threats
```

## 🧪 Testing

### Running Tests

```bash
# Run all tests
python -m pytest tests/

# Run specific test file
python -m pytest tests/test_threat_extractor.py

# Run with coverage
python -m pytest --cov=src tests/
```

### Writing Tests

- Add tests for new features
- Ensure tests are independent
- Use descriptive test names
- Mock external services (AWS, APIs)

## 📋 Pull Request Process

1. **Update Documentation** - Update README.md if needed
2. **Add Tests** - Ensure your changes are tested
3. **Run Tests** - All tests must pass
4. **Format Code** - Run `black src/`
5. **Update CHANGELOG** - Add entry for your changes (if applicable)
6. **Describe Changes** - Provide clear PR description

### PR Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
How did you test these changes?

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] Tests added/updated
- [ ] All tests passing
```

## 🌿 Branch Strategy

- `main` - Stable release branch
- `develop` - Development branch
- `feature/*` - New features
- `bugfix/*` - Bug fixes
- `hotfix/*` - Critical fixes

## 📜 Commit Messages

Use clear, descriptive commit messages:

```bash
# Good
git commit -m "Add support for Gemini AI provider"
git commit -m "Fix: Handle missing priority field in threat models"
git commit -m "Docs: Update Quick Start guide"

# Avoid
git commit -m "fix stuff"
git commit -m "update"
```

## 🎯 Priority Areas

We especially welcome contributions in:

- 📊 Enhanced visualization features
- 🔌 New AI provider integrations
- 📝 Documentation improvements
- 🧪 Test coverage expansion
- 🐛 Bug fixes
- 🌍 Localization/i18n

## ❓ Questions?

Feel free to:
- Open a discussion on GitHub
- Comment on existing issues
- Reach out to maintainers

## 📄 License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for making ThreatForest better! 🌳
