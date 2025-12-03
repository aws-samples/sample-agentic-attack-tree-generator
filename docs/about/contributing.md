# Contributing to ThreatForest

Thank you for your interest in contributing to ThreatForest! We welcome contributions from the community.

## How to Contribute

### Reporting Bugs/Feature Requests

We welcome you to use the GitHub issue tracker to report bugs or suggest features.

When filing an issue, please check existing open, or recently closed, issues to make sure somebody else hasn't already reported the issue. Please try to include as much information as you can:

* A reproducible test case or series of steps
* The version of ThreatForest being used
* Any modifications you've made relevant to the bug
* Anything unusual about your environment or deployment

### Contributing via Pull Requests

Contributions via pull requests are much appreciated. Before sending us a pull request, please ensure that:

1. You are working against the latest source on the *main* branch
2. You check existing open, and recently merged, pull requests to make sure someone else hasn't addressed the problem already
3. You open an issue to discuss any significant work - we would hate for your time to be wasted

To send us a pull request, please:

1. Fork the repository
2. Modify the source; please focus on the specific change you are contributing
3. Ensure local tests pass
4. Commit to your fork using clear commit messages
5. Send us a pull request, answering any default questions in the pull request interface
6. Pay attention to any automated CI failures reported in the pull request, and stay involved in the conversation

### Finding Contributions to Work On

Looking at the existing issues is a great way to find something to contribute on. Look for issues labeled 'help wanted' or 'good first issue' to get started.

## Code of Conduct

This project has adopted the [Amazon Open Source Code of Conduct](https://aws.github.io/code-of-conduct).
For more information see the [Code of Conduct FAQ](https://aws.github.io/code-of-conduct-faq) or contact opensource-codeofconduct@amazon.com with any additional questions or comments.

## Development Setup

```bash
# Clone your fork
git clone https://github.com/aws-samples/sample-agentic-attack-tree-generator.git
cd sample-agentic-attack-tree-generator

# Install in editable mode with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/

# Format code
black src/
isort src/
```

## Questions?

If you have questions about contributing, please open a [GitHub Discussion](https://github.com/aws-samples/sample-agentic-attack-tree-generator/discussions) or reach out via GitHub Issues.
