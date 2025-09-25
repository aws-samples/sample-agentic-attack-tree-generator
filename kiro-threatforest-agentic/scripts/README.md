# ThreatForest Scripts

This directory contains utility scripts for ThreatForest development, testing, and validation.

## Directory Structure

- **`validation/`** - Scripts for validating ThreatForest setup and configuration
- **`testing/`** - Test scripts and integration test runners
- **`demo/`** - Demonstration scripts showing ThreatForest features

## Usage

### Validation Scripts
```bash
# Verify Bedrock setup and connectivity
python scripts/validation/verify_bedrock_setup.py

# Validate enhanced configuration features
python scripts/validation/validate_enhanced_config.py
```

### Testing Scripts
```bash
# Run comprehensive integration tests
python scripts/testing/run_integration_tests.py

# Test CLI help text and logging functionality
python scripts/testing/test_cli_help_and_logging.py

# Run all tests with coverage
python scripts/testing/run_tests.py
```

### Demo Scripts
```bash
# Demonstrate CLI features
python scripts/demo/demo_cli_features.py

# Show setup wizard functionality
python scripts/demo/demo_setup_wizard.py

# Demonstrate validation features
python scripts/demo/demo_validation.py
```

## Requirements

All scripts require ThreatForest to be installed in development mode:

```bash
pip install -e .
```

Some scripts may require additional dependencies for testing or validation.