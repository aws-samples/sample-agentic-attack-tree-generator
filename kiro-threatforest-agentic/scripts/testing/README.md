# Testing Scripts

Scripts for running tests, integration tests, and validating functionality.

## Scripts

### `run_integration_tests.py`
Comprehensive integration test runner for enhanced configuration features.

**Features:**
- Tests end-to-end configuration workflows
- Validates model provider integration
- Tests CLI command functionality
- Generates detailed test reports

**Usage:**
```bash
python scripts/testing/run_integration_tests.py
```

### `test_cli_help_and_logging.py`
Tests CLI help text and logging configuration functionality.

**Features:**
- Validates help text content and formatting
- Tests logging options and output
- Checks error message enhancements
- Verifies examples functionality

**Usage:**
```bash
python scripts/testing/test_cli_help_and_logging.py
```

### `run_tests.py`
Main test runner for all ThreatForest tests.

**Features:**
- Runs unit tests with coverage reporting
- Executes integration tests
- Generates comprehensive test reports
- Supports various test filtering options

**Usage:**
```bash
python scripts/testing/run_tests.py
```

## Requirements

- ThreatForest installed in development mode
- pytest and testing dependencies
- AWS credentials for integration tests