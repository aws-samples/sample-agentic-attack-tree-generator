# Validation Scripts

Scripts for validating ThreatForest setup, configuration, and connectivity.

## Scripts

### `verify_bedrock_setup.py`
Comprehensive verification of AWS Bedrock setup and connectivity.

**Features:**
- Checks AWS credentials and permissions
- Tests Bedrock service connectivity
- Validates model availability
- Verifies SDK versions and compatibility

**Usage:**
```bash
python scripts/validation/verify_bedrock_setup.py
```

### `validate_enhanced_config.py`
Validates the enhanced configuration system and model provider integration.

**Features:**
- Tests configuration loading from multiple sources
- Validates model selection and recommendations
- Checks configuration validation system
- Tests error handling and recovery

**Usage:**
```bash
python scripts/validation/validate_enhanced_config.py
```

## Requirements

- ThreatForest installed in development mode
- AWS credentials configured
- Network access to AWS services