# ThreatForest Configuration

## Overview

ThreatForest uses a centralized configuration file (`config.yaml`) to manage data paths, model settings, and AWS configurations. This eliminates hardcoded paths throughout the codebase.

## Configuration File

Location: `config.yaml` (project root)

```yaml
# Data paths
data:
  stix_bundle: "data/aaf-bundle.json"
  embeddings_file: "data/embeddings/attack_pattern_embeddings_qwen.json"
  input_dir: ""
  output_dir: "output"

# Model settings
models:
  default_bedrock_model: ""

# Embeddings settings
embeddings:
  model: "Qwen/Qwen3-Embedding-0.6B"

# AWS settings
aws:
  default_profile: "default"
  default_region: "us-east-1"
```

## Configuration Properties

### Data Paths

- **`stix_bundle`**: Path to MITRE ATT&CK STIX bundle file (aaf-bundle.json)
- **`embeddings_file`**: Path to pre-generated embeddings JSON file
- **`input_dir`**: Default input directory (empty = user must specify)
- **`output_dir`**: Default output directory for generated files

### Model Settings

- **`default_bedrock_model`**: Default AWS Bedrock model (empty = user selects)
  - Examples: 
    - `us.anthropic.claude-sonnet-4-20250514-v1:0` (Claude Sonnet 4)
    - `us.anthropic.claude-sonnet-4-5-20250929-v1:0` (Claude Sonnet 4.5)
    - `us.anthropic.claude-opus-4-1-20250805-v1:0` (Claude Opus 4.1)

### Embeddings Settings

- **`model`**: Sentence transformer model for TTC matching
  - Default: `Qwen/Qwen3-Embedding-0.6B`

### AWS Settings

- **`default_profile`**: Default AWS CLI profile name
- **`default_region`**: Default AWS region for Bedrock

## Usage in Code

### Python

```python
from config import config

# Access configuration values
stix_path = config.stix_bundle_path  # Returns Path object
embeddings_path = config.embeddings_file_path  # Returns Path object
model_name = config.embeddings_model  # Returns string
output_dir = config.output_dir  # Returns string

# Or use dot notation
value = config.get('data.stix_bundle')
```

### Updated Files

The following files now use the centralized configuration:

1. **`src/config.py`** - Configuration loader module
2. **`src/modules/ttc_mappings/matcher.py`** - Uses `embeddings_model`
3. **`src/modules/ttc_mappings/demo_mitigations.py`** - Uses `stix_bundle_path`
4. **`src/modules/ttc_mappings/map_mitigations.py`** - Uses `stix_bundle_path`
5. **`src/modules/ttc_mappings/mitigation_cli.py`** - Uses `stix_bundle_path`
6. **`src/modules/ttc_mappings/example.py`** - Uses `stix_bundle_path`
7. **`src/modules/tools/ttc_mapping_tool.py`** - Uses `stix_bundle_path`

## Benefits

✅ **No hardcoded paths** - All paths centralized in one file  
✅ **Easy updates** - Change paths once, affects entire application  
✅ **Environment flexibility** - Different configs for dev/prod  
✅ **Clear documentation** - All settings in one place  
✅ **Type safety** - Config module provides typed properties

## Migration Notes

### Old Pattern (Hardcoded)
```python
bundle_path = Path(__file__).parent.parent / "stix-data" / "aaf-bundle.json"
model_name = "Qwen/Qwen3-Embedding-0.6B"
```

### New Pattern (Config)
```python
from config import config
bundle_path = config.stix_bundle_path
model_name = config.embeddings_model
```
