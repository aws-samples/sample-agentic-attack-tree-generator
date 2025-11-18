# Hybrid Embeddings Usage Guide

## Overview

ThreatForest now supports two modes for matching attack steps to MITRE ATT&CK techniques:

1. **Local Mode** - Uses local SentenceTransformer model with pre-generated embeddings
2. **Neptune Mode** - Uses Neptune graph database with graph-native embeddings

Both modes use **cisco-ai/SecureBERT2.0-base** as the embedding model.

## Configuration

Edit `config.yaml` to set your embedding mode:

```yaml
# Embeddings settings
embeddings:
  mode: "local"  # Options: "local" or "neptune"
  model: "cisco-ai/SecureBERT2.0-base"
  
# Neptune settings (required when embeddings.mode=neptune)
neptune:
  graph_id: "g-f7i4wf2pc5"
  region: "us-west-2"
  s3_bucket: "threatforest-neptune"
```

## Local Mode Usage

### Prerequisites
- Pre-generated embeddings file: `data/embeddings/attack_pattern_embeddings_qwen.json`
- Internet connection (first time only, to download SecureBERT model)

### Configuration
```yaml
embeddings:
  mode: "local"
```

### Example Code
```python
from src.config import config
from src.modules.ttc_mappings import TTCMatcher, AttackTreeEnricher

# Initialize matcher in local mode
matcher = TTCMatcher(
    mode='local',
    embeddings_path=str(config.embeddings_file_path),
    model_name=config.embeddings_model
)

# Use with enricher
enricher = AttackTreeEnricher(matcher)
enriched_content = enricher.enrich_attack_tree(markdown_content)
```

### Pros
- ✅ Works offline (after first model download)
- ✅ Fast - no network latency
- ✅ Predictable performance

### Cons
- ❌ No graph context
- ❌ Requires pre-generated embeddings
- ❌ Limited to embeddings file techniques

## Neptune Mode Usage

### Prerequisites
- Neptune graph with AAF data loaded (see `scripts/graph/README.md`)
- AWS credentials configured
- Neptune graph ID in config
- boto3 and neptune-graph-manager installed

### Configuration
```yaml
embeddings:
  mode: "neptune"
  
neptune:
  graph_id: "g-f7i4wf2pc5"
  region: "us-west-2"
  s3_bucket: "threatforest-neptune"
```

### Example Code
```python
from boto3 import Session
from neptune_graph_manager import NeptuneGraphManager
from src.config import config
from src.modules.ttc_mappings import TTCMatcher, AttackTreeEnricher
from ast import literal_eval
import os

# Initialize Neptune manager
session = Session(**literal_eval(os.getenv("SESSION_PARAMS", "{}")))
neptune_manager = NeptuneGraphManager(
    session=session, 
    graph_id=config.neptune_graph_id
)

# Initialize matcher in Neptune mode
matcher = TTCMatcher(
    mode='neptune',
    neptune_manager=neptune_manager
)

# Use with enricher
enricher = AttackTreeEnricher(matcher)
enriched_content = enricher.enrich_attack_tree(markdown_content)
```

### Pros
- ✅ Leverages graph relationships
- ✅ Always up-to-date with graph
- ✅ Can query connected data (mitigations, threat actors, etc.)
- ✅ Scalable to large datasets

### Cons
- ❌ Requires Neptune connection
- ❌ Network latency per query
- ❌ Requires AWS credentials
- ❌ Potential cost implications

## Error Handling

### Local Mode Errors

**Error**: `ValueError: No embeddings loaded for local mode`  
**Solution**: Provide `embeddings_path` when initializing TTCMatcher

**Error**: `FileNotFoundError: Embeddings file not found`  
**Solution**: Generate embeddings or verify file path

### Neptune Mode Errors

**Error**: `ValueError: Neptune mode requires neptune_manager parameter`  
**Solution**: Initialize and pass NeptuneGraphManager instance

**Error**: `ConnectionError: Unable to connect to Neptune`  
**Solution**: Verify graph ID, region, and AWS credentials

**Error**: `Query execution failed`  
**Solution**: Check Neptune graph has Technique nodes with embeddings

## Mode Comparison

| Feature | Local | Neptune |
|---------|-------|---------|
| Speed | Fast ⚡ | Moderate 🐌 |
| Offline | Yes ✅ | No ❌ |
| Graph Context | No ❌ | Yes ✅ |
| Setup Complexity | Low 🟢 | High 🔴 |
| Scalability | Limited 🟡 | High 🟢 |
| Cost | Free 💚 | AWS Charges 💰 |

## Switching Modes

Simply update `config.yaml` and restart ThreatForest:

```yaml
# Switch to Neptune
embeddings:
  mode: "neptune"
```

No code changes needed - the matcher automatically uses the configured mode!

## Advanced: Programmatic Mode Selection

Override config mode at runtime:

```python
# Force local mode
matcher = TTCMatcher(
    mode='local',
    embeddings_path='path/to/embeddings.json'
)

# Force Neptune mode
matcher = TTCMatcher(
    mode='neptune',
    neptune_manager=neptune_manager
)
```

## Generating Local Embeddings with SecureBERT

To create new embeddings with SecureBERT:

```python
from src.modules.ttc_mappings import TTCMatcher

matcher = TTCMatcher(
    mode='local',
    model_name='cisco-ai/SecureBERT2.0-base'
)

# Generate from STIX bundle
embeddings = matcher.create_embeddings(
    stix_bundle_path='data/threat-intelligence/ttc-aaf.json',
    output_path='data/embeddings/attack_pattern_embeddings_securebert.json'
)
```

## AWS Term Boosting

Both modes apply AWS-specific term boosting:
- Matches get 10% boost per shared AWS term (max 50%)
- Terms: aws, s3, ec2, iam, lambda, dynamodb, etc.
- Improves relevance for cloud-specific attacks

## Troubleshooting

### Neptune Mode Not Working?

1. Verify graph exists: `aws neptune-graph get-graph --graph-id g-f7i4wf2pc5`
2. Check AWS credentials: `aws sts get-caller-identity`
3. Verify graph has Technique nodes with embeddings
4. Test connection:
   ```python
   summary = neptune_manager.get_summary()
   print(f"Nodes: {summary['numNodes']}")
   ```

### Local Mode Slow?

- First run downloads SecureBERT (~400MB)
- Subsequent runs use cached model
- Consider GPU for faster embedding generation

## Related Files

- `src/modules/ttc_mappings/matcher.py` - Hybrid matcher implementation
- `src/config.py` - Configuration properties
- `config.yaml` - User configuration
- `scripts/graph/` - Neptune graph tools
