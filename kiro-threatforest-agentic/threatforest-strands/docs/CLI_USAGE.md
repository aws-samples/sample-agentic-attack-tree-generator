# ThreatForest CLI Usage Guide

## Installation

### 1. Install Python Dependencies
```bash
pip install -r requirements.txt
```

### 2. Install UI Dependencies
```bash
cd ui
npm install
npm run build:all
npm link  # Install CLI globally
```

## CLI Commands

### Start New Threat Modeling Session
```bash
threatforest run
# or simply
threatforest
```

This will:
- Check for previous sessions
- Guide you through configuration
- Discover threat model files
- Extract threats
- Generate attack trees
- Map to MITRE ATT&CK TTC
- Display summary with cache statistics

### Resume from Checkpoint
```bash
threatforest resume
```

Resumes from the last saved checkpoint if available. Shows:
- Current stage
- Start time
- Interactive prompt to resume or restart

### Manage Response Cache
```bash
# Show cache statistics
threatforest cache stats

# Clear all cached responses
threatforest cache clear

# Show cache configuration
threatforest cache info
```

Cache features:
- 24-hour TTL by default
- 100MB size limit with LRU eviction
- SHA256 cache keys
- Reduces API calls by 50%+

### Check Workflow Status
```bash
threatforest status
```

Shows:
- Current workflow stage
- Start time
- Last updated time
- Completed stages
- Resume instructions

### Help
```bash
threatforest help
```

## Interactive Features

### Keyboard Navigation
- **Arrow Keys**: Navigate options
- **Space**: Toggle selection
- **Enter**: Confirm action
- **Escape**: Cancel/Go back
- **Letters**: Quick shortcuts (R, S, A, etc.)
- **Tab**: Next field

### Resume Prompt
When a previous session is detected:
- **R** or **↑**: Resume from checkpoint
- **N** or **↓**: Start new session
- **Enter**: Confirm selection

### Error Recovery
When errors occur:
- **R**: Retry operation
- **S**: Skip and continue
- **A**: Abort workflow
- **Arrow Keys**: Navigate options

## Workflow Stages

1. **File Discovery**
   - Single-pass file discovery
   - Cached results
   - Excluded directories (.git, node_modules, etc.)

2. **Threat Extraction**
   - Parser chain (ThreatComposer, JSON, YAML, Markdown)
   - Parallel extraction for multiple files
   - Format auto-detection

3. **Attack Tree Generation**
   - Parallel generation for multiple threats
   - Real-time progress with ETA
   - Cache hit/miss indicators

4. **TTC Mapping**
   - MITRE ATT&CK mapping
   - Confidence scores
   - Technique identification

5. **Summary**
   - Total threats processed
   - Attack trees generated
   - Cache statistics
   - Output location

## Progress Visualization

The UI displays:
- ✓ Completed stages (green)
- ▶ Current stage (yellow, animated)
- ○ Pending stages (gray)
- Progress bar with percentage
- ETA and elapsed time
- Parallel task execution
- Cache hit rate

## Output

Results are saved to:
```
./threatforest_output/
├── attack_tree_001_threat_description.md
├── attack_tree_002_threat_description.md
├── ...
└── summary.json
```

## Examples

### Basic Usage
```bash
# Start new session
threatforest run

# Follow prompts:
# 1. Enter project path
# 2. Enter AWS profile (or default)
# 3. Select Bedrock model
# 4. Wait for completion
```

### Resume After Interruption
```bash
# If workflow was interrupted
threatforest resume

# Choose to resume or restart
```

### Check Cache Performance
```bash
# View cache statistics
threatforest cache stats

# Output:
# Total Entries: 45
# Cache Hits: 23
# Cache Misses: 22
# Hit Rate: 51.1%
# Total Size: 12.34 MB
```

### Monitor Progress
```bash
# In another terminal
threatforest status

# Output:
# Stage: trees
# Started: 2025-10-10 20:00:00
# ✓ Setup complete
# ✓ Context analysis complete
# ✓ Information extraction complete
```

## Troubleshooting

### CLI Not Found
```bash
cd ui
npm link
```

### Build Errors
```bash
cd ui
rm -rf node_modules dist
npm install
npm run build:all
```

### Python Bridge Errors
Ensure Python path is correct:
```bash
export PYTHON_PATH=/path/to/python
threatforest run
```

### Cache Issues
Clear cache and restart:
```bash
threatforest cache clear
threatforest run
```

## Advanced Usage

### Custom Python Path
```bash
PYTHON_PATH=/usr/local/bin/python3 threatforest run
```

### Development Mode
```bash
cd ui
npm run dev
```

### Watch Mode
```bash
cd ui
npm run watch
```

## Support

For issues or questions:
- Check logs in `./threatforest_output/`
- Review cache stats: `threatforest cache stats`
- Check workflow status: `threatforest status`
- Clear cache if needed: `threatforest cache clear`
