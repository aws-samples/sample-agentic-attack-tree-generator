# ThreatForest UI Installation & Verification

## Prerequisites
- Node.js 18+ installed
- npm installed
- Python 3.8+ with ThreatForest backend

## Installation Steps

### 1. Install Dependencies
```bash
cd ui
npm install
```

### 2. Build the CLI
```bash
npm run build:all
```

This will:
- Build the main UI bundle to `dist/index.js`
- Build the CLI with shebang to `dist/cli.js`
- Make `dist/cli.js` executable

### 3. Install Globally (Optional)
```bash
npm link
```

This creates a global `threatforest` command.

## Verification

### Check Build Output
```bash
ls -la dist/
# Should show:
# - index.js
# - cli.js (executable)
```

### Test CLI Commands

#### 1. Help Command
```bash
node dist/cli.js help
# Should display help menu with all commands
```

#### 2. Status Command
```bash
node dist/cli.js status
# Should show "No active workflow" if no state exists
```

#### 3. Run Command (requires full setup)
```bash
node dist/cli.js run
# Should start the interactive wizard
```

### Test Global Installation
```bash
# After npm link
threatforest help
threatforest status
```

## CLI Commands Reference

| Command | Description | Example |
|---------|-------------|---------|
| `threatforest run` | Start new session | `threatforest run` |
| `threatforest resume` | Resume from checkpoint | `threatforest resume` |
| `threatforest cache stats` | Show cache statistics | `threatforest cache stats` |
| `threatforest cache clear` | Clear cache | `threatforest cache clear` |
| `threatforest cache info` | Show cache config | `threatforest cache info` |
| `threatforest status` | Show workflow status | `threatforest status` |
| `threatforest help` | Show help | `threatforest help` |

## Troubleshooting

### Build Fails
```bash
# Clean and rebuild
rm -rf node_modules dist
npm install
npm run build:all
```

### CLI Not Found After npm link
```bash
# Unlink and relink
npm unlink -g
npm link
```

### Permission Denied
```bash
# Make CLI executable
chmod +x dist/cli.js
```

### Python Bridge Errors
```bash
# Set Python path
export PYTHON_PATH=/usr/bin/python3
node dist/cli.js run
```

## Development

### Watch Mode
```bash
npm run watch
```

### Development Mode
```bash
npm run dev
```

### Build Individual Components
```bash
npm run build        # Build main UI only
npm run build:cli    # Build CLI only
npm run build:all    # Build both
```

## Verification Checklist

- [ ] Dependencies installed (`npm install`)
- [ ] Build successful (`npm run build:all`)
- [ ] `dist/cli.js` exists and is executable
- [ ] `dist/index.js` exists
- [ ] Help command works (`node dist/cli.js help`)
- [ ] Status command works (`node dist/cli.js status`)
- [ ] Global install works (`npm link`)
- [ ] Global command works (`threatforest help`)

## Success Criteria

✅ All CLI commands implemented:
- run, resume, cache, status, help

✅ Package.json configured:
- bin entry points to dist/cli.js
- build:cli script creates executable
- install:global script for easy setup

✅ Documentation complete:
- CLI_USAGE.md for end users
- INSTALLATION.md for setup
- README.md for developers

✅ Integration complete:
- Python bridge for backend calls
- Workflow executor for orchestration
- All UI components functional
