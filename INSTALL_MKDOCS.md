# Installing ThreatForest with MkDocs Support

## The Issue with pipx

If you see this error when trying to install mkdocs-material with pipx:
```
No apps associated with package mkdocs-material. Try again with '--include-deps'...
If you are attempting to install a library, pipx should not be used.
```

This is because **pipx is for installing Python applications**, not libraries. MkDocs and its dependencies are libraries that need to be installed alongside ThreatForest.

## Correct Installation Methods

### Option 1: Install ThreatForest in Development Mode (Recommended for Development)

```bash
cd ThreatForest-internal
pip install -e .
```

This installs ThreatForest in "editable" mode with all dependencies including MkDocs.

### Option 2: Install ThreatForest Normally

```bash
cd ThreatForest-internal
pip install .
```

### Option 3: Install Just the MkDocs Dependencies

If ThreatForest is already installed but MkDocs is missing:

```bash
pip install mkdocs>=1.5.0 mkdocs-material>=9.0.0 pymdown-extensions>=10.0
```

### Option 4: Using a Virtual Environment (Recommended)

```bash
# Create a virtual environment
python -m venv venv

# Activate it
source venv/bin/activate  # On macOS/Linux
# or
venv\Scripts\activate  # On Windows

# Install ThreatForest with all dependencies
pip install -e .
```

## Verify Installation

After installation, verify MkDocs is available:

```bash
mkdocs --version
```

You should see output like:
```
mkdocs, version 1.5.x
```

## Using ThreatForest with MkDocs

Once installed, you can use the docs commands:

```bash
# Generate and build documentation
threatforest docs build ./output/threatforest/attack_trees

# Serve documentation locally
threatforest docs serve ./output/threatforest/attack_trees
```

## Troubleshooting

### "mkdocs: command not found"

This means MkDocs isn't in your PATH. Solutions:

1. **Ensure you're in the correct environment** (if using venv)
2. **Reinstall ThreatForest**: `pip install -e . --force-reinstall`
3. **Check pip installation location**: `pip show mkdocs`

### "ModuleNotFoundError: No module named 'mkdocs'"

Python can't find the mkdocs module. Solutions:

1. **Verify installation**: `pip list | grep mkdocs`
2. **Reinstall**: `pip install mkdocs mkdocs-material pymdown-extensions`
3. **Check Python environment**: Make sure you're using the same Python that has the packages installed

### Using pipx for ThreatForest CLI

If you want to use pipx to install ThreatForest as a CLI tool:

```bash
# Install ThreatForest with pipx, including all dependencies
pipx install .

# Or from a specific directory
pipx install /path/to/ThreatForest-internal
```

This will install ThreatForest and all its dependencies (including MkDocs) in an isolated environment.
