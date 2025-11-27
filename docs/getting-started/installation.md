# Installation

This guide covers all methods for installing ThreatForest on your system.

## 🎯 Choose Your Installation Method

Select the method that best fits your use case:

| Method | Best For | Pros | Cons |
|--------|----------|------|------|
| **pipx** | End users | Global command, isolated, automatic PATH | Requires pipx install |
| **uv** | Modern Python users | Fastest, automatic venv, modern | Newer tool |
| **pip** | Traditional workflows | Familiar, works everywhere | Manual venv management |
| **Development** | Contributors | Editable install, instant updates | Local clone required |

---

## 📦 Method 1: pipx Installation (Recommended)

**Best for:** End users who want a global `threatforest` command.

### Install pipx

=== "macOS/Linux"

    ```bash
    # Install pipx
    python3 -m pip install --user pipx
    python3 -m pipx ensurepath
    
    # Reload shell
    source ~/.bashrc  # or ~/.zshrc
    ```

=== "Windows"

    ```powershell
    # Install pipx
    python -m pip install --user pipx
    python -m pipx ensurepath
    
    # Restart PowerShell
    ```

### Install ThreatForest

```bash
# Clone repository
git clone https://github.com/YOUR-ORG/ThreatForest.git
cd ThreatForest

# Install with pipx
pipx install .

# Verify
threatforest --version
```

### Verify Installation

```bash
$ threatforest --help
Usage: threatforest [OPTIONS] COMMAND [ARGS]...

  ThreatForest - AI-Driven Threat Modeling CLI

Options:
  --help  Show this message and exit.

Commands:
  config  Manage ThreatForest configuration
  help    Show help information
  run     Run ThreatForest workflow
  status  Show current workflow status
```

!!! success "Installation Complete"
    You can now run `threatforest` from any directory!

---

## ⚡ Method 2: uv Installation (Modern)

**Best for:** Users who want the fastest, most modern Python tooling.

### Install uv

=== "macOS/Linux"

    ```bash
    curl -LsSf https://astral.sh/uv/install.sh | sh
    ```

=== "Windows"

    ```powershell
    powershell -c "irm https://astral.sh/uv/install.ps1 | iex"
    ```

### Install ThreatForest

```bash
# Clone repository
git clone https://github.com/YOUR-ORG/ThreatForest.git
cd ThreatForest

# Install with uv
uv tool install .

# Verify
threatforest --version
```

### Benefits of uv

- ⚡ **10-100x faster** than pip
- 🔒 **Built-in virtual environments** - automatic isolation
- 📦 **Better dependency resolution** - faster, more reliable
- 🚀 **Modern Python standards** - follows latest best practices

---

## 🐍 Method 3: pip Installation (Traditional)

**Best for:** Users familiar with traditional Python workflows.

### Create Virtual Environment

=== "macOS/Linux"

    ```bash
    # Clone repository
    git clone https://github.com/YOUR-ORG/ThreatForest.git
    cd ThreatForest
    
    # Create venv
    python3 -m venv venv
    
    # Activate
    source venv/bin/activate
    ```

=== "Windows"

    ```powershell
    # Clone repository
    git clone https://github.com/YOUR-ORG/ThreatForest.git
    cd ThreatForest
    
    # Create venv
    python -m venv venv
    
    # Activate
    .\venv\Scripts\activate
    ```

### Install ThreatForest

```bash
# Install
pip install .

# Verify
threatforest --version
```

### Running ThreatForest

With pip installation, you must activate the virtual environment first:

```bash
# Activate venv
source venv/bin/activate  # macOS/Linux
# or
.\venv\Scripts\activate   # Windows

# Run ThreatForest
threatforest
```

---

## 👨‍💻 Method 4: Development Installation

**Best for:** Contributors working on ThreatForest code.

### Editable Install with pip

```bash
# Clone repository
git clone https://github.com/YOUR-ORG/ThreatForest.git
cd ThreatForest

# Create venv
python3 -m venv venv
source venv/bin/activate

# Install in editable mode with dev dependencies
pip install -e ".[dev]"

# Verify
threatforest --version
```

### Development with uv (Modern)

```bash
# Clone repository
git clone https://github.com/YOUR-ORG/ThreatForest.git
cd ThreatForest

# No install needed - run directly
uv run threatforest

# Make code changes, then run again
# uv automatically uses your latest edits!
uv run threatforest
```

### Why Editable Install?

- ✏️ **Instant Updates** - Code changes reflect immediately
- 🧪 **Easy Testing** - Test changes without reinstalling
- 🔄 **Rapid Iteration** - Perfect for development workflow

---

## 🐳 Method 5: Docker (Coming Soon)

**Best for:** Isolated environments and reproducible deployments.

```bash
# Pull image
docker pull threatforest:latest

# Run analysis
docker run -v $(pwd):/workspace threatforest analyze /workspace

# Interactive mode
docker run -it threatforest
```

!!! info "Docker Support"
    Docker images are coming in a future release. Follow our [GitHub repository](https://github.com/YOUR-ORG/ThreatForest) for updates.

---

## 🔧 Post-Installation Setup

### Configure AWS Credentials (for Bedrock)

```bash
# Method 1: AWS CLI
aws configure

# Method 2: Environment variables
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
export AWS_DEFAULT_REGION="us-east-1"

# Method 3: AWS credentials file
cat > ~/.aws/credentials << EOF
[default]
aws_access_key_id = your-access-key
aws_secret_access_key = your-secret-key
EOF
```

### Verify AWS Bedrock Access

```bash
# Test connection
aws bedrock list-foundation-models --region us-east-1

# Expected output: List of available models
# Including: Claude 3, Llama 3, etc.
```

### Request Model Access (if needed)

If you see "access denied" errors:

1. Open [AWS Bedrock Console](https://console.aws.amazon.com/bedrock/)
2. Navigate to "Model access" in left sidebar
3. Click "Enable specific models"
4. Select: **Anthropic Claude 3 Sonnet**
5. Submit access request (usually instant approval)

---

## ✅ Verify Installation

Run these commands to ensure everything is working:

### 1. Check Version

```bash
$ threatforest --version
ThreatForest 1.0.0
```

### 2. View Help

```bash
$ threatforest --help
```

### 3. Check Configuration

```bash
$ threatforest config show
```

Expected output:
```yaml
AWS Profile: default
Region: us-east-1
Model: anthropic.claude-3-sonnet-20240229-v1:0
Bedrock: ✓ Connected
```

### 4. Test Bedrock Connection

```bash
$ aws bedrock list-foundation-models --region us-east-1
```

---

## 🔄 Updating ThreatForest

Keep ThreatForest up to date with the latest features:

=== "pipx"

    ```bash
    # Update to latest version
    pipx upgrade threatforest
    
    # Reinstall specific version
    pipx install threatforest==1.0.0 --force
    ```

=== "uv"

    ```bash
    # Update to latest
    uv tool upgrade threatforest
    
    # Reinstall
    uv tool install threatforest --force
    ```

=== "pip"

    ```bash
    # Activate venv
    source venv/bin/activate
    
    # Update
    pip install --upgrade threatforest
    ```

=== "Development"

    ```bash
    # Pull latest changes
    git pull origin main
    
    # Update dependencies
    pip install -e ".[dev]" --upgrade
    ```

---

## 🗑️ Uninstalling ThreatForest

If you need to remove ThreatForest:

=== "pipx"

    ```bash
    pipx uninstall threatforest
    ```

=== "uv"

    ```bash
    uv tool uninstall threatforest
    ```

=== "pip"

    ```bash
    # Activate venv
    source venv/bin/activate
    
    # Uninstall
    pip uninstall threatforest
    
    # Remove venv (optional)
    deactivate
    rm -rf venv
    ```

---

## 🆘 Installation Troubleshooting

### Issue: "command not found: threatforest"

**Cause:** PATH not configured correctly

**Solution:**

=== "pipx"

    ```bash
    # Ensure pipx paths
    python3 -m pipx ensurepath
    
    # Reload shell
    source ~/.bashrc  # or ~/.zshrc
    ```

=== "pip/venv"

    ```bash
    # Activate virtual environment first
    source venv/bin/activate
    
    # Then run
    threatforest
    ```

### Issue: "ModuleNotFoundError"

**Cause:** Dependencies not installed correctly

**Solution:**

```bash
# Reinstall with force
pipx install threatforest --force

# Or with pip
pip install --force-reinstall threatforest
```

### Issue: "Permission denied"

**Cause:** Insufficient permissions for system install

**Solution:**

```bash
# Use pipx instead of system pip
pipx install threatforest

# Or use uv
uv tool install threatforest
```

### Issue: SSL/Certificate Errors

**Cause:** Corporate proxy or firewall

**Solution:**

```bash
# Set proxy
export HTTP_PROXY="http://proxy:port"
export HTTPS_PROXY="http://proxy:port"

# Or disable SSL verification (not recommended for production)
pip install --trusted-host pypi.org --trusted-host files.pythonhosted.org threatforest
```

---

## 📚 Next Steps

Now that ThreatForest is installed:

1. [Configure your LLM provider](configuration.md)
2. [Run your first analysis](quick-start.md)
3. [Learn about workflows](../user-guide/workflows.md)
4. [Explore examples](../examples/index.md)

---

## 💡 Pro Tips

!!! tip "Use pipx or uv"
    These tools handle virtual environments automatically and provide global commands. Much easier than managing venvs manually!

!!! tip "Development Workflow"
    For development, use `pip install -e ".[dev]"` (pip) or `uv run` (uv) to avoid reinstalling after every code change.

!!! tip "Multiple Versions"
    Use `pipx` or `uv` to install different versions side-by-side:
    ```bash
    pipx install threatforest --suffix=@1.0.0
    pipx install threatforest --suffix=@latest
    ```

---

<div class="cta-section" markdown>

## Installation Complete? 🎉

Ready to configure ThreatForest and run your first analysis!

[Configure ThreatForest](configuration.md){ .md-button .md-button--primary }
[Quick Start Guide](quick-start.md){ .md-button }

</div>
