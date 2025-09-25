# Virtual Environments Guide for ThreatForest

## 🔒 Why Use Virtual Environments?

Virtual environments are isolated Python environments that allow you to install packages without affecting your system Python installation. This is especially important for ThreatForest because:

### Benefits
- **🛡️ Dependency Isolation**: Prevents conflicts with other Python projects
- **🧹 Clean Uninstall**: Easy to remove by deleting the virtual environment directory
- **📌 Version Control**: Lock specific dependency versions for reproducibility
- **🔒 System Protection**: Keeps your system Python installation clean and stable
- **🔄 Multiple Versions**: Run different versions of ThreatForest simultaneously

### Without Virtual Environment (Problems)
```bash
# System-wide installation can cause:
pip install threatforest  # May conflict with existing packages
pip install other-project # May break ThreatForest dependencies
# Difficult to uninstall cleanly
# Version conflicts between projects
```

### With Virtual Environment (Recommended)
```bash
# Each project has its own isolated environment
python -m venv threatforest-env
source threatforest-env/bin/activate
pip install threatforest  # Isolated installation
deactivate  # Clean separation
```

## 🚀 Quick Setup Guide

### 1. Create Virtual Environment

```bash
# Create a new virtual environment
python -m venv threatforest-env

# Alternative: Use a different name
python -m venv tf-venv
python -m venv .venv  # Hidden directory
```

### 2. Activate Virtual Environment

**Linux/macOS:**
```bash
source threatforest-env/bin/activate
```

**Windows (Command Prompt):**
```cmd
threatforest-env\Scripts\activate
```

**Windows (PowerShell):**
```powershell
threatforest-env\Scripts\Activate.ps1
```

### 3. Verify Activation

When activated, your prompt should show the environment name:
```bash
(threatforest-env) $ python --version
(threatforest-env) $ which python  # Should point to venv
```

### 4. Install ThreatForest

```bash
(threatforest-env) $ python install.py
# OR
(threatforest-env) $ pip install -e .
```

### 5. Deactivate When Done

```bash
(threatforest-env) $ deactivate
$ # Back to system Python
```

## 🔧 Advanced Virtual Environment Management

### Using Different Python Versions

```bash
# Use specific Python version
python3.9 -m venv threatforest-py39
python3.11 -m venv threatforest-py311

# Activate specific version
source threatforest-py39/bin/activate
```

### Virtual Environment with Custom Location

```bash
# Create in custom directory
python -m venv /path/to/custom/location/tf-env
source /path/to/custom/location/tf-env/bin/activate
```

### Upgrading pip in Virtual Environment

```bash
# Always upgrade pip after creating venv
source threatforest-env/bin/activate
pip install --upgrade pip
```

## 📋 Virtual Environment Best Practices

### 1. Naming Conventions
```bash
# Good names
python -m venv threatforest-env
python -m venv tf-dev
python -m venv .venv  # Hidden, project-specific

# Avoid generic names
python -m venv env    # Too generic
python -m venv venv   # Confusing with command
```

### 2. Location
```bash
# Option 1: In project directory (add to .gitignore)
cd threatforest/
python -m venv .venv
echo ".venv/" >> .gitignore

# Option 2: In dedicated directory
mkdir ~/venvs
python -m venv ~/venvs/threatforest
```

### 3. Requirements Management
```bash
# Save current environment
pip freeze > requirements.txt

# Recreate environment elsewhere
pip install -r requirements.txt
```

## 🛠️ Troubleshooting Virtual Environments

### Common Issues

#### Virtual Environment Not Activating
```bash
# Check if file exists
ls threatforest-env/bin/activate  # Linux/macOS
ls threatforest-env\Scripts\activate  # Windows

# Recreate if missing
rm -rf threatforest-env
python -m venv threatforest-env
```

#### Command Not Found After Installation
```bash
# Ensure virtual environment is activated
source threatforest-env/bin/activate

# Check if ThreatForest is installed
pip list | grep threatforest

# Reinstall if missing
pip install -e .
```

#### Permission Errors
```bash
# Don't use sudo with virtual environments
# Instead, fix permissions or use different location
python -m venv ~/threatforest-env
```

#### Python Version Issues
```bash
# Check Python version in venv
source threatforest-env/bin/activate
python --version

# Recreate with specific Python version
rm -rf threatforest-env
python3.9 -m venv threatforest-env
```

### Cleaning Up

#### Remove Virtual Environment
```bash
# Simply delete the directory
rm -rf threatforest-env

# Or on Windows
rmdir /s threatforest-env
```

#### Start Fresh
```bash
# Complete clean installation
rm -rf threatforest-env
python -m venv threatforest-env
source threatforest-env/bin/activate
pip install --upgrade pip
python install.py
```

## 🔄 Integration with ThreatForest

### Automatic Detection

The `install.py` script automatically:
- ✅ Detects if you're in a virtual environment
- ✅ Warns if you're not using one
- ✅ Offers to create one for you
- ✅ Provides activation instructions

### Manual Setup with ThreatForest

```bash
# Complete setup from scratch
git clone https://github.com/threatforest/threatforest.git
cd threatforest

# Create and activate virtual environment
python -m venv threatforest-env
source threatforest-env/bin/activate

# Install ThreatForest
python install.py

# Verify installation
tf --version
tf status

# Use ThreatForest
tf analyze

# Deactivate when done
deactivate
```

### Development Workflow

```bash
# Daily workflow
source threatforest-env/bin/activate
tf analyze my-project/
tf config validate
deactivate

# Development workflow
source threatforest-env/bin/activate
pip install -e ".[dev]"
python -m pytest tests/
tf analyze --verbose
deactivate
```

## 📚 Additional Resources

### Virtual Environment Tools
- **venv**: Built-in Python tool (recommended)
- **virtualenv**: Third-party alternative with more features
- **conda**: Package and environment manager
- **pipenv**: Higher-level tool combining pip and venv
- **poetry**: Modern dependency management

### Documentation Links
- [Python venv documentation](https://docs.python.org/3/library/venv.html)
- [Virtual Environments and Packages](https://docs.python.org/3/tutorial/venv.html)
- [pip User Guide](https://pip.pypa.io/en/stable/user_guide/)

## 🎯 Summary

Virtual environments are essential for Python development and strongly recommended for ThreatForest:

1. **Create**: `python -m venv threatforest-env`
2. **Activate**: `source threatforest-env/bin/activate`
3. **Install**: `python install.py`
4. **Use**: `tf analyze`
5. **Deactivate**: `deactivate`

This approach ensures a clean, isolated, and reproducible ThreatForest installation that won't interfere with your system or other Python projects.