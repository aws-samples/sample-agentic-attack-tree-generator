#!/usr/bin/env python3
"""
Quick installation script for ThreatForest.

This script provides an easy way to install ThreatForest with all dependencies.
"""

import os
import subprocess
import sys
from pathlib import Path


def run_command(cmd, description=""):
    """Run a command and handle errors."""
    print(f"🔧 {description}")
    try:
        result = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
        print(f"✅ {description} completed")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} failed:")
        print(f"   Command: {cmd}")
        print(f"   Error: {e.stderr}")
        return False


def check_python_version():
    """Check if Python version is compatible."""
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 9):
        print(f"❌ Python 3.9+ required, found {version.major}.{version.minor}")
        return False
    print(f"✅ Python {version.major}.{version.minor}.{version.micro} is compatible")
    return True


def check_virtual_environment():
    """Check if running in a virtual environment and offer to create one."""
    in_venv = hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix)
    
    if in_venv:
        print(f"✅ Running in virtual environment: {sys.prefix}")
        return True
    else:
        print("⚠️  Not running in a virtual environment")
        print("   Virtual environments are recommended to avoid dependency conflicts")
        
        # Ask user if they want to create a virtual environment
        try:
            response = input("Would you like to create a virtual environment? (y/N): ").strip().lower()
            if response in ['y', 'yes']:
                return create_virtual_environment()
            else:
                print("📝 Continuing with system Python (not recommended)")
                print("   You can create a virtual environment later with:")
                print("   python -m venv threatforest-env")
                print("   source threatforest-env/bin/activate  # Linux/macOS")
                print("   threatforest-env\\Scripts\\activate     # Windows")
                return True
        except KeyboardInterrupt:
            print("\n❌ Installation cancelled by user")
            return False


def create_virtual_environment():
    """Create and activate a virtual environment."""
    venv_name = "threatforest-env"
    
    print(f"🔧 Creating virtual environment: {venv_name}")
    
    try:
        # Create virtual environment
        if not run_command(f"python -m venv {venv_name}", "Creating virtual environment"):
            return False
        
        print(f"✅ Virtual environment created: {venv_name}")
        print("\n📋 To activate the virtual environment in the future:")
        
        if os.name == 'nt':  # Windows
            print(f"   {venv_name}\\Scripts\\activate")
        else:  # Linux/macOS
            print(f"   source {venv_name}/bin/activate")
        
        print("\n⚠️  Please activate the virtual environment and run this installer again:")
        if os.name == 'nt':  # Windows
            print(f"   {venv_name}\\Scripts\\activate")
        else:  # Linux/macOS
            print(f"   source {venv_name}/bin/activate")
        print("   python install.py")
        
        return False  # Return False to stop installation and let user activate venv
        
    except Exception as e:
        print(f"❌ Failed to create virtual environment: {e}")
        print("📝 You can create one manually with:")
        print("   python -m venv threatforest-env")
        return True  # Continue with system installation


def install_threatforest():
    """Install ThreatForest in development mode."""
    print("🚀 Installing ThreatForest")
    print("=" * 40)
    
    # Check Python version
    if not check_python_version():
        return False
    
    # Check virtual environment
    if not check_virtual_environment():
        return False
    
    # Install in development mode
    if not run_command("pip install -e .", "Installing ThreatForest in development mode"):
        return False
    
    # Install development dependencies
    if os.path.exists("requirements-dev.txt"):
        if not run_command("pip install -r requirements-dev.txt", "Installing development dependencies"):
            print("⚠️  Development dependencies installation failed (optional)")
    
    # Verify installation
    if not run_command("tf --version", "Verifying ThreatForest installation"):
        return False
    
    print("\n" + "=" * 40)
    print("🎉 ThreatForest installation complete!")
    print("\nNext steps:")
    print("1. Configure AWS credentials: aws configure")
    print("2. Run setup wizard: tf setup")
    print("3. Check system status: tf status")
    print("4. Analyze a project: tf analyze")
    print("\nFor help: tf --help")
    
    return True


def main():
    """Main installation function."""
    # Change to script directory
    script_dir = Path(__file__).parent
    os.chdir(script_dir)
    
    if install_threatforest():
        sys.exit(0)
    else:
        print("\n❌ Installation failed. Please check the errors above.")
        sys.exit(1)


if __name__ == "__main__":
    main()