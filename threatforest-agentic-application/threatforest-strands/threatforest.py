#!/usr/bin/env python3
"""
ThreatForest - AI-Driven Threat Modeling & Attack Tree Generation

Main entry point for the ThreatForest application.
Usage: python threatforest.py
"""

import sys
import os
import subprocess
from pathlib import Path

def activate_venv():
    """Activate virtual environment if it exists"""
    venv_path = Path(__file__).parent / "venv"
    if venv_path.exists():
        # Update PATH to use venv python
        venv_bin = venv_path / "bin"
        os.environ["PATH"] = f"{venv_bin}:{os.environ['PATH']}"
        os.environ["VIRTUAL_ENV"] = str(venv_path)
        # Use venv python
        return str(venv_bin / "python")
    return sys.executable

def main():
    """Launch ThreatForest React Ink UI"""
    # Activate venv if available
    python_path = activate_venv()
    
    ui_dir = Path(__file__).parent / "ui"
    cli_path = ui_dir / "dist" / "cli.js"
    
    # Check if UI is built
    if not cli_path.exists():
        print("❌ React UI not built.")
        print("\n📦 Build the UI first:")
        print("   ./setup.sh")
        print("\nOr manually:")
        print("   cd ui")
        print("   npm install")
        print("   npm run build:cli")
        print("   cd ..")
        print("   python threatforest.py")
        sys.exit(1)
    
    # Launch React UI with any arguments passed
    try:
        env = os.environ.copy()
        env['NODE_ENV'] = 'production'
        env['PYTHON_PATH'] = python_path  # Pass venv python to UI
        subprocess.run(["node", str(cli_path)] + sys.argv[1:], cwd=ui_dir, env=env)
    except KeyboardInterrupt:
        print("\n\n👋 ThreatForest terminated")
        sys.exit(0)
    except Exception as e:
        print(f"❌ Error launching UI: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

