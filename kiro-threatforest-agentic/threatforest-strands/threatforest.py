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

def launch_react_ui():
    """Launch ThreatForest React Ink UI"""
    ui_dir = Path(__file__).parent / "ui"
    cli_path = ui_dir / "dist" / "cli.js"
    
    # Check if UI is built
    if not cli_path.exists():
        print("⚠️  React UI not built yet.")
        print("📦 To build: cd ui && npm install && npm run build:cli")
        return False
    
    # Launch React UI with any arguments passed
    try:
        subprocess.run(["node", str(cli_path)] + sys.argv[1:], cwd=ui_dir)
        return True
    except KeyboardInterrupt:
        print("\n\n👋 ThreatForest terminated")
        sys.exit(0)
    except Exception as e:
        print(f"❌ Error launching React UI: {e}")
        return False

def launch_python_wizard():
    """Fallback to Python wizard"""
    print("\n🐍 Launching Python wizard (fallback)...\n")
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))
    from threatforest_wizard import main
    main()

def main():
    """Main entry point - tries React UI first, falls back to Python wizard"""
    # Try React UI first
    if not launch_react_ui():
        # Fallback to Python wizard
        launch_python_wizard()

if __name__ == "__main__":
    main()

