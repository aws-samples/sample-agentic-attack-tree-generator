#!/usr/bin/env python3
"""
ThreatForest - AI-Driven Threat Modeling & Attack Tree Generation

Main entry point for the ThreatForest application.
Usage: python threatforest.py
"""

import sys
import subprocess
from pathlib import Path

def main():
    """Launch ThreatForest React Ink UI"""
    ui_dir = Path(__file__).parent / "ui"
    cli_path = ui_dir / "dist" / "cli.js"
    
    # Check if UI is built
    if not cli_path.exists():
        print("❌ React UI not built yet.")
        print("\n📦 Build instructions:")
        print("   cd ui")
        print("   npm install")
        print("   npm run build:cli")
        print("   cd ..")
        print("   python threatforest.py")
        sys.exit(1)
    
    # Launch React UI with any arguments passed
    try:
        subprocess.run(["node", str(cli_path)] + sys.argv[1:], cwd=ui_dir)
    except KeyboardInterrupt:
        print("\n\n👋 ThreatForest terminated")
        sys.exit(0)
    except Exception as e:
        print(f"❌ Error launching UI: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

