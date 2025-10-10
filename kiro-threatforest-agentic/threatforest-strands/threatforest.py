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

def build_ui(ui_dir):
    """Build the React UI automatically"""
    print("📦 Building React UI (first time setup)...")
    
    # Check if node_modules exists
    if not (ui_dir / "node_modules").exists():
        print("   Installing dependencies...")
        result = subprocess.run(["npm", "install"], cwd=ui_dir, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"❌ npm install failed: {result.stderr}")
            return False
    
    # Build the CLI
    print("   Building CLI...")
    result = subprocess.run(["npm", "run", "build:cli"], cwd=ui_dir, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"❌ Build failed: {result.stderr}")
        return False
    
    print("✅ UI built successfully!\n")
    return True

def main():
    """Launch ThreatForest React Ink UI"""
    ui_dir = Path(__file__).parent / "ui"
    cli_path = ui_dir / "dist" / "cli.js"
    
    # Check if UI is built, build if needed
    if not cli_path.exists():
        if not build_ui(ui_dir):
            print("\n❌ Failed to build UI automatically.")
            print("\n📦 Manual build instructions:")
            print("   cd ui")
            print("   npm install")
            print("   npm run build:cli")
            sys.exit(1)
    
    # Launch React UI with any arguments passed
    try:
        env = os.environ.copy()
        env['NODE_ENV'] = 'production'  # Skip devtools
        subprocess.run(["node", str(cli_path)] + sys.argv[1:], cwd=ui_dir, env=env)
    except KeyboardInterrupt:
        print("\n\n👋 ThreatForest terminated")
        sys.exit(0)
    except Exception as e:
        print(f"❌ Error launching UI: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

