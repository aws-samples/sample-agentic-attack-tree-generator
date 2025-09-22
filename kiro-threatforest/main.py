#!/usr/bin/env python3
"""
Main entry point for ThreatForest application.
"""

import sys
import os

# Add current directory to Python path to allow imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from threat_forest.cli import main
except ImportError as e:
    print(f"Error importing ThreatForest: {e}")
    print("Make sure you have installed the required dependencies:")
    print("  pip install -r requirements.txt")
    sys.exit(1)

if __name__ == "__main__":
    sys.exit(main())