#!/usr/bin/env python3
"""
ThreatForest - AI-Driven Threat Modeling & Attack Tree Generation

Main entry point for the ThreatForest application.
Usage: python threatforest.py
"""

import sys
from pathlib import Path

# Add src to path so we can import the package
sys.path.insert(0, str(Path(__file__).parent / "src"))

from threatforest.cli import main

if __name__ == "__main__":
    main()
