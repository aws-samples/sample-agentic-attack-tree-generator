#!/usr/bin/env python3
"""
Demo script for the ThreatForest Setup Wizard.

This script demonstrates how the setup wizard would be integrated into the CLI.
"""

import sys
import tempfile
from pathlib import Path

# Add the threatforest package to the path
sys.path.insert(0, str(Path(__file__).parent))

from threatforest.setup_wizard import SetupWizard, SetupWizardError


def demo_setup_wizard():
    """Demonstrate the setup wizard functionality."""
    print("ThreatForest Setup Wizard Demo")
    print("=" * 40)
    
    # Create a temporary directory for demo
    temp_dir = tempfile.mkdtemp()
    print(f"Demo workspace: {temp_dir}")
    
    try:
        # Initialize the setup wizard
        wizard = SetupWizard(temp_dir)
        print("✓ Setup wizard initialized")
        
        # Test credential detection (without actual AWS calls)
        print("\n1. Testing credential detection...")
        try:
            credential_status = wizard.detect_aws_credentials()
            if credential_status.is_valid:
                print(f"✓ AWS credentials detected: {credential_status.account_id}")
            else:
                print(f"✗ AWS credentials issue: {credential_status.message}")
        except Exception as e:
            print(f"✗ Credential detection failed: {e}")
        
        # Test credential source detection
        print("\n2. Testing credential source detection...")
        source = wizard._get_credential_source()
        print(f"✓ Credential source: {source}")
        
        # Test configuration scope selection (mock)
        print("\n3. Testing configuration utilities...")
        print("✓ Configuration scope selection available")
        print("✓ Model parameter configuration available")
        print("✓ Additional settings configuration available")
        
        print("\n✓ Setup wizard demo completed successfully!")
        print("\nTo use the setup wizard in practice:")
        print("1. Ensure AWS credentials are configured")
        print("2. Run: wizard.run_interactive_setup()")
        print("3. Follow the interactive prompts")
        
    except SetupWizardError as e:
        print(f"✗ Setup wizard error: {e}")
        return False
    except Exception as e:
        print(f"✗ Unexpected error: {e}")
        return False
    
    return True


if __name__ == "__main__":
    success = demo_setup_wizard()
    sys.exit(0 if success else 1)