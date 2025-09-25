#!/usr/bin/env python3
"""
Demo script to showcase the enhanced CLI features for Task 14.
"""

import tempfile
import os
from pathlib import Path
from threatforest.cli import main
from click.testing import CliRunner


def demo_cli_features():
    """Demonstrate the enhanced CLI features."""
    print("🌳 ThreatForest CLI Enhancement Demo")
    print("=" * 50)
    
    runner = CliRunner()
    
    # Demo 1: Welcome screen
    print("\n1. Welcome Screen:")
    print("-" * 20)
    result = runner.invoke(main, [])
    print(result.output)
    
    # Demo 2: Status command
    print("\n2. Status Command:")
    print("-" * 20)
    result = runner.invoke(main, ['status'])
    print(result.output)
    
    # Demo 3: Examples flag
    print("\n3. Usage Examples:")
    print("-" * 20)
    result = runner.invoke(main, ['analyze', '--examples'])
    print(result.output)
    
    # Demo 4: Init command
    print("\n4. Project Initialization:")
    print("-" * 20)
    with tempfile.TemporaryDirectory() as temp_dir:
        demo_project = Path(temp_dir) / "demo_project"
        
        # Use input simulation for the confirmation
        result = runner.invoke(main, ['init', str(demo_project)], input='y\n')
        print(result.output)
        
        # Show created files
        if demo_project.exists():
            print(f"\nCreated files in {demo_project}:")
            for file_path in demo_project.rglob('*'):
                if file_path.is_file():
                    print(f"  📄 {file_path.relative_to(demo_project)}")
    
    # Demo 5: Dry run with verbose
    print("\n5. Dry Run Analysis:")
    print("-" * 20)
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create sample files
        readme = Path(temp_dir) / "README.md"
        readme.write_text("# Demo Project\nThis is a demo project using Python and Docker.")
        
        threats = Path(temp_dir) / "threats.md"
        threats.write_text("# Threats\n## T001: Sample Threat\n- **Severity**: High")
        
        result = runner.invoke(main, ['analyze', temp_dir, '--dry-run', '--verbose'])
        print(result.output)
    
    print("\n🎉 Demo completed! The enhanced CLI features include:")
    print("  ✅ Interactive welcome screen")
    print("  ✅ System status checking")
    print("  ✅ Comprehensive usage examples")
    print("  ✅ Project initialization with templates")
    print("  ✅ Enhanced progress reporting")
    print("  ✅ Interactive validation prompts")
    print("  ✅ Improved error handling and help")


if __name__ == "__main__":
    demo_cli_features()