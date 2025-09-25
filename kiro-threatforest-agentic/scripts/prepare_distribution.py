#!/usr/bin/env python3
"""
Script to prepare ThreatForest for distribution.

This script cleans up the project directory and creates a distributable package.
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path


def run_command(cmd, cwd=None):
    """Run a command and return the result."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, cwd=cwd
        )
        return result.returncode == 0, result.stdout, result.stderr
    except Exception as e:
        return False, "", str(e)


def clean_project():
    """Clean up build artifacts and temporary files."""
    print("🧹 Cleaning project directory...")
    
    # Directories to remove
    dirs_to_remove = [
        "build",
        "dist",
        "*.egg-info",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".coverage",
        "htmlcov",
        "tf-output",
    ]
    
    for pattern in dirs_to_remove:
        if "*" in pattern:
            # Use shell expansion for patterns
            success, stdout, stderr = run_command(f"rm -rf {pattern}")
        else:
            if os.path.exists(pattern):
                if os.path.isdir(pattern):
                    shutil.rmtree(pattern)
                else:
                    os.remove(pattern)
                print(f"  ✅ Removed {pattern}")
    
    # Remove Python cache files
    success, stdout, stderr = run_command("find . -name '*.pyc' -delete")
    success, stdout, stderr = run_command("find . -name '__pycache__' -type d -exec rm -rf {} +")
    
    print("✅ Project cleaned")


def validate_structure():
    """Validate the project structure."""
    print("🔍 Validating project structure...")
    
    required_files = [
        "README.md",
        "pyproject.toml",
        "setup.py",
        "LICENSE",
        "MANIFEST.in",
        "threatforest/__init__.py",
        "threatforest/cli.py",
        "threatforest/config.py",
    ]
    
    missing_files = []
    for file_path in required_files:
        if not os.path.exists(file_path):
            missing_files.append(file_path)
    
    if missing_files:
        print(f"❌ Missing required files: {missing_files}")
        return False
    
    print("✅ Project structure validated")
    return True


def run_tests():
    """Run tests to ensure everything works."""
    print("🧪 Running tests...")
    
    success, stdout, stderr = run_command("python -m pytest tests/ -v --tb=short")
    if not success:
        print(f"❌ Tests failed:\n{stderr}")
        return False
    
    print("✅ All tests passed")
    return True


def build_package():
    """Build the distribution package."""
    print("📦 Building distribution package...")
    
    # Build source distribution
    success, stdout, stderr = run_command("python -m build --sdist")
    if not success:
        print(f"❌ Source distribution build failed:\n{stderr}")
        return False
    
    # Build wheel distribution
    success, stdout, stderr = run_command("python -m build --wheel")
    if not success:
        print(f"❌ Wheel distribution build failed:\n{stderr}")
        return False
    
    print("✅ Distribution packages built")
    return True


def create_zip_archive():
    """Create a zip archive of the project."""
    print("📁 Creating zip archive...")
    
    project_name = "threatforest"
    archive_name = f"{project_name}-distribution"
    
    # Create temporary directory for clean copy
    temp_dir = f"/tmp/{archive_name}"
    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir)
    
    # Copy project files
    shutil.copytree(".", temp_dir, ignore=shutil.ignore_patterns(
        "venv", ".venv", ".git", ".kiro", "__pycache__", "*.pyc",
        ".pytest_cache", ".mypy_cache", "tf-output", "*.egg-info",
        "build", "dist"
    ))
    
    # Create zip archive
    archive_path = f"{archive_name}.zip"
    success, stdout, stderr = run_command(f"cd /tmp && zip -r {os.getcwd()}/{archive_path} {archive_name}")
    
    if success:
        print(f"✅ Zip archive created: {archive_path}")
        return True
    else:
        print(f"❌ Failed to create zip archive:\n{stderr}")
        return False


def main():
    """Main function."""
    print("🚀 Preparing ThreatForest for distribution")
    print("=" * 50)
    
    # Change to project root
    script_dir = Path(__file__).parent
    project_root = script_dir.parent
    os.chdir(project_root)
    
    steps = [
        ("Clean project", clean_project),
        ("Validate structure", validate_structure),
        ("Run tests", run_tests),
        ("Build package", build_package),
        ("Create zip archive", create_zip_archive),
    ]
    
    for step_name, step_func in steps:
        print(f"\n📋 {step_name}...")
        try:
            if not step_func():
                print(f"❌ {step_name} failed")
                sys.exit(1)
        except Exception as e:
            print(f"❌ {step_name} failed with error: {e}")
            sys.exit(1)
    
    print("\n" + "=" * 50)
    print("🎉 ThreatForest distribution preparation complete!")
    print("\nGenerated files:")
    print("  📦 dist/ - Python packages (wheel and source)")
    print("  📁 threatforest-distribution.zip - Complete project archive")
    print("\nThe project is ready for distribution and sharing.")


if __name__ == "__main__":
    main()