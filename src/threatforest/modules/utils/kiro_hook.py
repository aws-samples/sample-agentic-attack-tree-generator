#!/usr/bin/env python3
"""
Kiro IDE Hook Handler for ThreatForest
Automatically triggers ThreatForest analysis when ThreatComposer files are modified
"""
import sys
import os
from pathlib import Path
from typing import Dict, Any, Optional
import json
from datetime import datetime


def setup_paths():
    """Setup Python paths to import ThreatForest modules"""
    # Get the ThreatForest root directory
    current_file = Path(__file__).resolve()
    threatforest_root = current_file.parent.parent.parent.parent
    
    # Add to Python path
    if str(threatforest_root) not in sys.path:
        sys.path.insert(0, str(threatforest_root))
    
    return threatforest_root


def check_dependencies(root_dir: Path) -> tuple[bool, str]:
    """Check if required dependencies are installed
    
    Args:
        root_dir: ThreatForest root directory
        
    Returns:
        Tuple of (dependencies_ok, error_message)
    """
    required_modules = ['strands', 'yaml', 'boto3', 'rich']
    missing = []
    
    for module in required_modules:
        try:
            __import__(module)
        except ImportError:
            missing.append(module)
    
    if missing:
        setup_msg = f"""
╔════════════════════════════════════════════════════════════════╗
║  ⚠️  ThreatForest Dependencies Not Installed                   ║
╚════════════════════════════════════════════════════════════════╝

Missing Python packages: {', '.join(missing)}

This is a one-time setup. Please run:

    cd {root_dir}
    
    # Create virtual environment (if not exists)
    python3 -m venv venv
    
    # Activate virtual environment
    source venv/bin/activate
    
    # Install dependencies
    pip install -r requirements.txt

Then the Kiro hook will work automatically on every save!

Alternatively, if you have dependencies installed globally or in
a different environment, make sure that Python environment is active
when Kiro runs.
"""
        return False, setup_msg
    
    return True, ""


def validate_threatcomposer_file(tc_file_path: str) -> tuple[bool, str]:
    """Validate that the file is a valid ThreatComposer file
    
    Args:
        tc_file_path: Path to the ThreatComposer file
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    tc_path = Path(tc_file_path)
    
    # Check file exists
    if not tc_path.exists():
        return False, f"File not found: {tc_file_path}"
    
    # Check it's a .tc.json file
    if not tc_path.name.endswith('.tc.json'):
        return False, f"Not a ThreatComposer file (must end with .tc.json): {tc_path.name}"
    
    # Check it's valid JSON
    try:
        with open(tc_path, 'r') as f:
            data = json.load(f)
            
        # Basic validation - ThreatComposer files should have certain structure
        if not isinstance(data, dict):
            return False, "Invalid ThreatComposer file structure (not a JSON object)"
            
    except json.JSONDecodeError as e:
        return False, f"Invalid JSON in ThreatComposer file: {e}"
    except Exception as e:
        return False, f"Error reading ThreatComposer file: {e}"
    
    return True, ""


def determine_project_directory(tc_file_path: str) -> Path:
    """Determine the project directory from the ThreatComposer file location
    
    Args:
        tc_file_path: Path to the ThreatComposer file
        
    Returns:
        Path to the project directory
    """
    tc_path = Path(tc_file_path).resolve()
    
    # The project directory is the parent directory of the .tc.json file
    project_dir = tc_path.parent
    
    return project_dir


def load_kiro_config() -> Dict[str, Any]:
    """Load Kiro integration configuration from config.yaml
    
    Returns:
        Dict containing configuration settings
    """
    setup_paths()
    
    try:
        from threatforest.config import config
        
        # Get Kiro integration settings if they exist
        kiro_config = getattr(config, 'kiro_integration', {})
        
        # Defaults
        default_config = {
            'enabled': True,
            'auto_run_on_save': True,
            'notification_level': 'summary',  # full/summary/silent
            'timeout_seconds': 300  # 5 minutes
        }
        
        # Merge with defaults
        if isinstance(kiro_config, dict):
            default_config.update(kiro_config)
        
        return default_config
        
    except Exception as e:
        print(f"⚠️  Warning: Could not load config.yaml, using defaults: {e}")
        return {
            'enabled': True,
            'auto_run_on_save': True,
            'notification_level': 'summary',
            'timeout_seconds': 300
        }


def handle_threatcomposer_change(tc_file_path: str) -> Dict[str, Any]:
    """Main handler called by Kiro hook when a ThreatComposer file is saved
    
    Args:
        tc_file_path: Path to the ThreatComposer file that was modified
        
    Returns:
        Result dict with status, message, and output location
    """
    start_time = datetime.now()
    
    print(f"\n{'='*60}")
    print(f"🔍 ThreatForest Kiro Hook Triggered")
    print(f"{'='*60}")
    print(f"📁 File: {tc_file_path}")
    
    # Load configuration
    kiro_config = load_kiro_config()
    
    # Check if integration is enabled
    if not kiro_config.get('enabled', True):
        message = "Kiro integration is disabled in config.yaml"
        print(f"⚠️  {message}")
        return {
            'status': 'skipped',
            'message': message
        }
    
    # Validate the ThreatComposer file
    is_valid, error_msg = validate_threatcomposer_file(tc_file_path)
    if not is_valid:
        print(f"❌ Validation failed: {error_msg}")
        return {
            'status': 'error',
            'message': f"Invalid ThreatComposer file: {error_msg}"
        }
    
    print(f"✅ ThreatComposer file validated")
    
    # Determine project directory
    project_dir = determine_project_directory(tc_file_path)
    print(f"📂 Project directory: {project_dir}")
    
    # Setup paths for imports
    root_dir = setup_paths()
    
    # Check dependencies before proceeding
    deps_ok, deps_msg = check_dependencies(root_dir)
    if not deps_ok:
        print(deps_msg)
        return {
            'status': 'error',
            'message': 'Dependencies not installed. Please run setup (see output above).'
        }
    
    try:
        # Import ThreatForest modules
        from threatforest.orchestrator import ThreatForestOrchestrator, ThreatForestConfig
        from threatforest.config import config
        
        print(f"\n🚀 Starting ThreatForest analysis...")
        print(f"   Model: {config.default_bedrock_model}")
        print(f"   AWS Profile: {config.default_aws_profile}")
        
        # Create ThreatForest configuration
        tf_config = ThreatForestConfig(
            project_path=project_dir,
            threat_model_path=tc_file_path,
            aws_profile=config.default_aws_profile,
            bedrock_model=config.default_bedrock_model,
            resume=False
        )
        
        # Create orchestrator
        orchestrator = ThreatForestOrchestrator(tf_config)
        
        # Execute workflow
        result = orchestrator.execute_workflow()
        
        elapsed_time = (datetime.now() - start_time).total_seconds()
        
        # Process result
        if result.get('status') == 'success':
            output_dir = result.get('output_directory', 'unknown')
            app_name = result.get('application_name', 'unknown')
            
            print(f"\n{'='*60}")
            print(f"✅ ThreatForest Analysis Complete!")
            print(f"{'='*60}")
            print(f"⏱️  Time: {elapsed_time:.1f}s")
            print(f"📊 Application: {app_name}")
            print(f"📁 Output: {output_dir}")
            
            # Check for dashboard
            dashboard_path = Path(output_dir) / 'attack_trees_dashboard.html'
            if dashboard_path.exists():
                print(f"🌐 Dashboard: {dashboard_path}")
            
            print(f"{'='*60}\n")
            
            return {
                'status': 'success',
                'message': 'ThreatForest analysis completed successfully',
                'output_directory': str(output_dir),
                'application_name': app_name,
                'elapsed_seconds': elapsed_time,
                'dashboard_path': str(dashboard_path) if dashboard_path.exists() else None
            }
        else:
            error = result.get('error', 'Unknown error')
            print(f"\n❌ ThreatForest Analysis Failed")
            print(f"   Error: {error}")
            print(f"   Stage: {result.get('stage', 'unknown')}")
            
            return {
                'status': 'error',
                'message': f"ThreatForest analysis failed: {error}",
                'stage': result.get('stage', 'unknown'),
                'elapsed_seconds': elapsed_time
            }
            
    except Exception as e:
        elapsed_time = (datetime.now() - start_time).total_seconds()
        error_msg = str(e)
        
        print(f"\n❌ Unexpected Error")
        print(f"   {error_msg}")
        
        import traceback
        print(f"\n📋 Traceback:")
        print(traceback.format_exc())
        
        return {
            'status': 'error',
            'message': f"Unexpected error: {error_msg}",
            'elapsed_seconds': elapsed_time
        }


def main():
    """CLI entry point for the Kiro hook"""
    if len(sys.argv) < 2:
        print("Usage: kiro_hook.py <path-to-threatcomposer-file.tc.json>")
        print("\nThis script is designed to be called by Kiro IDE hooks.")
        print("It automatically triggers ThreatForest analysis when ThreatComposer files are saved.")
        sys.exit(1)
    
    tc_file_path = sys.argv[1]
    
    # Execute the hook handler
    result = handle_threatcomposer_change(tc_file_path)
    
    # Exit with appropriate status code
    if result['status'] == 'success':
        sys.exit(0)
    elif result['status'] == 'skipped':
        sys.exit(0)  # Not an error, just skipped
    else:
        sys.exit(1)  # Error occurred


if __name__ == '__main__':
    main()
