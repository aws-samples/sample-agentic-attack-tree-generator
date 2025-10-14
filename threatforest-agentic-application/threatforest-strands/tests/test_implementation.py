#!/usr/bin/env python3
"""Test script for ThreatForest Strands implementation"""

import asyncio
import sys
from pathlib import Path

# Add the threatforest package to path
sys.path.insert(0, str(Path(__file__).parent))

from threatforest.strands_agent import run_threatforest
from rich.console import Console

console = Console()


async def test_threatforest():
    """Test the ThreatForest implementation"""
    
    console.print("[bold blue]🧪 Testing ThreatForest Implementation[/bold blue]\n")
    
    # Test with genai-chatbot-example directory
    test_project = Path(__file__).parent / "genai-chatbot-example"
    
    if not test_project.exists():
        console.print(f"❌ Test project not found: {test_project}")
        return
    
    console.print(f"📁 Testing with project: [cyan]{test_project}[/cyan]")
    
    try:
        result = await run_threatforest(
            project_path=str(test_project),
            bedrock_model="anthropic.claude-3-5-sonnet-20241022-v2:0"
        )
        
        console.print(f"\n📊 [bold]Test Results:[/bold]")
        console.print(f"Status: [{'green' if result['status'] == 'success' else 'red'}]{result['status']}[/]")
        
        if result["status"] == "success":
            console.print(f"Application: [cyan]{result.get('application_name', 'Unknown')}[/cyan]")
            console.print(f"Output directory: [cyan]{result.get('output_directory')}[/cyan]")
            
            if result.get("output_files"):
                console.print("\n📄 Generated files:")
                for file_path in result["output_files"]:
                    console.print(f"  • {file_path}")
        else:
            console.print(f"Error: [red]{result.get('error', 'Unknown error')}[/red]")
            
            if "setup_result" in result:
                setup = result["setup_result"]
                console.print(f"\n🔧 Setup Status:")
                console.print(f"  • AWS: {setup.get('aws_status')}")
                console.print(f"  • Bedrock: {setup.get('bedrock_status')}")
                console.print(f"  • VEnv: {setup.get('venv_status')}")
        
    except Exception as e:
        console.print(f"❌ [red]Test failed with exception: {str(e)}[/red]")
        import traceback
        console.print(traceback.format_exc())


if __name__ == "__main__":
    asyncio.run(test_threatforest())
