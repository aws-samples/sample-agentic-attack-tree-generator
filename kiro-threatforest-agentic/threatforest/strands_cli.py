"""Strands-based CLI for ThreatForest"""
import asyncio
import click
from pathlib import Path
from rich.console import Console
from rich.panel import Panel

from .strands_agent import run_threatforest

console = Console()


@click.command()
@click.option("--project-path", "-p", default=".", help="Path to project directory")
@click.option("--aws-profile", help="AWS profile to use")
@click.option("--bedrock-model", default="anthropic.claude-3-haiku-20240307-v1:0", help="Bedrock model ID")
@click.option("--output-dir", help="Output directory for generated files")
@click.option("--ttc-threshold", default=0.8, help="TTC mapping threshold")
def main(project_path: str, aws_profile: str, bedrock_model: str, output_dir: str, ttc_threshold: float):
    """ThreatForest - Agentic Attack Tree Generator"""
    
    console.print(Panel.fit(
        "[bold blue]ThreatForest[/bold blue]\n"
        "Agentic AI for Attack Tree Generation",
        border_style="blue"
    ))
    
    # Convert to absolute path
    project_path = Path(project_path).resolve()
    
    console.print(f"🔍 Analyzing project: [cyan]{project_path}[/cyan]")
    
    # Run the Strands-based workflow
    try:
        result = asyncio.run(run_threatforest(
            project_path=str(project_path),
            aws_profile=aws_profile,
            bedrock_model=bedrock_model,
            output_dir=output_dir,
            ttc_threshold=ttc_threshold
        ))
        
        if result["status"] == "success":
            console.print("✅ [green]ThreatForest execution completed successfully![/green]")
            
            if "output_files" in result:
                console.print("\n📁 Generated files:")
                for file_path in result["output_files"]:
                    console.print(f"  • {file_path}")
        else:
            console.print(f"❌ [red]Error: {result.get('error', 'Unknown error')}[/red]")
            
    except Exception as e:
        console.print(f"❌ [red]Fatal error: {str(e)}[/red]")


if __name__ == "__main__":
    main()
