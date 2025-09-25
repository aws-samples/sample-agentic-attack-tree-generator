"""Context Analysis Tool for discovering and parsing project files"""
import os
from pathlib import Path
from typing import Dict, List, Any

from strands import Tool


class ContextAnalysisTool(Tool):
    """Tool for analyzing project context files"""
    
    def __init__(self):
        super().__init__(
            name="context_analysis",
            description="Discover and analyze context files including READMEs, architecture diagrams, and threat statements"
        )
    
    async def execute(self, project_path: str) -> Dict[str, Any]:
        """Execute context analysis"""
        project_dir = Path(project_path)
        
        context_files = {
            "readmes": [],
            "architecture_diagrams": [],
            "data_flow_diagrams": [],
            "threat_statements": [],
            "other_docs": []
        }
        
        # Search for relevant files
        for file_path in project_dir.rglob("*"):
            if file_path.is_file():
                self._categorize_file(file_path, context_files)
        
        # Parse file contents
        parsed_files = {}
        for category, files in context_files.items():
            parsed_files[category] = []
            for file_path in files:
                content = self._parse_file(file_path)
                if content:
                    parsed_files[category].append({
                        "path": str(file_path),
                        "content": content,
                        "size": file_path.stat().st_size
                    })
        
        return {
            "project_path": project_path,
            "discovered_files": context_files,
            "parsed_content": parsed_files,
            "summary": self._generate_summary(parsed_files)
        }
    
    def _categorize_file(self, file_path: Path, context_files: Dict[str, List]) -> None:
        """Categorize file based on name and extension"""
        name_lower = file_path.name.lower()
        
        # READMEs
        if name_lower.startswith("readme"):
            context_files["readmes"].append(file_path)
        
        # Architecture diagrams
        elif any(keyword in name_lower for keyword in ["architecture", "arch", "design", "system"]):
            if file_path.suffix.lower() in [".png", ".jpg", ".svg", ".puml", ".md", ".mmd"]:
                context_files["architecture_diagrams"].append(file_path)
        
        # Data flow diagrams
        elif any(keyword in name_lower for keyword in ["dataflow", "data_flow", "dfd", "flow"]):
            context_files["data_flow_diagrams"].append(file_path)
        
        # Threat statements
        elif any(keyword in name_lower for keyword in ["threat", "security", "risk", "attack"]):
            if file_path.suffix.lower() in [".md", ".txt", ".json", ".yaml", ".yml"]:
                context_files["threat_statements"].append(file_path)
        
        # Other documentation
        elif file_path.suffix.lower() in [".md", ".txt", ".doc", ".docx"]:
            context_files["other_docs"].append(file_path)
    
    def _parse_file(self, file_path: Path) -> str:
        """Parse file content based on type"""
        try:
            if file_path.suffix.lower() in [".md", ".txt", ".yaml", ".yml", ".json"]:
                return file_path.read_text(encoding="utf-8")
            elif file_path.suffix.lower() in [".png", ".jpg", ".svg"]:
                return f"[IMAGE FILE: {file_path.name}]"
            else:
                return f"[BINARY FILE: {file_path.name}]"
        except Exception as e:
            return f"[ERROR READING FILE: {str(e)}]"
    
    def _generate_summary(self, parsed_files: Dict[str, List]) -> Dict[str, Any]:
        """Generate summary of discovered context"""
        return {
            "total_files": sum(len(files) for files in parsed_files.values()),
            "readmes_found": len(parsed_files["readmes"]),
            "diagrams_found": len(parsed_files["architecture_diagrams"]) + len(parsed_files["data_flow_diagrams"]),
            "threat_files_found": len(parsed_files["threat_statements"]),
            "has_sufficient_context": (
                len(parsed_files["readmes"]) > 0 and 
                len(parsed_files["threat_statements"]) > 0
            )
        }
