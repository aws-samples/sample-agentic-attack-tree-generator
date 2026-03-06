"""Main Context Analysis Tool - Orchestrates discovery and analysis"""
from typing import Dict, Any, Optional
from pathlib import Path
from threatforest.modules.utils.logger import ThreatForestLogger
from threatforest.modules.core import FileDiscovery, BaseAgent
from threatforest.modules.models.project_models import ContextFiles
from .file_categorizer import FileCategorizer
from threatforest.modules.agents.context_extractor_agent import ContextExtractor
from .summary_generator import SummaryGenerator


class ContextAnalysisTool(BaseAgent):
    """Enhanced tool for analyzing project context"""
    
    def __init__(self):
        self.name = "context_analysis"
        self.description = "Discover and analyze context files including threat models, READMEs, and architecture diagrams"
        self.logger = ThreatForestLogger.get_logger(self.__class__.__name__)
        
        # Initialize modules
        self.categorizer = FileCategorizer(self.logger)
        self.context_extractor = ContextExtractor(self.logger)
        self.summary_generator = SummaryGenerator()
    
    def run(self, project_path: str) -> Dict[str, Any]:
        """Execute enhanced context analysis (implements BaseAgent)"""
        # Use FileDiscovery for single-pass file discovery
        discovered = FileDiscovery.discover(project_path)
        self.logger.info(f"Discovered {discovered.total_files} files in {discovered.discovery_time_ms:.2f}ms")
        
        # Build context files structure using Pydantic model
        context_files = ContextFiles(
            threat_models=discovered.threat_models,
            readmes=[f for f in discovered.documentation if 'readme' in Path(f).name.lower()],
            architecture_diagrams=[f for f in discovered.diagrams if 'flow' not in Path(f).name.lower() and 'dfd' not in Path(f).name.lower()],
            data_flow_diagrams=[f for f in discovered.diagrams if 'flow' in Path(f).name.lower() or 'dfd' in Path(f).name.lower()],
            other_docs=[f for f in discovered.documentation if 'readme' not in Path(f).name.lower()],
            project_path=project_path
        )
        
        # Log discovered files
        self._log_discovered_files(context_files)
        
        # Parse other files
        parsed_files = self._parse_files(context_files)
        
        # Extract enhanced context
        enhanced_context = self.context_extractor.extract_enhanced_context(context_files)
        
        # Update context_files with enhanced context
        context_files.enhanced_context = enhanced_context
        
        # Generate summary
        summary = self.summary_generator.generate_summary(parsed_files, context_files.to_dict())
        
        return {
            "project_path": project_path,
            "discovered_files": context_files.to_dict(),
            "parsed_content": parsed_files,
            "summary": summary,
            "enhanced_context": enhanced_context
        }
    
    def _log_discovered_files(self, context_files: ContextFiles):
        """Log discovered files by category"""
        self.logger.info("=== DISCOVERED FILES ===")
        for category in ['threat_models', 'readmes', 'architecture_diagrams', 'data_flow_diagrams', 'other_docs']:
            files = getattr(context_files, category)
            self.logger.info(f"{category.replace('_', ' ').title()}: {len(files)}")
            for f in files[:5]:  # Log first 5
                self.logger.info(f"  - {Path(f).name}")
            if len(files) > 5:
                self.logger.info(f"  ... and {len(files) - 5} more")
    
    def _parse_files(self, context_files: ContextFiles) -> Dict:
        """Parse non-threat files"""
        parsed_files = {}
        for category in ['readmes', 'architecture_diagrams', 'data_flow_diagrams', 'other_docs']:
            files = getattr(context_files, category)
            parsed_files[category] = []
            for file_path in files:
                content = self._parse_file(Path(file_path))
                if content:
                    parsed_files[category].append({
                        "path": str(file_path),
                        "content": content,
                        "size": Path(file_path).stat().st_size
                    })
        return parsed_files
    
    def _parse_file(self, file_path: Path) -> Optional[str]:
        """Parse file content"""
        try:
            if file_path.suffix.lower() in [".md", ".txt", ".json", ".yaml", ".yml"]:
                with open(file_path, 'r', encoding='utf-8') as f:
                    return f.read()
        except:
            pass
        return None
