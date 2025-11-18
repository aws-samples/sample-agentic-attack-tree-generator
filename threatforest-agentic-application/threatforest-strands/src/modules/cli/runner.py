"""Workflow runner for ThreatForest CLI"""
import asyncio
from pathlib import Path
from typing import Dict, Any, Optional
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn
from rich.console import Console
from src.strands_agent import ThreatForestOrchestrator, ThreatForestConfig
from src.modules.ttc_mappings import TTCMatcher, AttackTreeEnricher, MitigationMapper
from src.config import config


class WorkflowRunner:
    """Execute ThreatForest workflows with progress tracking"""
    
    def __init__(self):
        self.console = Console()
    
    def run_full_workflow(
        self,
        project_path: str,
        threat_model_path: Optional[str] = None
    ) -> Dict[str, Any]:
        """Execute full workflow (generate + enrich + mitigate)"""
        
        # Create ThreatForestConfig using values from config.yaml
        tf_config = ThreatForestConfig(
            project_path=Path(project_path),
            aws_profile=config.default_aws_profile,
            bedrock_model=config.default_bedrock_model,
            resume=False
        )
        
        # Create orchestrator with console for progress bars
        orchestrator = ThreatForestOrchestrator(tf_config, console=self.console)
        
        # Run orchestrator (tools will show their own progress bars)
        result = orchestrator.execute_workflow()
        
        return result
    
    async def run_enrichment(
        self,
        input_dir: str,
        output_dir: str
    ) -> Dict[str, Any]:
        """Execute TTC enrichment only"""
        
        input_path = Path(input_dir).expanduser().resolve()
        output_path = Path(output_dir).expanduser().resolve()
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Initialize matcher based on config
        if config.embeddings_mode == 'local':
            matcher = TTCMatcher(
                mode='local',
                embeddings_path=str(config.embeddings_file_path),
                model_name=config.embeddings_model,
                min_similarity=0.8
            )
        else:  # neptune
            import boto3
            from neptune_graph_manager import NeptuneGraphManager
            
            session = boto3.Session(profile_name=config.default_aws_profile)
            
            # Validate Neptune account ID
            if config.neptune_account_id:
                sts_client = session.client('sts', region_name=config.neptune_region)
                identity = sts_client.get_caller_identity()
                current_account_id = identity['Account']
                
                if current_account_id != config.neptune_account_id:
                    raise ValueError(
                        f"Account ID mismatch! "
                        f"Expected: {config.neptune_account_id}, "
                        f"Current: {current_account_id}"
                    )
            
            neptune_manager = NeptuneGraphManager(
                session=session,
                graph_id=config.neptune_graph_id,
                embedding_model=config.embeddings_model
            )
            
            matcher = TTCMatcher(
                mode='neptune',
                neptune_manager=neptune_manager,
                min_similarity=0.8
            )
        
        enricher = AttackTreeEnricher(matcher)
        
        # Find attack tree files
        files = list(input_path.glob('attack_tree_*.md'))
        
        if not files:
            return {
                'success': False,
                'error': f'No attack tree files found in {input_path}'
            }
        
        enriched_count = 0
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=self.console
        ) as progress:
            
            task = progress.add_task(
                f"[cyan]Enriching {len(files)} attack trees...",
                total=len(files)
            )
            
            for file in files:
                progress.update(task, description=f"[cyan]Enriching {file.name}...")
                output_file = output_path / f"enriched_{file.name}"
                enricher.enrich_file(str(file), str(output_file))
                enriched_count += 1
                progress.advance(task)
        
        return {
            'success': True,
            'enriched_count': enriched_count,
            'output_dir': str(output_path)
        }
    
    async def run_mitigation(
        self,
        input_dir: str,
        output_dir: str
    ) -> Dict[str, Any]:
        """Execute mitigation mapping only"""
        
        input_path = Path(input_dir).expanduser().resolve()
        output_path = Path(output_dir).expanduser().resolve()
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Initialize mitigation mapper
        mapper = MitigationMapper(str(config.stix_bundle_path))
        
        # Find enriched files
        files = list(input_path.glob('*.md'))
        
        if not files:
            return {
                'success': False,
                'error': f'No files found in {input_path}'
            }
        
        processed_count = 0
        total_mitigations = 0
        techniques_with_mitigations = 0
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=self.console
        ) as progress:
            
            task = progress.add_task(
                f"[cyan]Processing {len(files)} files...",
                total=len(files)
            )
            
            for file in files:
                progress.update(task, description=f"[cyan]Processing {file.name}...")
                output_file = output_path / f"mitigated_{file.name}"
                result = mapper.process_enriched_file(str(file), str(output_file))
                
                if result['mitigations_found']:
                    techniques_with_mitigations += len(result['techniques'])
                    for tech in result['techniques']:
                        total_mitigations += len(tech.get('mitigations', []))
                
                processed_count += 1
                progress.advance(task)
        
        return {
            'success': True,
            'processed_count': processed_count,
            'techniques_with_mitigations': techniques_with_mitigations,
            'total_mitigations': total_mitigations,
            'output_dir': str(output_path)
        }
