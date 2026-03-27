"""Build MITRE ATT&CK graph from STIX bundle"""
import json
from pathlib import Path
from datetime import datetime
from typing import List
from .types import TechniqueNode, MitreAttackGraph
from .embedding_service import EmbeddingService
from .graph_store import GraphStore
from ..utils.logger import ThreatForestLogger


class GraphBuilder:
    """Builds MITRE ATT&CK graph from STIX bundle with embeddings"""
    
    def __init__(self, embedding_service: EmbeddingService):
        """
        Initialize graph builder
        
        Args:
            embedding_service: Service for generating embeddings
        """
        self.embedding_service = embedding_service
        self.logger = ThreatForestLogger.get_logger(self.__class__.__name__)
    
    def build_from_stix(
        self,
        stix_bundle_path: str,
        source_name: str = "mitre-attack",
        kill_chain_name: str = "mitre-attack",
    ) -> MitreAttackGraph:
        """
        Build graph from STIX bundle

        Args:
            stix_bundle_path: Path to STIX bundle JSON file
            source_name: STIX source_name to filter on (e.g. "mitre-attack", "mitre-atlas")
            kill_chain_name: STIX kill_chain_name to filter on

        Returns:
            MitreAttackGraph with embedded techniques
        """
        self.logger.info(f"Building graph from STIX bundle: {stix_bundle_path}")

        # Load STIX bundle
        with open(stix_bundle_path, 'r') as f:
            bundle = json.load(f)

        # Extract attack patterns
        techniques = self._extract_techniques(bundle, source_name=source_name, kill_chain_name=kill_chain_name)
        self.logger.info(f"Extracted {len(techniques)} techniques from STIX bundle")
        
        # Generate embeddings
        technique_nodes = self._add_embeddings(techniques)
        self.logger.info(f"Generated embeddings for {len(technique_nodes)} techniques")
        
        # Extract STIX version from bundle
        stix_version = self._get_stix_version(bundle)
        
        # Create graph
        graph = MitreAttackGraph(
            techniques=technique_nodes,
            embedding_model=self.embedding_service.model_name,
            embedding_dim=self.embedding_service.embedding_dim,
            created_at=datetime.utcnow().isoformat(),
            stix_version=stix_version,
            metadata={
                "source": stix_bundle_path,
                "num_techniques": len(technique_nodes)
            }
        )
        
        self.logger.info(f"✓ Graph built successfully")
        return graph
    
    def _extract_techniques(
        self,
        bundle: dict,
        source_name: str = "mitre-attack",
        kill_chain_name: str = "mitre-attack",
    ) -> List[dict]:
        """
        Extract attack pattern objects from STIX bundle

        Args:
            bundle: STIX bundle dictionary
            source_name: STIX source_name to match in external_references
            kill_chain_name: STIX kill_chain_name to match in kill_chain_phases

        Returns:
            List of attack pattern dictionaries
        """
        techniques = []

        for obj in bundle.get('objects', []):
            if obj.get('type') == 'attack-pattern':
                # Extract external IDs (technique IDs like T1190 or AML.T0000)
                external_ids = []
                for ref in obj.get('external_references', []):
                    if ref.get('source_name') == source_name:
                        ext_id = ref.get('external_id')
                        if ext_id:
                            external_ids.append(ext_id)

                # Extract tactics from kill chain phases
                tactics = []
                for phase in obj.get('kill_chain_phases', []):
                    if phase.get('kill_chain_name') == kill_chain_name:
                        tactics.append(phase.get('phase_name', ''))
                
                techniques.append({
                    'stix_id': obj['id'],
                    'name': obj.get('name', ''),
                    'description': obj.get('description', ''),
                    'external_ids': external_ids,
                    'tactics': tactics,
                    'created': obj.get('created', ''),
                    'modified': obj.get('modified', '')
                })
        
        return techniques
    
    def _add_embeddings(self, techniques: List[dict]) -> List[TechniqueNode]:
        """
        Generate embeddings for techniques
        
        Args:
            techniques: List of technique dictionaries
            
        Returns:
            List of TechniqueNode with embeddings
        """
        # Prepare texts for embedding
        texts = []
        for tech in techniques:
            # Combine name and description for richer embedding
            text = f"{tech['name']}: {tech['description']}"
            texts.append(text)
        
        # Generate embeddings in batch (more efficient)
        embeddings = self.embedding_service.get_batch_embeddings(texts, show_progress=False)
        
        # Create TechniqueNode objects
        technique_nodes = []
        for i, tech in enumerate(techniques):
            # Generate internal ID
            primary_id = tech['external_ids'][0] if tech['external_ids'] else f"tech-{i}"
            internal_id = f"technique-{primary_id}"
            
            node = TechniqueNode(
                id=internal_id,
                stix_id=tech['stix_id'],
                name=tech['name'],
                description=tech['description'],
                technique_ids=tech['external_ids'],
                tactics=tech['tactics'],
                embedding=embeddings[i],
                metadata={
                    'created': tech.get('created', ''),
                    'modified': tech.get('modified', '')
                }
            )
            technique_nodes.append(node)
        
        return technique_nodes
    
    def _get_stix_version(self, bundle: dict) -> str:
        """Extract STIX version from bundle"""
        # Try to get version from spec_version
        version = bundle.get('spec_version', 'unknown')
        
        # Try to extract ATT&CK version from description if available
        for obj in bundle.get('objects', []):
            if obj.get('type') == 'x-mitre-collection':
                desc = obj.get('description', '')
                if 'ATT&CK' in desc:
                    # Extract version number if present
                    import re
                    match = re.search(r'v(\d+\.\d+)', desc)
                    if match:
                        return f"ATT&CK-{match.group(1)}"
        
        return version
    
    @classmethod
    def get_or_build(
        cls,
        graph_path: str,
        stix_bundle_path: str,
        embedding_model: str,
        force_rebuild: bool = False,
        show_progress: bool = False,
        source_name: str = "mitre-attack",
        kill_chain_name: str = "mitre-attack",
    ) -> MitreAttackGraph:
        """
        Get existing graph or build new one

        Args:
            graph_path: Path to save/load graph JSON
            stix_bundle_path: Path to STIX bundle
            embedding_model: Model name for embeddings
            force_rebuild: Force rebuild even if graph exists
            show_progress: Show progress in CLI
            source_name: STIX source_name filter
            kill_chain_name: STIX kill_chain_name filter

        Returns:
            MitreAttackGraph instance
        """
        logger = ThreatForestLogger.get_logger(cls.__name__)
        store = GraphStore(graph_path)

        # Check if we need to build (now includes embedding model validation)
        need_build = force_rebuild or not store.exists() or store.is_stale(stix_bundle_path, expected_embedding_model=embedding_model)

        if not need_build:
            if show_progress:
                from rich.console import Console
                console = Console()
                console.print("📊 [cyan]Loading existing MITRE ATT&CK graph...[/cyan]")
            logger.info("Loading existing graph...")
            try:
                graph = store.load()
                if show_progress:
                    from rich.console import Console
                    console = Console()
                    console.print(f"[green]✓[/green] Graph loaded: {len(graph)} techniques")
                return graph
            except Exception as e:
                logger.warning(f"Failed to load existing graph: {e}")
                logger.info("Will build new graph...")
                need_build = True

        # Build new graph
        if show_progress:
            from rich.console import Console
            console = Console()
            console.print("\n🔨 [bold cyan]Building MITRE ATT&CK graph...[/bold cyan]")
            console.print(f"   [dim]Embedding model: {embedding_model}[/dim]")

        logger.info("Building new graph from STIX bundle...")
        embedding_service = EmbeddingService(embedding_model)
        builder = cls(embedding_service)

        graph = builder.build_from_stix(
            stix_bundle_path,
            source_name=source_name,
            kill_chain_name=kill_chain_name,
        )

        # Save for future use
        store.save(graph)

        if show_progress:
            from rich.console import Console
            console = Console()
            console.print(f"[green]✓[/green] Graph built and cached: {len(graph)} techniques\n")

        return graph
