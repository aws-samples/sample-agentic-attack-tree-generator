"""Graph storage and loading"""
import json
from pathlib import Path
from typing import Optional
from datetime import datetime
from .types import MitreAttackGraph
from ..utils.logger import ThreatForestLogger


class GraphStore:
    """Manages loading and saving of the MITRE ATT&CK graph"""
    
    def __init__(self, graph_path: str):
        """
        Initialize graph store
        
        Args:
            graph_path: Path to the JSON graph file
        """
        self.graph_path = Path(graph_path)
        self.graph: Optional[MitreAttackGraph] = None
        self.logger = ThreatForestLogger.get_logger(self.__class__.__name__)
    
    def load(self) -> MitreAttackGraph:
        """
        Load graph from JSON file
        
        Returns:
            MitreAttackGraph instance
            
        Raises:
            FileNotFoundError: If graph file doesn't exist
            ValueError: If graph file is invalid
        """
        if not self.graph_path.exists():
            raise FileNotFoundError(f"Graph file not found: {self.graph_path}")
        
        self.logger.info(f"Loading graph from {self.graph_path}")
        
        try:
            with open(self.graph_path, 'r') as f:
                data = json.load(f)
            
            self.graph = MitreAttackGraph.from_dict(data)
            self.logger.info(f"✓ Loaded graph with {len(self.graph)} techniques")
            self.logger.info(f"  Model: {self.graph.embedding_model}")
            self.logger.info(f"  Dimensions: {self.graph.embedding_dim}")
            self.logger.info(f"  Created: {self.graph.created_at}")
            
            return self.graph
            
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in graph file: {e}")
        except KeyError as e:
            raise ValueError(f"Missing required field in graph: {e}")
        except Exception as e:
            raise ValueError(f"Error loading graph: {e}")
    
    def save(self, graph: MitreAttackGraph):
        """
        Save graph to JSON file
        
        Args:
            graph: MitreAttackGraph to save
        """
        self.logger.info(f"Saving graph to {self.graph_path}")
        
        # Create directory if it doesn't exist
        self.graph_path.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            with open(self.graph_path, 'w') as f:
                json.dump(graph.to_dict(), f, indent=2)
            
            self.graph = graph
            self.logger.info(f"✓ Saved graph with {len(graph)} techniques")
            
        except Exception as e:
            self.logger.error(f"Failed to save graph: {e}")
            raise
    
    def exists(self) -> bool:
        """Check if graph file exists"""
        return self.graph_path.exists()
    
    def is_stale(self, stix_bundle_path: str, expected_embedding_model: str = None) -> bool:
        """
        Check if graph is older than STIX bundle or uses different embedding model
        
        Args:
            stix_bundle_path: Path to STIX bundle file
            expected_embedding_model: Expected embedding model name to validate against
            
        Returns:
            True if graph is stale, doesn't exist, or uses wrong embedding model
        """
        if not self.exists():
            return True
        
        # Check if embedding model matches (if specified)
        if expected_embedding_model:
            try:
                graph = self.load()
                if graph.embedding_model != expected_embedding_model:
                    self.logger.info(f"Graph uses different embedding model: {graph.embedding_model} != {expected_embedding_model}")
                    self.logger.info("Graph will be rebuilt with new embedding model")
                    return True
            except Exception as e:
                self.logger.warning(f"Could not validate graph embedding model: {e}")
                return True
        
        # Check if STIX bundle is newer
        stix_path = Path(stix_bundle_path)
        if not stix_path.exists():
            return False
        
        graph_mtime = self.graph_path.stat().st_mtime
        stix_mtime = stix_path.stat().st_mtime
        
        return stix_mtime > graph_mtime
    
    def get_or_load(self) -> Optional[MitreAttackGraph]:
        """
        Get cached graph or load from file
        
        Returns:
            MitreAttackGraph if available, None otherwise
        """
        if self.graph is not None:
            return self.graph
        
        if self.exists():
            return self.load()
        
        return None
