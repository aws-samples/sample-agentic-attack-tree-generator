"""Data types for local graph storage"""
from dataclasses import dataclass, field
from typing import List, Dict, Any
from datetime import datetime


@dataclass
class TechniqueNode:
    """Represents a MITRE ATT&CK technique node"""
    id: str                          # Internal ID (e.g., "technique-T1190")
    stix_id: str                     # STIX bundle ID
    name: str                        # Technique name
    description: str                 # Full description
    technique_ids: List[str]         # External IDs (e.g., ["T1190"])
    tactics: List[str]               # Kill chain phases/tactics
    embedding: List[float]           # Embedding vector
    metadata: Dict[str, Any] = field(default_factory=dict)  # Additional properties
    
    @property
    def primary_technique_id(self) -> str:
        """Get the primary technique ID"""
        return self.technique_ids[0] if self.technique_ids else ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "id": self.id,
            "stix_id": self.stix_id,
            "name": self.name,
            "description": self.description,
            "technique_ids": self.technique_ids,
            "tactics": self.tactics,
            "embedding": self.embedding,
            "metadata": self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TechniqueNode":
        """Create from dictionary"""
        return cls(
            id=data["id"],
            stix_id=data["stix_id"],
            name=data["name"],
            description=data["description"],
            technique_ids=data["technique_ids"],
            tactics=data["tactics"],
            embedding=data["embedding"],
            metadata=data.get("metadata", {})
        )


@dataclass
class MitreAttackGraph:
    """Represents the complete MITRE ATT&CK graph"""
    techniques: List[TechniqueNode]
    embedding_model: str
    embedding_dim: int
    created_at: str
    stix_version: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "techniques": [t.to_dict() for t in self.techniques],
            "embedding_model": self.embedding_model,
            "embedding_dim": self.embedding_dim,
            "created_at": self.created_at,
            "stix_version": self.stix_version,
            "metadata": self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "MitreAttackGraph":
        """Create from dictionary"""
        return cls(
            techniques=[TechniqueNode.from_dict(t) for t in data["techniques"]],
            embedding_model=data["embedding_model"],
            embedding_dim=data["embedding_dim"],
            created_at=data["created_at"],
            stix_version=data["stix_version"],
            metadata=data.get("metadata", {})
        )
    
    def get_technique_by_id(self, technique_id: str) -> TechniqueNode:
        """Get technique by external ID (e.g., 'T1190')"""
        for tech in self.techniques:
            if technique_id in tech.technique_ids:
                return tech
        return None
    
    def __len__(self) -> int:
        """Number of techniques in graph"""
        return len(self.techniques)
