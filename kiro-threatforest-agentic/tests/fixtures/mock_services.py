"""
Mock services for ThreatForest testing.

Provides mock implementations of external services and dependencies
to enable isolated testing without requiring actual AWS Bedrock,
STIX files, or other external resources.
"""

import json
import time
import asyncio
from typing import Dict, List, Any, Optional
from unittest.mock import MagicMock, AsyncMock
from pathlib import Path

from threatforest.models import ContextInformation, ThreatStatement, AttackTree
from .sample_data import SAMPLE_CONTEXT_INFO, SAMPLE_AAF_BUNDLE, SAMPLE_ATTACK_TREES


class MockBedrockClient:
    """Mock implementation of Bedrock client for testing."""
    
    def __init__(self, simulate_errors: bool = False, response_delay: float = 0.1):
        """
        Initialize mock Bedrock client.
        
        Args:
            simulate_errors: Whether to simulate API errors
            response_delay: Simulated response delay in seconds
        """
        self.simulate_errors = simulate_errors
        self.response_delay = response_delay
        self.call_count = 0
        self.last_request = None
        
    async def invoke_model(self, model_id: str, body: Dict[str, Any]) -> Dict[str, Any]:
        """Mock model invocation."""
        self.call_count += 1
        self.last_request = {"model_id": model_id, "body": body}
        
        # Simulate network delay
        if self.response_delay > 0:
            await asyncio.sleep(self.response_delay)
        
        # Simulate errors if configured
        if self.simulate_errors and self.call_count % 3 == 0:
            raise Exception("Simulated Bedrock API error")
        
        # Generate mock response based on request type
        prompt = body.get("prompt", "").lower()
        
        if "extract" in prompt or "information" in prompt:
            return self._mock_extraction_response()
        elif "attack tree" in prompt or "mermaid" in prompt:
            return self._mock_attack_tree_response()
        elif "semantic" in prompt or "similarity" in prompt:
            return self._mock_similarity_response()
        else:
            return self._mock_generic_response()
    
    def _mock_extraction_response(self) -> Dict[str, Any]:
        """Mock response for information extraction."""
        return {
            "completion": json.dumps({
                "technologies": ["Python", "Django", "PostgreSQL", "Redis"],
                "programming_languages": ["Python", "JavaScript"],
                "sector": "E-commerce",
                "security_objectives": ["Confidentiality", "Integrity", "Availability"],
                "architecture_type": "Microservices",
                "compliance_frameworks": ["PCI DSS", "GDPR"],
                "confidence_score": 0.85
            })
        }
    
    def _mock_attack_tree_response(self) -> Dict[str, Any]:
        """Mock response for attack tree generation."""
        return {
            "completion": SAMPLE_ATTACK_TREES['sql_injection_attack']
        }
    
    def _mock_similarity_response(self) -> Dict[str, Any]:
        """Mock response for semantic similarity."""
        return {
            "completion": json.dumps({
                "similarity_score": 0.87,
                "matched_technique": "T1190",
                "technique_name": "Exploit Public-Facing Application"
            })
        }
    
    def _mock_generic_response(self) -> Dict[str, Any]:
        """Mock generic response."""
        return {
            "completion": "Mock response from Bedrock model"
        }
    
    def reset_mock(self):
        """Reset mock state."""
        self.call_count = 0
        self.last_request = None


class MockSTIXProcessor:
    """Mock implementation of STIX processor for testing."""
    
    def __init__(self, bundle_data: Optional[Dict] = None):
        """
        Initialize mock STIX processor.
        
        Args:
            bundle_data: Optional custom STIX bundle data
        """
        self.bundle_data = bundle_data or SAMPLE_AAF_BUNDLE
        self.techniques = self._extract_techniques()
    
    def _extract_techniques(self) -> List[Dict[str, Any]]:
        """Extract techniques from bundle data."""
        techniques = []
        for obj in self.bundle_data.get("objects", []):
            if obj.get("type") == "attack-pattern":
                techniques.append({
                    "id": obj.get("id"),
                    "name": obj.get("name"),
                    "description": obj.get("description"),
                    "external_id": self._get_external_id(obj),
                    "kill_chain_phases": obj.get("kill_chain_phases", [])
                })
        return techniques
    
    def _get_external_id(self, obj: Dict) -> Optional[str]:
        """Extract external ID from STIX object."""
        refs = obj.get("external_references", [])
        for ref in refs:
            if ref.get("source_name") == "mitre-attack":
                return ref.get("external_id")
        return None
    
    def search_techniques(self, query: str, threshold: float = 0.8) -> List[Dict[str, Any]]:
        """Mock technique search."""
        # Simple keyword matching for testing
        query_lower = query.lower()
        matches = []
        
        for technique in self.techniques:
            name_lower = technique["name"].lower()
            desc_lower = technique["description"].lower()
            
            # Simple scoring based on keyword presence
            score = 0.0
            if query_lower in name_lower:
                score += 0.5
            if query_lower in desc_lower:
                score += 0.3
            
            # Add some keywords for common attack patterns
            keywords = {
                "sql": ["sql", "injection", "database"],
                "phishing": ["phishing", "email", "social"],
                "ddos": ["denial", "service", "flood"],
                "malware": ["malware", "virus", "trojan"]
            }
            
            for key, terms in keywords.items():
                if key in query_lower:
                    for term in terms:
                        if term in name_lower or term in desc_lower:
                            score += 0.2
            
            if score >= threshold:
                matches.append({
                    **technique,
                    "alignment_score": min(score, 1.0)
                })
        
        return sorted(matches, key=lambda x: x["alignment_score"], reverse=True)
    
    def get_technique_by_id(self, technique_id: str) -> Optional[Dict[str, Any]]:
        """Get technique by external ID."""
        for technique in self.techniques:
            if technique["external_id"] == technique_id:
                return technique
        return None


class MockFileSystem:
    """Mock file system for testing file operations."""
    
    def __init__(self):
        """Initialize mock file system."""
        self.files: Dict[str, str] = {}
        self.directories: set = set()
        
    def create_file(self, path: str, content: str):
        """Create a mock file."""
        self.files[path] = content
        # Create parent directories
        parent = str(Path(path).parent)
        if parent != ".":
            self.directories.add(parent)
    
    def read_file(self, path: str) -> str:
        """Read a mock file."""
        if path not in self.files:
            raise FileNotFoundError(f"File not found: {path}")
        return self.files[path]
    
    def file_exists(self, path: str) -> bool:
        """Check if mock file exists."""
        return path in self.files
    
    def list_files(self, directory: str = ".") -> List[str]:
        """List files in mock directory."""
        files = []
        for path in self.files.keys():
            if str(Path(path).parent) == directory or directory == ".":
                files.append(Path(path).name)
        return files
    
    def create_directory(self, path: str):
        """Create mock directory."""
        self.directories.add(path)
    
    def directory_exists(self, path: str) -> bool:
        """Check if mock directory exists."""
        return path in self.directories
    
    def clear(self):
        """Clear all mock files and directories."""
        self.files.clear()
        self.directories.clear()


class MockAgent:
    """Base mock agent for testing."""
    
    def __init__(self, name: str, simulate_delay: bool = True):
        """
        Initialize mock agent.
        
        Args:
            name: Agent name
            simulate_delay: Whether to simulate processing delay
        """
        self.name = name
        self.simulate_delay = simulate_delay
        self.call_count = 0
        self.last_input = None
        
    async def process(self, input_data: Any) -> Any:
        """Mock processing method."""
        self.call_count += 1
        self.last_input = input_data
        
        if self.simulate_delay:
            await asyncio.sleep(0.1)  # Simulate processing time
        
        return self._generate_mock_output(input_data)
    
    def _generate_mock_output(self, input_data: Any) -> Any:
        """Generate mock output - to be overridden by subclasses."""
        return f"Mock output from {self.name}"


class MockContextDetectionAgent(MockAgent):
    """Mock context detection agent."""
    
    def __init__(self, file_system: MockFileSystem):
        super().__init__("ContextDetectionAgent")
        self.file_system = file_system
    
    def _generate_mock_output(self, directory_path: str) -> List[Dict[str, Any]]:
        """Generate mock context files."""
        files = self.file_system.list_files(directory_path)
        context_files = []
        
        for file_name in files:
            file_type = "other"
            if "readme" in file_name.lower():
                file_type = "readme"
            elif "threat" in file_name.lower():
                file_type = "threats"
            elif "architecture" in file_name.lower():
                file_type = "architecture"
            elif "dataflow" in file_name.lower():
                file_type = "dataflow"
            
            context_files.append({
                "path": f"{directory_path}/{file_name}",
                "type": file_type,
                "size": len(self.file_system.read_file(f"{directory_path}/{file_name}")),
                "modified": time.time()
            })
        
        return context_files


class MockInformationExtractionAgent(MockAgent):
    """Mock information extraction agent."""
    
    def __init__(self, bedrock_client: MockBedrockClient):
        super().__init__("InformationExtractionAgent")
        self.bedrock_client = bedrock_client
    
    async def _generate_mock_output(self, context_files: List[Dict]) -> ContextInformation:
        """Generate mock extracted information."""
        # Use predefined context info based on file content
        return SAMPLE_CONTEXT_INFO['web_application']


class MockAttackTreeGeneratorAgent(MockAgent):
    """Mock attack tree generator agent."""
    
    def __init__(self, bedrock_client: MockBedrockClient):
        super().__init__("AttackTreeGeneratorAgent")
        self.bedrock_client = bedrock_client
    
    def _generate_mock_output(self, threat_statements: List[ThreatStatement]) -> List[Dict[str, Any]]:
        """Generate mock attack trees."""
        attack_trees = []
        
        for i, threat in enumerate(threat_statements):
            if threat.severity.lower() == "high":
                tree_key = 'sql_injection_attack' if 'sql' in threat.threat_action.lower() else 'phishing_attack'
                attack_trees.append({
                    "threat_id": threat.id,
                    "title": f"Attack Tree for {threat.id}",
                    "severity": threat.severity,
                    "mermaid_content": SAMPLE_ATTACK_TREES.get(tree_key, SAMPLE_ATTACK_TREES['sql_injection_attack']),
                    "generated_timestamp": time.time()
                })
        
        return attack_trees


class MockTTCMappingAgent(MockAgent):
    """Mock TTC mapping agent."""
    
    def __init__(self, stix_processor: MockSTIXProcessor):
        super().__init__("TTCMappingAgent")
        self.stix_processor = stix_processor
    
    def _generate_mock_output(self, attack_trees: List[Dict]) -> List[Dict[str, Any]]:
        """Generate mock TTC mappings."""
        enhanced_trees = []
        
        for tree in attack_trees:
            # Add mock TTC mappings
            tree_copy = tree.copy()
            tree_copy["ttc_mappings"] = {
                "T1190": {
                    "technique": "Exploit Public-Facing Application",
                    "alignment_score": 0.92
                },
                "T1566": {
                    "technique": "Phishing",
                    "alignment_score": 0.87
                }
            }
            tree_copy["enhanced"] = True
            enhanced_trees.append(tree_copy)
        
        return enhanced_trees


def create_mock_environment() -> Dict[str, Any]:
    """
    Create a complete mock environment for testing.
    
    Returns:
        Dictionary containing all mock services and utilities
    """
    file_system = MockFileSystem()
    bedrock_client = MockBedrockClient()
    stix_processor = MockSTIXProcessor()
    
    # Create mock agents
    context_agent = MockContextDetectionAgent(file_system)
    extraction_agent = MockInformationExtractionAgent(bedrock_client)
    generator_agent = MockAttackTreeGeneratorAgent(bedrock_client)
    mapping_agent = MockTTCMappingAgent(stix_processor)
    
    return {
        "file_system": file_system,
        "bedrock_client": bedrock_client,
        "stix_processor": stix_processor,
        "agents": {
            "context_detection": context_agent,
            "information_extraction": extraction_agent,
            "attack_tree_generator": generator_agent,
            "ttc_mapping": mapping_agent
        }
    }