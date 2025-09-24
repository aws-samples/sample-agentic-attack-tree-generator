# ThreatForest API Documentation

This document provides comprehensive API documentation for ThreatForest classes and methods.

## Core Classes

### OrchestratorAgent

The main orchestrator that manages the complete threat analysis workflow.

```python
from threatforest.agents.orchestrator import OrchestratorAgent

class OrchestratorAgent:
    """
    Main orchestrator for the ThreatForest workflow.
    
    Manages the execution of all analysis phases including context detection,
    information extraction, attack tree generation, and TTC mapping.
    """
    
    def __init__(self, bedrock_client, config, error_handler=None):
        """
        Initialize the orchestrator agent.
        
        Args:
            bedrock_client: Configured BedrockClient instance
            config: Configuration object with workflow settings
            error_handler: Optional ErrorHandler instance
        """
    
    async def execute_workflow(self, directory_path: str) -> Dict[str, Any]:
        """
        Execute the complete threat analysis workflow.
        
        Args:
            directory_path: Path to directory containing context files
            
        Returns:
            Dict containing workflow results and metadata
            
        Raises:
            WorkflowError: If critical phases fail
        """
```

### ContextDetectionAgent

Scans directories and identifies relevant context files.

```python
from threatforest.agents.context_detection import ContextDetectionAgent

class ContextDetectionAgent:
    """
    Agent responsible for detecting and validating context files.
    
    Scans directories for README files, architecture diagrams, threat statements,
    and other relevant documentation.
    """
    
    def __init__(self, config=None):
        """
        Initialize the context detection agent.
        
        Args:
            config: Optional configuration for file patterns and validation
        """
    
    def scan_directory(self, directory_path: str) -> Dict[str, List[str]]:
        """
        Scan directory for context files.
        
        Args:
            directory_path: Path to scan for context files
            
        Returns:
            Dict mapping file types to lists of found files
            
        Example:
            {
                'readme_files': ['README.md'],
                'threat_files': ['threats.md'],
                'diagram_files': ['dataflow.mmd'],
                'architecture_files': ['architecture.png']
            }
        """
```

### InformationExtractionAgent

Extracts key security information from context files using AI.

```python
from threatforest.agents.information_extraction import InformationExtractionAgent

class InformationExtractionAgent:
    """
    Agent for extracting security-relevant information from context files.
    
    Uses Amazon Bedrock to analyze README files, architecture diagrams,
    and other documentation to extract technologies, security objectives,
    and other key information.
    """
    
    def __init__(self, bedrock_client, config=None):
        """
        Initialize the information extraction agent.
        
        Args:
            bedrock_client: Configured BedrockClient instance
            config: Optional configuration for extraction parameters
        """
    
    async def extract_information(self, context_files: Dict[str, List[str]]) -> ExtractionResult:
        """
        Extract key information from context files.
        
        Args:
            context_files: Dict of file types to file paths
            
        Returns:
            ExtractionResult containing extracted information and confidence
            
        Raises:
            ExtractionError: If extraction fails or confidence is too low
        """
```

### AttackTreeGeneratorAgent

Generates Mermaid-formatted attack trees from threat statements.

```python
from threatforest.agents.attack_tree_generator import AttackTreeGeneratorAgent

class AttackTreeGeneratorAgent:
    """
    Agent for generating attack trees from threat statements.
    
    Processes threat statements and generates Mermaid-formatted attack trees
    for high-severity threats only.
    """
    
    def __init__(self, bedrock_client, config=None):
        """
        Initialize the attack tree generator agent.
        
        Args:
            bedrock_client: Configured BedrockClient instance
            config: Optional configuration for generation parameters
        """
    
    async def generate_attack_trees(self, threat_statements: List[ThreatStatement], 
                                  context_info: ContextInformation) -> List[AttackTree]:
        """
        Generate attack trees for high-severity threats.
        
        Args:
            threat_statements: List of parsed threat statements
            context_info: Extracted context information
            
        Returns:
            List of generated AttackTree objects
            
        Raises:
            GenerationError: If attack tree generation fails
        """
```

### TTCMappingAgent

Enhances attack trees with STIX threat intelligence mappings.

```python
from threatforest.agents.ttc_mapping import TTCMappingAgent

class TTCMappingAgent:
    """
    Agent for enhancing attack trees with TTC (STIX) mappings.
    
    Uses semantic similarity to map attack steps to STIX techniques
    from the AAF bundle.
    """
    
    def __init__(self, aaf_bundle_path: str, config=None):
        """
        Initialize the TTC mapping agent.
        
        Args:
            aaf_bundle_path: Path to AAF bundle JSON file
            config: Optional configuration for mapping parameters
        """
    
    async def enhance_attack_trees(self, attack_trees: List[AttackTree]) -> List[AttackTree]:
        """
        Enhance attack trees with TTC mappings.
        
        Args:
            attack_trees: List of attack trees to enhance
            
        Returns:
            List of enhanced attack trees with TTC mappings
            
        Raises:
            MappingError: If TTC mapping fails
        """
```

## Utility Classes

### BedrockClient

Wrapper for Amazon Bedrock API interactions.

```python
from threatforest.utils.bedrock_client import BedrockClient

class BedrockClient:
    """
    Client for interacting with Amazon Bedrock APIs.
    
    Provides methods for invoking language models with proper error handling,
    retry logic, and response parsing.
    """
    
    def __init__(self, region: str = "us-east-1", model_id: str = None):
        """
        Initialize Bedrock client.
        
        Args:
            region: AWS region for Bedrock service
            model_id: Default model ID to use for requests
        """
    
    async def invoke_model(self, prompt: str, model_id: str = None, 
                          max_tokens: int = 4000) -> str:
        """
        Invoke a Bedrock model with the given prompt.
        
        Args:
            prompt: Input prompt for the model
            model_id: Model ID to use (overrides default)
            max_tokens: Maximum tokens in response
            
        Returns:
            Model response text
            
        Raises:
            BedrockError: If API call fails
        """
```

### STIXProcessor

Processes STIX threat intelligence data from AAF bundles.

```python
from threatforest.utils.stix_processor import STIXProcessor

class STIXProcessor:
    """
    Processor for STIX threat intelligence data.
    
    Loads and indexes STIX techniques and tactics from AAF bundle files
    for use in TTC mapping.
    """
    
    def __init__(self, aaf_bundle_path: str):
        """
        Initialize STIX processor.
        
        Args:
            aaf_bundle_path: Path to AAF bundle JSON file
        """
    
    def load_aaf_bundle(self, bundle_path: str) -> None:
        """
        Load STIX data from AAF bundle file.
        
        Args:
            bundle_path: Path to AAF bundle JSON file
            
        Raises:
            STIXProcessorError: If bundle loading fails
        """
    
    def search_techniques(self, query: str, limit: int = 10) -> List[STIXSearchResult]:
        """
        Search for STIX techniques matching the query.
        
        Args:
            query: Search query string
            limit: Maximum number of results
            
        Returns:
            List of STIXSearchResult objects sorted by relevance
        """
```

### FileManager

Manages file I/O operations for ThreatForest.

```python
from threatforest.utils.file_manager import FileManager

class FileManager:
    """
    Manager for file I/O operations.
    
    Handles reading context files, writing output files, and managing
    session directories.
    """
    
    def __init__(self, base_output_dir: str = "./tf-output"):
        """
        Initialize file manager.
        
        Args:
            base_output_dir: Base directory for output files
        """
    
    def read_context_files(self, file_paths: List[str]) -> Dict[str, str]:
        """
        Read content from context files.
        
        Args:
            file_paths: List of file paths to read
            
        Returns:
            Dict mapping file paths to content
            
        Raises:
            FileManagerError: If file reading fails
        """
    
    def write_attack_tree(self, attack_tree: AttackTree, output_dir: str) -> str:
        """
        Write attack tree to Mermaid file.
        
        Args:
            attack_tree: AttackTree object to write
            output_dir: Directory to write file to
            
        Returns:
            Path to written file
            
        Raises:
            FileManagerError: If file writing fails
        """
```

## Data Models

### ContextInformation

```python
from threatforest.models import ContextInformation

@dataclass
class ContextInformation:
    """Information extracted from context files."""
    
    technologies: List[str]
    programming_languages: List[str]
    sector: str
    security_objectives: List[str]
    architecture_type: str
    compliance_frameworks: List[str]
    extracted_from: List[str]
    validation_status: str
    timestamp: datetime
```

### ThreatStatement

```python
from threatforest.models import ThreatStatement

@dataclass
class ThreatStatement:
    """Parsed threat statement."""
    
    id: str
    severity: str
    threat_source: str
    prerequisites: str
    threat_action: str
    threat_impact: str
    impacted_assets: List[str]
    impacted_goals: List[str]
    raw_statement: str
```

### AttackTree

```python
from threatforest.models import AttackTree

@dataclass
class AttackTree:
    """Generated attack tree."""
    
    threat_id: str
    title: str
    mermaid_content: str
    attack_steps: List[AttackStep]
    ttc_mappings: Dict[str, TTCMapping]
    generated_timestamp: datetime
```

## Configuration

### Config Class

```python
from threatforest.config import Config

class Config:
    """
    Configuration management for ThreatForest.
    
    Loads configuration from files, environment variables, and CLI arguments
    with proper precedence handling.
    """
    
    def __init__(self, config_file: str = None):
        """
        Initialize configuration.
        
        Args:
            config_file: Optional path to configuration file
        """
    
    def get(self, key: str, default=None):
        """
        Get configuration value.
        
        Args:
            key: Configuration key (dot-separated for nested values)
            default: Default value if key not found
            
        Returns:
            Configuration value or default
        """
    
    def set(self, key: str, value):
        """
        Set configuration value.
        
        Args:
            key: Configuration key (dot-separated for nested values)
            value: Value to set
        """
```

## Error Handling

### ErrorHandler

```python
from threatforest.error_handler import ErrorHandler

class ErrorHandler:
    """
    Centralized error handling for ThreatForest.
    
    Provides categorized error handling, retry logic, and error reporting.
    """
    
    def handle_error(self, error: Exception, category: ErrorCategory, 
                    context: Dict = None, operation: str = "") -> ErrorContext:
        """
        Handle an error with appropriate categorization and logging.
        
        Args:
            error: Exception that occurred
            category: ErrorCategory for the error
            context: Additional context information
            operation: Description of operation that failed
            
        Returns:
            ErrorContext object with error details
        """
```

## CLI Interface

### Main CLI Commands

```python
# Basic usage
tf analyze                          # Analyze current directory
tf analyze /path/to/project        # Analyze specific directory
tf analyze --output ./results      # Custom output directory

# Configuration
tf config --set key value          # Set configuration value
tf config --show                   # Show current configuration
tf config --reset                  # Reset to defaults

# Advanced options
tf analyze --verbose               # Verbose output
tf analyze --debug                 # Debug logging
tf analyze --no-validation         # Skip user validation
tf analyze --region us-west-2      # Custom AWS region
```

## Usage Examples

### Basic Workflow

```python
from threatforest.agents.orchestrator import OrchestratorAgent
from threatforest.utils.bedrock_client import BedrockClient
from threatforest.config import Config

# Initialize components
config = Config()
bedrock_client = BedrockClient(region="us-east-1")
orchestrator = OrchestratorAgent(bedrock_client, config)

# Execute workflow
results = await orchestrator.execute_workflow("/path/to/project")

# Access results
attack_trees = results['attack_trees']
context_info = results['context_information']
```

### Custom Configuration

```python
from threatforest.config import Config

# Load custom configuration
config = Config("./my-config.yaml")

# Set runtime values
config.set("bedrock.region", "us-west-2")
config.set("processing.severity_threshold", "medium")
config.set("ttc.enable_enhancement", False)
```

### Error Handling

```python
from threatforest.error_handler import ErrorHandler, ErrorCategory

error_handler = ErrorHandler()

try:
    # ThreatForest operations
    pass
except Exception as e:
    error_context = error_handler.handle_error(
        e, ErrorCategory.AGENT_PROCESSING, 
        {"agent": "attack_tree_generator"}
    )
    print(f"Error: {error_context.message}")
```

For more examples, see the [examples/](../examples/) directory.