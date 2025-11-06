"""Input validation models for ThreatForest tools"""
from pathlib import Path
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, field_validator, model_validator


class SetupToolInput(BaseModel):
    """Validation model for SetupTool inputs"""
    project_path: str = Field(..., description="Path to the project directory")
    aws_profile: Optional[str] = Field(None, description="AWS profile name")
    bedrock_model: Optional[str] = Field(None, description="Bedrock model ID")
    inference_profile_arn: Optional[str] = Field(None, description="Inference profile ARN")
    interactive: bool = Field(True, description="Interactive mode flag")
    
    @field_validator('project_path')
    @classmethod
    def validate_project_path(cls, v: str) -> str:
        """Validate project path exists"""
        path = Path(v)
        if not path.exists():
            raise ValueError(f"Project path does not exist: {v}")
        if not path.is_dir():
            raise ValueError(f"Project path is not a directory: {v}")
        return str(path.absolute())


class ContextAnalysisInput(BaseModel):
    """Validation model for ContextAnalysisTool inputs"""
    project_path: str = Field(..., description="Path to the project directory")
    
    @field_validator('project_path')
    @classmethod
    def validate_project_path(cls, v: str) -> str:
        """Validate project path exists"""
        path = Path(v)
        if not path.exists():
            raise ValueError(f"Project path does not exist: {v}")
        if not path.is_dir():
            raise ValueError(f"Project path is not a directory: {v}")
        return str(path.absolute())


class ExtractionToolInput(BaseModel):
    """Validation model for InformationExtractionTool inputs"""
    context_files: Dict[str, Any] = Field(..., description="Context files dictionary")
    bedrock_model: str = Field(..., description="Bedrock model ID")
    aws_profile: Optional[str] = Field(None, description="AWS profile name")
    interactive: bool = Field(False, description="Interactive mode flag")
    
    @field_validator('context_files')
    @classmethod
    def validate_context_files(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        """Validate context files structure"""
        if not isinstance(v, dict):
            raise ValueError("context_files must be a dictionary")
        if not v:
            raise ValueError("context_files cannot be empty")
        return v
    
    @field_validator('bedrock_model')
    @classmethod
    def validate_bedrock_model(cls, v: str) -> str:
        """Validate Bedrock model ID format"""
        if not v or not isinstance(v, str):
            raise ValueError("bedrock_model must be a non-empty string")
        return v


class AttackTreeGeneratorInput(BaseModel):
    """Validation model for AttackTreeGeneratorTool inputs"""
    threat_statements: List[Dict[str, Any]] = Field(..., description="List of threat statements")
    extracted_info: Dict[str, Any] = Field(..., description="Extracted information dictionary")
    bedrock_model: str = Field(..., description="Bedrock model ID")
    aws_profile: Optional[str] = Field(None, description="AWS profile name")
    
    @field_validator('threat_statements')
    @classmethod
    def validate_threat_statements(cls, v: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Validate threat statements list"""
        if not isinstance(v, list):
            raise ValueError("threat_statements must be a list")
        if not v:
            raise ValueError("threat_statements cannot be empty")
        return v
    
    @field_validator('extracted_info')
    @classmethod
    def validate_extracted_info(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        """Validate extracted info structure"""
        if not isinstance(v, dict):
            raise ValueError("extracted_info must be a dictionary")
        return v


class TTCMappingInput(BaseModel):
    """Validation model for TTCMappingTool inputs"""
    attack_trees: Dict[str, Any] = Field(..., description="Attack trees dictionary")
    aaf_bundle_path: Optional[str] = Field(None, description="Path to AAF bundle")
    
    @field_validator('attack_trees')
    @classmethod
    def validate_attack_trees(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        """Validate attack trees structure"""
        if not isinstance(v, dict):
            raise ValueError("attack_trees must be a dictionary")
        return v
    
    @field_validator('aaf_bundle_path')
    @classmethod
    def validate_aaf_bundle_path(cls, v: Optional[str]) -> Optional[str]:
        """Validate AAF bundle path if provided"""
        if v is not None:
            path = Path(v)
            if not path.exists():
                raise ValueError(f"AAF bundle path does not exist: {v}")
            if not path.is_file():
                raise ValueError(f"AAF bundle path is not a file: {v}")
        return v


class SummaryGeneratorInput(BaseModel):
    """Validation model for SummaryGeneratorTool inputs"""
    attack_trees: Dict[str, Any] = Field(..., description="Attack trees dictionary")
    extracted_info: Dict[str, Any] = Field(..., description="Extracted information dictionary")
    output_dir: str = Field(..., description="Output directory path")
    
    @field_validator('attack_trees')
    @classmethod
    def validate_attack_trees(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        """Validate attack trees structure"""
        if not isinstance(v, dict):
            raise ValueError("attack_trees must be a dictionary")
        return v
    
    @field_validator('extracted_info')
    @classmethod
    def validate_extracted_info(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        """Validate extracted info structure"""
        if not isinstance(v, dict):
            raise ValueError("extracted_info must be a dictionary")
        return v
    
    @field_validator('output_dir')
    @classmethod
    def validate_output_dir(cls, v: str) -> str:
        """Validate output directory"""
        path = Path(v)
        # Create if doesn't exist
        path.mkdir(parents=True, exist_ok=True)
        return str(path.absolute())
