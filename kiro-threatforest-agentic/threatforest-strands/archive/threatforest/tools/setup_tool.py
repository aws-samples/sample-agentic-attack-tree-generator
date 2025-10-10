"""Setup Tool for ThreatForest initialization"""
import os
import sys
import json
import subprocess
from pathlib import Path
from threatforest.utils.logger import ThreatForestLogger
from threatforest.core import Tool, tool
from typing import Dict, Any, Optional, List

import boto3
from botocore.exceptions import NoCredentialsError, ProfileNotFound


class SetupTool(Tool):
    """Tool for setting up ThreatForest environment"""
    
    AVAILABLE_MODELS = [
        "us.anthropic.claude-sonnet-4-20250514-v1:0",
        "us.anthropic.claude-opus-4-1-20250805-v1:0",
        "anthropic.claude-3-5-sonnet-20241022-v2:0",
        "anthropic.claude-3-5-haiku-20241022-v1:0", 
        "anthropic.claude-3-opus-20240229-v1:0",
        "anthropic.claude-3-haiku-20240307-v1:0",
        "amazon.titan-text-premier-v1:0",
        "amazon.titan-text-express-v1",
        "meta.llama3-2-90b-instruct-v1:0",
        "meta.llama3-2-11b-instruct-v1:0"
    ]
    
    def __init__(self):
        super().__init__(
            name="setup",
            description="Setup ThreatForest environment including venv, AWS credentials, and Bedrock model validation"
        )
        self.logger = ThreatForestLogger.get_logger(self.__class__.__name__)
    
    async def execute(self, project_path: str, aws_profile: Optional[str] = None, 
                     bedrock_model: Optional[str] = None, 
                     inference_profile_arn: Optional[str] = None,
                     interactive: bool = True) -> Dict[str, Any]:
        """Execute setup process"""
        results = {
            "project_path": project_path,
            "venv_status": "not_checked",
            "aws_status": "not_checked", 
            "bedrock_status": "not_checked",
            "model_config": {},
            "setup_complete": False
        }
        
        try:
            # Check/create virtual environment
            results["venv_status"] = self._check_venv(project_path)
            
            # Validate AWS credentials
            results["aws_status"] = self._validate_aws_credentials(aws_profile)
            
            # Configure Bedrock model
            if results["aws_status"] == "valid":
                model_config = await self._configure_bedrock_model(
                    bedrock_model, inference_profile_arn, aws_profile, interactive
                )
                results["model_config"] = model_config
                results["bedrock_status"] = model_config.get("status", "error")
            
            results["setup_complete"] = all([
                results["venv_status"] in ["active", "exists_not_active"],
                results["aws_status"] == "valid",
                results["bedrock_status"] == "accessible"
            ])
            
            return results
            
        except Exception as e:
            results["error"] = str(e)
            return results
    
    def _check_venv(self, project_path: str) -> str:
        """Check if virtual environment exists and is active"""
        venv_path = Path(project_path) / "venv"
        
        if venv_path.exists():
            # Check if we're in the venv
            if hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix):
                return "active"
            else:
                return "exists_not_active"
        else:
            return "not_found"
    
    def _validate_aws_credentials(self, profile: Optional[str] = None) -> str:
        """Validate AWS credentials"""
        try:
            session = boto3.Session(profile_name=profile) if profile else boto3.Session()
            sts = session.client('sts')
            sts.get_caller_identity()
            return "valid"
        except NoCredentialsError:
            return "no_credentials"
        except ProfileNotFound:
            return "profile_not_found"
        except Exception as e:
            return f"error: {str(e)}"
    
    async def _configure_bedrock_model(self, model_id: Optional[str], 
                                      inference_profile_arn: Optional[str],
                                      profile: Optional[str] = None,
                                      interactive: bool = True) -> Dict[str, Any]:
        """Configure and validate Bedrock model"""
        
        # Use inference profile ARN if provided
        if inference_profile_arn:
            status = self._validate_inference_profile(inference_profile_arn, profile)
            return {
                "type": "inference_profile",
                "arn": inference_profile_arn,
                "status": status
            }
        
        # Use provided model or default
        if not model_id:
            model_id = self.AVAILABLE_MODELS[0]  # Default to Claude 3.5 Sonnet
        
        # Validate model access
        status = self._validate_bedrock_model(model_id, profile)
        
        return {
            "type": "model_id", 
            "model_id": model_id,
            "status": status,
            "available_models": self.AVAILABLE_MODELS
        }
    
    def _validate_bedrock_model(self, model_id: str, profile: Optional[str] = None) -> str:
        """Validate Bedrock model access"""
        try:
            session = boto3.Session(profile_name=profile) if profile else boto3.Session()
            bedrock = session.client('bedrock-runtime', region_name='us-east-1')
            
            # Test with a minimal request
            if "anthropic" in model_id:
                body = {
                    "anthropic_version": "bedrock-2023-05-31",
                    "max_tokens": 1,
                    "messages": [{"role": "user", "content": "test"}]
                }
            else:
                # Generic format for other models
                body = {"inputText": "test", "textGenerationConfig": {"maxTokenCount": 1}}
            
            response = bedrock.invoke_model(
                modelId=model_id,
                body=json.dumps(body)
            )
            return "accessible"
        except Exception as e:
            return f"error: {str(e)}"
    
    def _validate_inference_profile(self, profile_arn: str, aws_profile: Optional[str] = None) -> str:
        """Validate inference profile ARN access"""
        try:
            session = boto3.Session(profile_name=aws_profile) if aws_profile else boto3.Session()
            bedrock = session.client('bedrock-runtime', region_name='us-east-1')
            
            # Test inference profile
            body = {
                "anthropic_version": "bedrock-2023-05-31", 
                "max_tokens": 1,
                "messages": [{"role": "user", "content": "test"}]
            }
            
            response = bedrock.invoke_model(
                modelId=profile_arn,
                body=json.dumps(body)
            )
            return "accessible"
        except Exception as e:
            return f"error: {str(e)}"
