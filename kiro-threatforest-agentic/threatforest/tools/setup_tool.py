"""Setup Tool for ThreatForest initialization"""
import os
import subprocess
from pathlib import Path
from typing import Dict, Any, Optional

from strands import Tool
import boto3
from botocore.exceptions import NoCredentialsError, ProfileNotFound


class SetupTool(Tool):
    """Tool for setting up ThreatForest environment"""
    
    def __init__(self):
        super().__init__(
            name="setup",
            description="Setup ThreatForest environment including venv, AWS credentials, and Bedrock model validation"
        )
    
    async def execute(self, project_path: str, aws_profile: Optional[str] = None, 
                     bedrock_model: str = "anthropic.claude-3-5-sonnet-20241022-v2:0") -> Dict[str, Any]:
        """Execute setup process"""
        results = {
            "project_path": project_path,
            "venv_status": "not_checked",
            "aws_status": "not_checked", 
            "bedrock_status": "not_checked",
            "setup_complete": False
        }
        
        try:
            # Check/create virtual environment
            results["venv_status"] = self._check_venv(project_path)
            
            # Validate AWS credentials
            results["aws_status"] = self._validate_aws_credentials(aws_profile)
            
            # Validate Bedrock model access
            if results["aws_status"] == "valid":
                results["bedrock_status"] = self._validate_bedrock_model(bedrock_model, aws_profile)
            
            results["setup_complete"] = all([
                results["venv_status"] == "active",
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
    
    def _validate_bedrock_model(self, model_id: str, profile: Optional[str] = None) -> str:
        """Validate Bedrock model access"""
        try:
            session = boto3.Session(profile_name=profile) if profile else boto3.Session()
            bedrock = session.client('bedrock-runtime', region_name='us-east-1')
            
            # Test with a minimal request
            response = bedrock.invoke_model(
                modelId=model_id,
                body='{"anthropic_version": "bedrock-2023-05-31", "max_tokens": 1, "messages": [{"role": "user", "content": "test"}]}'
            )
            return "accessible"
        except Exception as e:
            return f"error: {str(e)}"
