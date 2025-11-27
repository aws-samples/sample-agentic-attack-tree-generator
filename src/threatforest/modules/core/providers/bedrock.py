"""AWS Bedrock model wrapper"""
from boto3 import Session
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound
from strands.models import BedrockModel
from threatforest.modules.utils.env_manager import EnvManager


def create_bedrock_model(config, temperature: float = 0):
    """
    Create Bedrock model from config
    
    Args:
        config: Config object with bedrock settings
        temperature: Model temperature (default 0)
        
    Returns:
        Configured BedrockModel
        
    Raises:
        ValueError: If AWS credentials are invalid or expired
    """
    bedrock_config = config.bedrock
    
    # Get AWS credentials from environment variables using EnvManager
    env_manager = EnvManager()
    profile = env_manager.get_value('AWS_PROFILE')
    region = env_manager.get_value('AWS_REGION') or 'us-east-1'
    
    try:
        # Create boto3 session
        if profile:
            # Use named profile from ~/.aws/credentials
            session = Session(profile_name=profile, region_name=region)
        else:
            # Use environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
            session = Session(region_name=region)
        
        # Validate credentials by making a test call
        sts = session.client('sts')
        sts.get_caller_identity()
        
    except ProfileNotFound:
        raise ValueError(
            f"❌ AWS Profile '{profile}' not found\n\n"
            f"💡 Solutions:\n"
            f"  • Check if profile exists: cat ~/.aws/credentials | grep {profile}\n"
            f"  • Configure AWS profile: aws configure --profile {profile}\n"
            f"  • Or use a different profile in .env (AWS_PROFILE=...)"
        )
    
    except NoCredentialsError:
        raise ValueError(
            "❌ No AWS credentials found\n\n"
            "💡 Solutions:\n"
            "  • Set AWS_PROFILE in .env (for profile-based auth)\n"
            "  • Or set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY in .env\n"
            "  • Configure AWS: aws configure"
        )
    
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', '')
        if error_code == 'UnrecognizedClientException' or 'security token' in str(e).lower():
            raise ValueError(
                f"❌ AWS credentials are invalid or expired\n\n"
                f"💡 Your credentials have expired. To fix:\n"
                f"  • Refresh AWS credentials (method depends on your setup)\n"
                f"  • For AWS SSO: aws sso login --profile {profile or 'your-profile'}\n"
                f"  • Test credentials: aws sts get-caller-identity --profile {profile or 'your-profile'}\n\n"
                f"🔐 Using profile: {profile or 'default'}\n"
                f"🌍 Region: {region}"
            )
        else:
            raise ValueError(f"❌ AWS Error: {str(e)}")
    
    # Create Bedrock model
    model = BedrockModel(
        model_id=bedrock_config['model_id'],
        boto_session=session,
        temperature=temperature
    )
    
    return model
