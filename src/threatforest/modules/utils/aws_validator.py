"""AWS credential validation utilities"""
from typing import Dict, Optional
from boto3 import Session
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound
from rich.console import Console
from rich.panel import Panel
from rich import box


class AWSValidator:
    """Validates AWS credentials and connection"""
    
    def __init__(self):
        self.console = Console()
    
    def test_aws_connection(
        self, 
        profile: Optional[str] = None,
        region: Optional[str] = None,
        access_key_id: Optional[str] = None,
        secret_access_key: Optional[str] = None,
        show_output: bool = True
    ) -> Dict[str, any]:
        """
        Test AWS connection with provided credentials
        
        Args:
            profile: AWS profile name (for profile-based auth)
            region: AWS region
            access_key_id: AWS access key ID (for key-based auth)
            secret_access_key: AWS secret access key (for key-based auth)
            show_output: Whether to display rich console output
            
        Returns:
            Dict with:
                - success: bool
                - account_id: str (if successful)
                - arn: str (if successful)
                - user_id: str (if successful)
                - error: str (if failed)
                - error_type: str (if failed)
        """
        region = region or 'us-east-1'
        
        try:
            # Create boto3 session based on auth method
            if profile:
                session = Session(profile_name=profile, region_name=region)
                auth_method = f"Profile: {profile}"
            elif access_key_id and secret_access_key:
                session = Session(
                    aws_access_key_id=access_key_id,
                    aws_secret_access_key=secret_access_key,
                    region_name=region
                )
                auth_method = "Access Keys"
            else:
                # Try default credentials
                session = Session(region_name=region)
                auth_method = "Default credentials"
            
            # Test credentials with STS get_caller_identity
            sts = session.client('sts')
            identity = sts.get_caller_identity()
            
            result = {
                'success': True,
                'account_id': identity['Account'],
                'arn': identity['Arn'],
                'user_id': identity['UserId'],
                'region': region,
                'auth_method': auth_method
            }
            
            if show_output:
                self._show_success(result)
            
            return result
            
        except ProfileNotFound as e:
            error_msg = f"AWS Profile '{profile}' not found"
            result = {
                'success': False,
                'error': error_msg,
                'error_type': 'ProfileNotFound',
                'suggestions': [
                    f"Check if profile exists: cat ~/.aws/credentials | grep {profile}",
                    f"Configure AWS profile: aws configure --profile {profile}",
                    "Or use a different profile in your configuration"
                ]
            }
            
            if show_output:
                self._show_error(result)
            
            return result
            
        except NoCredentialsError:
            error_msg = "No AWS credentials found"
            result = {
                'success': False,
                'error': error_msg,
                'error_type': 'NoCredentialsError',
                'suggestions': [
                    "Set AWS_PROFILE in .env (for profile-based auth)",
                    "Or set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY in .env",
                    "Configure AWS: aws configure"
                ]
            }
            
            if show_output:
                self._show_error(result)
            
            return result
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            error_message = e.response.get('Error', {}).get('Message', str(e))
            
            if error_code == 'UnrecognizedClientException' or 'security token' in str(e).lower():
                error_msg = "AWS credentials are invalid or expired"
                result = {
                    'success': False,
                    'error': error_msg,
                    'error_type': 'InvalidCredentials',
                    'suggestions': [
                        "Refresh AWS credentials (method depends on your setup)",
                        f"For AWS SSO: aws sso login --profile {profile or 'your-profile'}",
                        f"Test credentials: aws sts get-caller-identity --profile {profile or 'your-profile'}",
                        "For access keys: verify they are correct and not expired"
                    ]
                }
            elif error_code == 'InvalidClientTokenId':
                error_msg = "AWS Access Key ID is invalid"
                result = {
                    'success': False,
                    'error': error_msg,
                    'error_type': 'InvalidAccessKey',
                    'suggestions': [
                        "Verify your AWS Access Key ID is correct",
                        "Check for typos or extra spaces",
                        "Generate new access keys if needed: AWS Console → IAM → Users → Security credentials"
                    ]
                }
            elif error_code == 'SignatureDoesNotMatch':
                error_msg = "AWS Secret Access Key is invalid"
                result = {
                    'success': False,
                    'error': error_msg,
                    'error_type': 'InvalidSecretKey',
                    'suggestions': [
                        "Verify your AWS Secret Access Key is correct",
                        "Secret keys are only shown once - you may need to generate new ones",
                        "Generate new access keys: AWS Console → IAM → Users → Security credentials"
                    ]
                }
            else:
                error_msg = f"AWS Error: {error_message}"
                result = {
                    'success': False,
                    'error': error_msg,
                    'error_type': error_code or 'UnknownError',
                    'suggestions': [
                        "Check AWS service status",
                        "Verify your IAM permissions",
                        "Check network connectivity"
                    ]
                }
            
            if show_output:
                self._show_error(result)
            
            return result
            
        except Exception as e:
            error_msg = f"Unexpected error: {str(e)}"
            result = {
                'success': False,
                'error': error_msg,
                'error_type': 'UnexpectedError',
                'suggestions': [
                    "Check your network connection",
                    "Verify AWS credentials are properly configured"
                ]
            }
            
            if show_output:
                self._show_error(result)
            
            return result
    
    def _show_success(self, result: Dict):
        """Display success message"""
        success_panel = Panel(
            f"[bold green]✓ AWS Connection Successful![/bold green]\n\n"
            f"[cyan]Authentication:[/cyan] {result['auth_method']}\n"
            f"[cyan]Region:[/cyan] {result['region']}\n"
            f"[cyan]Account ID:[/cyan] {result['account_id']}\n"
            f"[cyan]User/Role:[/cyan] {result['arn'].split('/')[-1]}\n"
            f"\n[dim]Your AWS credentials are valid and working correctly.[/dim]",
            border_style="green",
            box=box.ROUNDED,
            padding=(1, 2)
        )
        self.console.print()
        self.console.print(success_panel)
        self.console.print()
    
    def _show_error(self, result: Dict):
        """Display error message with suggestions"""
        suggestions_text = "\n".join([f"  • {s}" for s in result.get('suggestions', [])])
        
        error_panel = Panel(
            f"[bold red]✗ AWS Connection Failed[/bold red]\n\n"
            f"[yellow]Error:[/yellow] {result['error']}\n"
            f"\n[cyan]💡 Suggestions:[/cyan]\n{suggestions_text}\n"
            f"\n[dim]Please fix the credentials and try again.[/dim]",
            border_style="red",
            box=box.ROUNDED,
            padding=(1, 2)
        )
        self.console.print()
        self.console.print(error_panel)
        self.console.print()


# Convenience function
def test_aws_connection(**kwargs) -> Dict[str, any]:
    """
    Test AWS connection (convenience function)
    
    Args:
        profile: AWS profile name
        region: AWS region
        access_key_id: AWS access key ID
        secret_access_key: AWS secret access key
        show_output: Whether to display console output
        
    Returns:
        Dict with success status and details
    """
    validator = AWSValidator()
    return validator.test_aws_connection(**kwargs)
