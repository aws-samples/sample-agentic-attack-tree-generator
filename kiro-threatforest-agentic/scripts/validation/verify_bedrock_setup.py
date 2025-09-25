#!/usr/bin/env python3
"""
Bedrock Setup Verification Script

This script verifies that the AWS SDK is properly installed and configured
for Bedrock connectivity in ThreatForest.
"""

import sys
import subprocess
from pathlib import Path


def check_python_version():
    """Check Python version compatibility."""
    print("🐍 Checking Python version...")
    
    if sys.version_info < (3, 9):
        print(f"❌ Python {sys.version_info.major}.{sys.version_info.minor} is not supported. Requires Python 3.9+")
        return False
    
    print(f"✅ Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro} is compatible")
    return True


def check_aws_sdk():
    """Check AWS SDK installation and versions."""
    print("\n📦 Checking AWS SDK installation...")
    
    try:
        import boto3
        import botocore
        
        boto3_version = boto3.__version__
        botocore_version = botocore.__version__
        
        print(f"✅ boto3 version: {boto3_version}")
        print(f"✅ botocore version: {botocore_version}")
        
        # Check minimum versions
        def parse_version(version_str):
            return tuple(map(int, version_str.split('.')[:3]))
        
        boto3_ok = parse_version(boto3_version) >= (1, 34, 0)
        botocore_ok = parse_version(botocore_version) >= (1, 34, 0)
        
        if not boto3_ok:
            print(f"⚠️  boto3 {boto3_version} is older than recommended (1.34.0+)")
            print("   Consider upgrading: pip install --upgrade boto3")
        
        if not botocore_ok:
            print(f"⚠️  botocore {botocore_version} is older than recommended (1.34.0+)")
            print("   Consider upgrading: pip install --upgrade botocore")
        
        return boto3_ok and botocore_ok
        
    except ImportError as e:
        print(f"❌ AWS SDK not installed: {e}")
        print("   Install with: pip install boto3>=1.34.0")
        return False


def check_bedrock_services():
    """Check if Bedrock services are available in boto3."""
    print("\n🔍 Checking Bedrock service availability...")
    
    try:
        import boto3
        
        # Check if bedrock services are available
        session = boto3.Session()
        
        # Check bedrock service
        try:
            bedrock_client = session.client('bedrock', region_name='us-east-1')
            print("✅ Bedrock service client available")
        except Exception as e:
            print(f"❌ Bedrock service client error: {e}")
            return False
        
        # Check bedrock-runtime service
        try:
            runtime_client = session.client('bedrock-runtime', region_name='us-east-1')
            print("✅ Bedrock Runtime service client available")
        except Exception as e:
            print(f"❌ Bedrock Runtime service client error: {e}")
            return False
        
        return True
        
    except Exception as e:
        print(f"❌ Error checking Bedrock services: {e}")
        return False


def check_aws_credentials():
    """Check AWS credentials configuration."""
    print("\n🔐 Checking AWS credentials...")
    
    try:
        import boto3
        from botocore.exceptions import NoCredentialsError, PartialCredentialsError
        
        session = boto3.Session()
        credentials = session.get_credentials()
        
        if credentials is None:
            print("❌ No AWS credentials found")
            print("   Configure with: aws configure")
            print("   Or set environment variables: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY")
            return False
        
        # Test credentials with STS
        try:
            sts_client = session.client('sts')
            identity = sts_client.get_caller_identity()
            
            print(f"✅ AWS credentials valid")
            print(f"   Account: {identity.get('Account', 'unknown')}")
            print(f"   User/Role: {identity.get('Arn', 'unknown')}")
            return True
            
        except Exception as e:
            print(f"❌ AWS credentials invalid: {e}")
            return False
            
    except (NoCredentialsError, PartialCredentialsError) as e:
        print(f"❌ AWS credentials error: {e}")
        return False
    except Exception as e:
        print(f"❌ Error checking credentials: {e}")
        return False


def check_bedrock_regions():
    """Check Bedrock availability in common regions."""
    print("\n🌍 Checking Bedrock region availability...")
    
    try:
        import boto3
        from botocore.exceptions import ClientError
        
        # Common regions with Bedrock support
        bedrock_regions = [
            'us-east-1',
            'us-west-2', 
            'eu-west-1',
            'eu-central-1',
            'ap-southeast-1',
            'ap-southeast-2',
            'ap-northeast-1'
        ]
        
        session = boto3.Session()
        available_regions = []
        
        for region in bedrock_regions:
            try:
                client = session.client('bedrock', region_name=region)
                # Try to list models to verify access
                response = client.list_foundation_models()
                model_count = len(response.get('modelSummaries', []))
                available_regions.append((region, model_count))
                print(f"✅ {region}: {model_count} models available")
            except ClientError as e:
                error_code = e.response.get('Error', {}).get('Code', 'Unknown')
                if error_code == 'AccessDeniedException':
                    print(f"⚠️  {region}: Access denied (check permissions)")
                else:
                    print(f"❌ {region}: {error_code}")
            except Exception as e:
                print(f"❌ {region}: {e}")
        
        if available_regions:
            print(f"\n✅ Bedrock available in {len(available_regions)} regions")
            return True
        else:
            print("\n❌ Bedrock not available in any tested regions")
            return False
            
    except Exception as e:
        print(f"❌ Error checking Bedrock regions: {e}")
        return False


def update_dependencies():
    """Update AWS SDK dependencies."""
    print("\n📦 Updating AWS SDK dependencies...")
    
    try:
        # Update boto3 and botocore
        subprocess.run([
            sys.executable, '-m', 'pip', 'install', '--upgrade',
            'boto3>=1.34.0', 'botocore>=1.34.0'
        ], check=True)
        
        print("✅ AWS SDK dependencies updated successfully")
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to update dependencies: {e}")
        return False


def main():
    """Run all verification checks."""
    print("🔬 ThreatForest Bedrock Setup Verification")
    print("=" * 50)
    
    checks = [
        ("Python Version", check_python_version),
        ("AWS SDK", check_aws_sdk),
        ("Bedrock Services", check_bedrock_services),
        ("AWS Credentials", check_aws_credentials),
        ("Bedrock Regions", check_bedrock_regions),
    ]
    
    results = []
    for name, check_func in checks:
        try:
            result = check_func()
            results.append((name, result))
        except Exception as e:
            print(f"❌ {name} check failed: {e}")
            results.append((name, False))
    
    # Summary
    print("\n" + "=" * 50)
    print("📋 Verification Summary:")
    
    all_passed = True
    for name, passed in results:
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"   {name}: {status}")
        if not passed:
            all_passed = False
    
    if all_passed:
        print("\n🎉 All checks passed! ThreatForest is ready for Bedrock connectivity.")
        print("\nNext steps:")
        print("1. Run: tf setup")
        print("2. Or run: tf config doctor")
    else:
        print("\n⚠️  Some checks failed. Please address the issues above.")
        print("\nCommon solutions:")
        print("• Update AWS SDK: pip install --upgrade boto3 botocore")
        print("• Configure AWS credentials: aws configure")
        print("• Check IAM permissions for Bedrock services")
        
        if input("\nWould you like to update AWS SDK dependencies? (y/N): ").lower() == 'y':
            update_dependencies()
    
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())