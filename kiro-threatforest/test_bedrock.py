#!/usr/bin/env python3
"""
Simple test script to verify Bedrock integration.
"""

import os
import sys
from threat_forest.config import ConfigManager, ThreatForestConfig
from threat_forest.llm_client import LLMClient

def test_bedrock_connection():
    """Test basic Bedrock connectivity."""
    print("Testing Bedrock connection...")
    
    try:
        # Create default config
        config = ThreatForestConfig()
        
        # Override with Bedrock settings
        config.llm.provider = "bedrock"
        config.llm.model = "anthropic.claude-3-haiku-20240307-v1:0"  # Use fastest model for testing
        config.llm.region = os.getenv("AWS_DEFAULT_REGION", "us-east-1")
        
        print(f"Using model: {config.llm.model}")
        print(f"Using region: {config.llm.region}")
        
        # Create LLM client
        llm_client = LLMClient(config.llm)
        
        # Test simple prompt
        test_prompt = "Hello! Please respond with 'Bedrock connection successful' if you can read this."
        
        print("Sending test prompt...")
        response = llm_client.generate(test_prompt)
        
        print(f"Response: {response.content}")
        print(f"Model: {response.model}")
        print(f"Provider: {response.provider}")
        print(f"Response time: {response.response_time:.2f}s")
        
        if response.usage:
            print(f"Usage: {response.usage}")
        
        print("✅ Bedrock connection test successful!")
        return True
        
    except Exception as e:
        print(f"❌ Bedrock connection test failed: {e}")
        return False

def test_config_loading():
    """Test configuration loading with environment variables."""
    print("\nTesting configuration loading...")
    
    try:
        config_manager = ConfigManager()
        config = config_manager.load_config()
        
        print(f"Provider: {config.llm.provider}")
        print(f"Model: {config.llm.model}")
        print(f"Region: {config.llm.region}")
        print(f"Max tokens: {config.llm.max_tokens}")
        
        print("✅ Configuration loading successful!")
        return True
        
    except Exception as e:
        print(f"❌ Configuration loading failed: {e}")
        return False

if __name__ == "__main__":
    print("ThreatForest Bedrock Integration Test")
    print("=" * 40)
    
    # Check AWS credentials
    if not (os.getenv("AWS_ACCESS_KEY_ID") or os.getenv("AWS_PROFILE")):
        print("⚠️  Warning: No AWS credentials detected.")
        print("   Set AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY or configure AWS_PROFILE")
        print("   You can also run 'aws configure' to set up credentials")
    
    success = True
    
    # Test configuration
    if not test_config_loading():
        success = False
    
    # Test Bedrock connection
    if not test_bedrock_connection():
        success = False
    
    if success:
        print("\n🎉 All tests passed! ThreatForest is ready to use with Bedrock.")
    else:
        print("\n💥 Some tests failed. Please check your AWS configuration.")
        sys.exit(1)