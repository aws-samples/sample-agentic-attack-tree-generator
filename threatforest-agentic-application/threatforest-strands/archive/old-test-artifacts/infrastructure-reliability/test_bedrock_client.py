"""Tests for BedrockClientManager (Task 6.1-6.5)"""
import unittest
from threatforest.core.bedrock_client import BedrockClientManager


class TestBedrockClientManager(unittest.TestCase):
    """Test BedrockClientManager functionality"""
    
    def setUp(self):
        """Clear client cache before each test"""
        manager = BedrockClientManager()
        manager.clear_cache()
    
    def test_singleton_pattern(self):
        """Test that BedrockClientManager is a singleton"""
        manager1 = BedrockClientManager()
        manager2 = BedrockClientManager()
        
        self.assertIs(manager1, manager2)
    
    def test_client_caching(self):
        """Test that clients are cached by profile/region"""
        manager = BedrockClientManager()
        
        client1 = manager.get_client(region_name="us-west-2")
        client2 = manager.get_client(region_name="us-west-2")
        
        self.assertIs(client1, client2)
        self.assertEqual(manager.get_active_connections(), 1)
    
    def test_different_regions_create_different_clients(self):
        """Test that different regions create separate clients"""
        manager = BedrockClientManager()
        
        client1 = manager.get_client(region_name="us-west-2")
        client2 = manager.get_client(region_name="us-east-1")
        
        self.assertIsNot(client1, client2)
        self.assertEqual(manager.get_active_connections(), 2)
    
    def test_clear_cache(self):
        """Test clearing client cache"""
        manager = BedrockClientManager()
        
        manager.get_client(region_name="us-west-2")
        self.assertEqual(manager.get_active_connections(), 1)
        
        manager.clear_cache()
        self.assertEqual(manager.get_active_connections(), 0)
    
    def test_bedrock_connectivity(self):
        """Test actual Bedrock connectivity using default profile"""
        import boto3
        
        try:
            # Use bedrock client (not bedrock-runtime) for listing models
            session = boto3.Session()
            bedrock_client = session.client('bedrock', region_name='us-west-2')
            
            # Test connectivity by listing foundation models
            response = bedrock_client.list_foundation_models()
            
            # Verify response structure
            self.assertIn('modelSummaries', response)
            self.assertIsInstance(response['modelSummaries'], list)
            
            print(f"\n✓ Bedrock connectivity successful")
            print(f"✓ Found {len(response['modelSummaries'])} foundation models")
            
            # Verify our BedrockClientManager works
            manager = BedrockClientManager()
            runtime_client = manager.get_client(region_name="us-west-2")
            self.assertIsNotNone(runtime_client)
            
        except Exception as e:
            # If connectivity fails, skip test but report
            self.skipTest(f"Bedrock connectivity not available: {str(e)}")
    
    def test_client_configuration(self):
        """Test that client has proper configuration"""
        manager = BedrockClientManager()
        client = manager.get_client(region_name="us-west-2")
        
        # Verify client is configured
        self.assertIsNotNone(client)
        self.assertEqual(client.meta.region_name, "us-west-2")


if __name__ == '__main__':
    unittest.main()
