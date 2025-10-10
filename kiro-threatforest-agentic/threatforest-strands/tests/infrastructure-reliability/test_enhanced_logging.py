"""Tests for enhanced logging (Tasks 8.1-8.6)"""
import unittest
import tempfile
import json
from pathlib import Path
from threatforest.utils.logger import (
    ThreatForestLogger, set_correlation_id, get_correlation_id,
    log_with_context, log_performance
)


class TestEnhancedLogging(unittest.TestCase):
    """Test enhanced logging functionality"""
    
    def setUp(self):
        """Create temporary directory for logs"""
        self.temp_dir = tempfile.mkdtemp()
    
    def test_logger_initialization(self):
        """Test logger initializes correctly"""
        log_path = ThreatForestLogger.initialize(Path(self.temp_dir))
        
        self.assertIsNotNone(log_path)
        self.assertTrue(log_path.exists())
    
    def test_json_mode_logging(self):
        """Test JSON format logging"""
        log_path = ThreatForestLogger.initialize(Path(self.temp_dir), json_mode=True)
        logger = ThreatForestLogger.get_logger("test")
        
        logger.info("Test message")
        
        # Read log file and verify JSON format
        with open(log_path) as f:
            lines = f.readlines()
            # Find the test message line
            for line in lines:
                try:
                    log_entry = json.loads(line)
                    if log_entry.get('message') == 'Test message':
                        self.assertEqual(log_entry['level'], 'INFO')
                        self.assertIn('timestamp', log_entry)
                        break
                except json.JSONDecodeError:
                    continue
    
    def test_correlation_id(self):
        """Test correlation ID functionality"""
        # Set correlation ID
        corr_id = set_correlation_id("test-123")
        self.assertEqual(corr_id, "test-123")
        
        # Get correlation ID
        retrieved_id = get_correlation_id()
        self.assertEqual(retrieved_id, "test-123")
    
    def test_auto_generated_correlation_id(self):
        """Test auto-generated correlation ID"""
        corr_id = set_correlation_id()
        
        self.assertIsNotNone(corr_id)
        self.assertEqual(len(corr_id), 36)  # UUID format
    
    def test_structured_logging_with_context(self):
        """Test logging with additional context"""
        log_path = ThreatForestLogger.initialize(Path(self.temp_dir), json_mode=True)
        logger = ThreatForestLogger.get_logger("test")
        
        set_correlation_id("ctx-test")
        log_with_context(
            logger, 'INFO', 'Test with context',
            user='test_user',
            operation='test_op'
        )
        
        # Verify context was logged
        with open(log_path) as f:
            lines = f.readlines()
            for line in lines:
                try:
                    log_entry = json.loads(line)
                    if log_entry.get('message') == 'Test with context':
                        self.assertEqual(log_entry.get('user'), 'test_user')
                        self.assertEqual(log_entry.get('operation'), 'test_op')
                        break
                except json.JSONDecodeError:
                    continue
    
    def test_performance_logging(self):
        """Test performance metrics logging"""
        log_path = ThreatForestLogger.initialize(Path(self.temp_dir), json_mode=True)
        logger = ThreatForestLogger.get_logger("test")
        
        log_performance(
            logger, 'test_operation', 1.23,
            tokens=100,
            cache_hit=True
        )
        
        # Verify performance log
        with open(log_path) as f:
            lines = f.readlines()
            for line in lines:
                try:
                    log_entry = json.loads(line)
                    if 'Performance' in log_entry.get('message', ''):
                        self.assertEqual(log_entry.get('operation'), 'test_operation')
                        self.assertEqual(log_entry.get('duration_seconds'), 1.23)
                        break
                except json.JSONDecodeError:
                    continue


if __name__ == '__main__':
    unittest.main()
