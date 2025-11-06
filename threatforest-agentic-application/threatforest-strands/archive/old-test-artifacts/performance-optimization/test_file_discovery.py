"""Tests for FileDiscovery (Tasks 9.1-9.6)"""
import unittest
import tempfile
import os
from pathlib import Path
from threatforest.core import FileDiscovery, DiscoveredFiles


class TestFileDiscovery(unittest.TestCase):
    """Test FileDiscovery functionality"""
    
    def setUp(self):
        """Create temporary test directory structure"""
        self.temp_dir = tempfile.mkdtemp()
        
        # Create test files
        (Path(self.temp_dir) / "threats.md").write_text("# Threats")
        (Path(self.temp_dir) / "README.md").write_text("# README")
        (Path(self.temp_dir) / "config.json").write_text('{"key": "value"}')
        (Path(self.temp_dir) / "app.py").write_text("print('hello')")
        (Path(self.temp_dir) / "diagram.mmd").write_text("graph TD")
        
        # Create excluded directory
        excluded = Path(self.temp_dir) / "node_modules"
        excluded.mkdir()
        (excluded / "package.json").write_text('{}')
        
        # Clear cache before each test
        FileDiscovery.clear_cache()
    
    def test_single_pass_discovery(self):
        """Test that discovery happens in single pass"""
        result = FileDiscovery.discover(self.temp_dir)
        
        self.assertIsInstance(result, DiscoveredFiles)
        self.assertGreater(result.total_files, 0)
        self.assertGreater(result.discovery_time_ms, 0)
    
    def test_threat_file_detection(self):
        """Test threat file detection"""
        result = FileDiscovery.discover(self.temp_dir)
        
        threat_files = [Path(f).name for f in result.threat_models]
        self.assertIn("threats.md", threat_files)
    
    def test_file_categorization(self):
        """Test file categorization"""
        result = FileDiscovery.discover(self.temp_dir)
        
        # Check categories
        self.assertGreater(len(result.threat_models), 0)
        self.assertGreater(len(result.source_code), 0)
        self.assertGreater(len(result.documentation), 0)
        self.assertGreater(len(result.diagrams), 0)
    
    def test_excluded_directories(self):
        """Test that excluded directories are skipped"""
        result = FileDiscovery.discover(self.temp_dir)
        
        # node_modules files should not be discovered
        all_paths = ' '.join(result.all_files)
        self.assertNotIn('node_modules', all_paths)
        self.assertGreater(result.excluded_dirs, 0)
    
    def test_caching(self):
        """Test that results are cached"""
        # First call
        result1 = FileDiscovery.discover(self.temp_dir)
        time1 = result1.discovery_time_ms
        
        # Second call (should be cached)
        result2 = FileDiscovery.discover(self.temp_dir)
        
        # Results should be identical
        self.assertEqual(result1.total_files, result2.total_files)
        self.assertEqual(len(result1.threat_models), len(result2.threat_models))
    
    def test_metadata_collection(self):
        """Test metadata collection"""
        result = FileDiscovery.discover(self.temp_dir)
        
        self.assertGreater(result.total_files, 0)
        self.assertGreater(result.total_size_bytes, 0)
        self.assertGreater(result.discovery_time_ms, 0)
    
    def test_nonexistent_path(self):
        """Test handling of nonexistent path"""
        result = FileDiscovery.discover("/nonexistent/path")
        
        self.assertEqual(result.total_files, 0)
        self.assertEqual(len(result.all_files), 0)


if __name__ == '__main__':
    unittest.main()
