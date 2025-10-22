"""Tests for input validation (Tasks 7.1-7.2)"""
import unittest
import tempfile
from pathlib import Path
from pydantic import ValidationError
from threatforest.core.validation import (
    SetupToolInput, ContextAnalysisInput, ExtractionToolInput,
    AttackTreeGeneratorInput, TTCMappingInput, SummaryGeneratorInput
)


class TestSetupToolInput(unittest.TestCase):
    """Test SetupToolInput validation"""
    
    def setUp(self):
        """Create temporary directory"""
        self.temp_dir = tempfile.mkdtemp()
    
    def test_valid_input(self):
        """Test valid setup tool input"""
        input_data = SetupToolInput(
            project_path=self.temp_dir,
            aws_profile="default",
            bedrock_model="test-model"
        )
        
        self.assertIsNotNone(input_data)
        self.assertTrue(Path(input_data.project_path).exists())
    
    def test_invalid_project_path(self):
        """Test invalid project path"""
        with self.assertRaises(ValidationError) as context:
            SetupToolInput(project_path="/nonexistent/path")
        
        self.assertIn("does not exist", str(context.exception))


class TestContextAnalysisInput(unittest.TestCase):
    """Test ContextAnalysisInput validation"""
    
    def setUp(self):
        """Create temporary directory"""
        self.temp_dir = tempfile.mkdtemp()
    
    def test_valid_input(self):
        """Test valid context analysis input"""
        input_data = ContextAnalysisInput(project_path=self.temp_dir)
        
        self.assertIsNotNone(input_data)
        self.assertTrue(Path(input_data.project_path).exists())
    
    def test_invalid_project_path(self):
        """Test invalid project path"""
        with self.assertRaises(ValidationError):
            ContextAnalysisInput(project_path="/nonexistent/path")


class TestExtractionToolInput(unittest.TestCase):
    """Test ExtractionToolInput validation"""
    
    def test_valid_input(self):
        """Test valid extraction tool input"""
        input_data = ExtractionToolInput(
            context_files={"file1": "content"},
            bedrock_model="test-model"
        )
        
        self.assertIsNotNone(input_data)
        self.assertEqual(input_data.bedrock_model, "test-model")
    
    def test_empty_context_files(self):
        """Test empty context files"""
        with self.assertRaises(ValidationError) as context:
            ExtractionToolInput(
                context_files={},
                bedrock_model="test-model"
            )
        
        self.assertIn("cannot be empty", str(context.exception))
    
    def test_invalid_bedrock_model(self):
        """Test invalid bedrock model"""
        with self.assertRaises(ValidationError):
            ExtractionToolInput(
                context_files={"file1": "content"},
                bedrock_model=""
            )


class TestAttackTreeGeneratorInput(unittest.TestCase):
    """Test AttackTreeGeneratorInput validation"""
    
    def test_valid_input(self):
        """Test valid attack tree generator input"""
        input_data = AttackTreeGeneratorInput(
            threat_statements=[{"id": "T001", "statement": "Test threat"}],
            extracted_info={"app": "test"},
            bedrock_model="test-model"
        )
        
        self.assertIsNotNone(input_data)
        self.assertEqual(len(input_data.threat_statements), 1)
    
    def test_empty_threat_statements(self):
        """Test empty threat statements"""
        with self.assertRaises(ValidationError) as context:
            AttackTreeGeneratorInput(
                threat_statements=[],
                extracted_info={"app": "test"},
                bedrock_model="test-model"
            )
        
        self.assertIn("cannot be empty", str(context.exception))


class TestSummaryGeneratorInput(unittest.TestCase):
    """Test SummaryGeneratorInput validation"""
    
    def setUp(self):
        """Create temporary directory"""
        self.temp_dir = tempfile.mkdtemp()
    
    def test_valid_input(self):
        """Test valid summary generator input"""
        input_data = SummaryGeneratorInput(
            attack_trees={"tree1": {}},
            extracted_info={"app": "test"},
            output_dir=self.temp_dir
        )
        
        self.assertIsNotNone(input_data)
        self.assertTrue(Path(input_data.output_dir).exists())
    
    def test_creates_output_dir(self):
        """Test that output directory is created if it doesn't exist"""
        new_dir = Path(self.temp_dir) / "new_output"
        
        input_data = SummaryGeneratorInput(
            attack_trees={"tree1": {}},
            extracted_info={"app": "test"},
            output_dir=str(new_dir)
        )
        
        self.assertTrue(Path(input_data.output_dir).exists())


if __name__ == '__main__':
    unittest.main()
