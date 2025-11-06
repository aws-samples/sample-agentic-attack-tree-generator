"""Tests for resume functionality (Task 5.5)"""
import unittest
from threatforest.core.state import ThreatForestState, WorkflowStage


class TestResumeFunctionality(unittest.TestCase):
    """Test resume functionality and state validation"""
    
    def test_valid_state_for_resume(self):
        """Test that valid state passes resume validation"""
        state = ThreatForestState(
            project_path="/test/path",
            bedrock_model="test-model",
            current_stage=WorkflowStage.CONTEXT_ANALYSIS
        )
        state.setup_complete = True
        
        is_valid, message = state.is_valid_for_resume()
        
        self.assertTrue(is_valid)
        self.assertEqual(message, "State valid for resume")
    
    def test_complete_workflow_invalid_for_resume(self):
        """Test that completed workflow cannot be resumed"""
        state = ThreatForestState(
            project_path="/test/path",
            bedrock_model="test-model",
            current_stage=WorkflowStage.COMPLETE
        )
        
        is_valid, message = state.is_valid_for_resume()
        
        self.assertFalse(is_valid)
        self.assertEqual(message, "Workflow already complete")
    
    def test_inconsistent_state_invalid_for_resume(self):
        """Test that inconsistent state fails validation"""
        state = ThreatForestState(
            project_path="/test/path",
            bedrock_model="test-model",
            current_stage=WorkflowStage.EXTRACTION
        )
        # Missing setup_complete and context_complete flags
        
        is_valid, message = state.is_valid_for_resume()
        
        self.assertFalse(is_valid)
        self.assertIn("Setup incomplete", message)
    
    def test_state_validation_checks_all_stages(self):
        """Test that validation checks completion flags for all stages"""
        state = ThreatForestState(
            project_path="/test/path",
            bedrock_model="test-model",
            current_stage=WorkflowStage.TREE_GENERATION
        )
        state.setup_complete = True
        state.context_complete = True
        # Missing extraction_complete
        
        is_valid, message = state.is_valid_for_resume()
        
        self.assertFalse(is_valid)
        self.assertIn("Extraction incomplete", message)
    
    def test_valid_state_at_summary_stage(self):
        """Test valid state at summary stage"""
        state = ThreatForestState(
            project_path="/test/path",
            bedrock_model="test-model",
            current_stage=WorkflowStage.SUMMARY
        )
        state.setup_complete = True
        state.context_complete = True
        state.extraction_complete = True
        state.tree_generation_complete = True
        
        is_valid, message = state.is_valid_for_resume()
        
        self.assertTrue(is_valid)


if __name__ == '__main__':
    unittest.main()
