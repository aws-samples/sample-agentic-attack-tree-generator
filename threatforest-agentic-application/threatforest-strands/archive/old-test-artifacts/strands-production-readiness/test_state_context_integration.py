"""Tests for state integration with orchestrator context (Task 5.4)"""
import unittest
from threatforest.core.context import Context
from threatforest.core.state import ThreatForestState, WorkflowStage


class TestStateContextIntegration(unittest.TestCase):
    """Test state integration with orchestrator context"""
    
    def test_state_added_to_context(self):
        """Test that state can be added to context"""
        context = Context()
        state = ThreatForestState(project_path="/test/path", bedrock_model="test-model")
        
        context.add("workflow_state", state.model_dump())
        
        self.assertIn("workflow_state", context.data)
        self.assertEqual(context.data["workflow_state"]["current_stage"], WorkflowStage.SETUP.value)

    def test_state_updates_in_context(self):
        """Test that state updates are reflected in context"""
        context = Context()
        state = ThreatForestState(project_path="/test/path", bedrock_model="test-model")
        
        # Initial state
        context.add("workflow_state", state.model_dump())
        self.assertEqual(context.data["workflow_state"]["current_stage"], WorkflowStage.SETUP.value)
        
        # Update state
        state.advance_to(WorkflowStage.CONTEXT_ANALYSIS)
        context.add("workflow_state", state.model_dump())
        
        self.assertEqual(context.data["workflow_state"]["current_stage"], WorkflowStage.CONTEXT_ANALYSIS.value)

    def test_state_contains_stage_completion_flags(self):
        """Test that state in context contains completion flags"""
        context = Context()
        state = ThreatForestState(project_path="/test/path", bedrock_model="test-model")
        state.setup_complete = True
        
        context.add("workflow_state", state.model_dump())
        
        self.assertTrue(context.data["workflow_state"]["setup_complete"])
        self.assertFalse(context.data["workflow_state"]["context_complete"])

    def test_context_to_dict_includes_state(self):
        """Test that context.to_dict() includes workflow state"""
        context = Context()
        state = ThreatForestState(project_path="/test/path", bedrock_model="test-model")
        
        context.add("workflow_state", state.model_dump())
        context.add("other_data", {"key": "value"})
        
        context_dict = context.to_dict()
        
        self.assertIn("workflow_state", context_dict)
        self.assertIn("other_data", context_dict)
        self.assertEqual(context_dict["workflow_state"]["current_stage"], WorkflowStage.SETUP.value)


if __name__ == '__main__':
    unittest.main()
