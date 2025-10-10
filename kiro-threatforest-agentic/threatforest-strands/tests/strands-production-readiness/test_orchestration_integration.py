"""Integration tests for orchestration (Task 4.6)"""
import unittest
from pathlib import Path
from threatforest.core.state import ThreatForestState, WorkflowStage
from threatforest.core.state_manager import StateManager
from threatforest.core.parallel import ParallelExecutor, ParallelTask
import tempfile


class TestOrchestrationIntegration(unittest.TestCase):
    """Test orchestration integration"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.state_manager = StateManager(state_dir=Path(self.temp_dir))
    
    def test_sequential_stage_execution(self):
        """Test that stages execute in correct order"""
        state = ThreatForestState(
            project_path="/test/path",
            bedrock_model="test-model"
        )
        
        # Simulate sequential execution
        self.assertEqual(state.current_stage, WorkflowStage.SETUP.value)
        
        state.advance_to(WorkflowStage.CONTEXT_ANALYSIS)
        self.assertEqual(state.current_stage, WorkflowStage.CONTEXT_ANALYSIS.value)
        
        state.advance_to(WorkflowStage.EXTRACTION)
        self.assertEqual(state.current_stage, WorkflowStage.EXTRACTION.value)
    
    def test_stage_dependencies_enforced(self):
        """Test that invalid stage transitions are prevented"""
        state = ThreatForestState(
            project_path="/test/path",
            bedrock_model="test-model"
        )
        
        # Try to skip stages
        with self.assertRaises(ValueError):
            state.advance_to(WorkflowStage.EXTRACTION)
    
    def test_resume_from_checkpoint(self):
        """Test resuming workflow from checkpoint"""
        # Create state at extraction stage
        state = ThreatForestState(
            project_path="/test/path",
            bedrock_model="test-model",
            current_stage=WorkflowStage.EXTRACTION
        )
        state.setup_complete = True
        state.context_complete = True
        
        # Save checkpoint
        self.state_manager.save_checkpoint(state)
        
        # Load checkpoint
        loaded_state = self.state_manager.load_checkpoint()
        
        self.assertIsNotNone(loaded_state)
        self.assertEqual(loaded_state.current_stage, WorkflowStage.EXTRACTION.value)
        self.assertTrue(loaded_state.setup_complete)
        self.assertTrue(loaded_state.context_complete)
    
    def test_error_isolation_in_parallel_tasks(self):
        """Test that error in one parallel task doesn't block others"""
        import asyncio
        
        async def success_task():
            return {"status": "success"}
        
        async def error_task():
            raise RuntimeError("Task failed")
        
        async def run_test():
            executor = ParallelExecutor(max_concurrent=2)
            tasks = [
                ParallelTask("success", success_task, {}),
                ParallelTask("error", error_task, {})
            ]
            results = await executor.execute(tasks)
            return results
        
        results = asyncio.run(run_test())
        
        # Success task should complete despite error task failing
        self.assertEqual(results["success"]["status"], "success")
        self.assertEqual(results["error"]["status"], "error")
    
    def test_state_persistence_after_each_stage(self):
        """Test that state is persisted after each stage"""
        state = ThreatForestState(
            project_path="/test/path",
            bedrock_model="test-model"
        )
        
        # Simulate stage completion with checkpoint
        state.setup_complete = True
        self.state_manager.save_checkpoint(state, "after_setup")
        
        state.advance_to(WorkflowStage.CONTEXT_ANALYSIS)
        state.context_complete = True
        self.state_manager.save_checkpoint(state, "after_context")
        
        # Verify both checkpoints exist
        checkpoints = self.state_manager.list_checkpoints()
        self.assertIn("after_setup", checkpoints)
        self.assertIn("after_context", checkpoints)


if __name__ == '__main__':
    unittest.main()
