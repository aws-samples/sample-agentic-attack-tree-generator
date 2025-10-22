"""Tests for Pipeline class (Task 4.2)"""
import unittest
import asyncio
from threatforest.core.pipeline import Pipeline, Stage
from threatforest.core.state import WorkflowStage


class TestPipeline(unittest.TestCase):
    """Test Pipeline orchestration"""
    
    def test_add_stage(self):
        """Test adding stages to pipeline"""
        pipeline = Pipeline()
        
        async def dummy_fn():
            return {}
        
        stage = Stage(
            name="test_stage",
            stage_type=WorkflowStage.SETUP,
            execute_fn=dummy_fn,
            dependencies=[]
        )
        
        pipeline.add_stage(stage)
        self.assertEqual(len(pipeline.stages), 1)
    
    def test_validate_dependencies_success(self):
        """Test dependency validation succeeds with valid dependencies"""
        pipeline = Pipeline()
        
        async def dummy_fn():
            return {}
        
        stage1 = Stage(
            name="setup",
            stage_type=WorkflowStage.SETUP,
            execute_fn=dummy_fn,
            dependencies=[]
        )
        
        stage2 = Stage(
            name="context",
            stage_type=WorkflowStage.CONTEXT_ANALYSIS,
            execute_fn=dummy_fn,
            dependencies=[WorkflowStage.SETUP]
        )
        
        pipeline.add_stage(stage1)
        pipeline.add_stage(stage2)
        
        self.assertTrue(pipeline.validate_dependencies())
    
    def test_validate_dependencies_failure(self):
        """Test dependency validation fails with missing dependencies"""
        pipeline = Pipeline()
        
        async def dummy_fn():
            return {}
        
        stage = Stage(
            name="context",
            stage_type=WorkflowStage.CONTEXT_ANALYSIS,
            execute_fn=dummy_fn,
            dependencies=[WorkflowStage.SETUP]  # Missing SETUP stage
        )
        
        pipeline.add_stage(stage)
        
        self.assertFalse(pipeline.validate_dependencies())
    
    def test_get_next_stages(self):
        """Test getting next executable stages based on completed stages"""
        pipeline = Pipeline()
        
        async def dummy_fn():
            return {}
        
        stage1 = Stage(
            name="setup",
            stage_type=WorkflowStage.SETUP,
            execute_fn=dummy_fn,
            dependencies=[]
        )
        
        stage2 = Stage(
            name="context",
            stage_type=WorkflowStage.CONTEXT_ANALYSIS,
            execute_fn=dummy_fn,
            dependencies=[WorkflowStage.SETUP]
        )
        
        pipeline.add_stage(stage1)
        pipeline.add_stage(stage2)
        
        # No stages completed - only SETUP should be ready
        next_stages = pipeline.get_next_stages([])
        self.assertEqual(len(next_stages), 1)
        self.assertEqual(next_stages[0].stage_type, WorkflowStage.SETUP)
        
        # SETUP completed - CONTEXT_ANALYSIS should be ready
        next_stages = pipeline.get_next_stages([WorkflowStage.SETUP])
        self.assertEqual(len(next_stages), 1)
        self.assertEqual(next_stages[0].stage_type, WorkflowStage.CONTEXT_ANALYSIS)
    
    def test_execute_stage(self):
        """Test executing a stage"""
        async def test_fn(value):
            return {"result": value * 2}
        
        async def run_test():
            pipeline = Pipeline()
            stage = Stage(
                name="test",
                stage_type=WorkflowStage.SETUP,
                execute_fn=test_fn,
                dependencies=[]
            )
            
            result = await pipeline.execute_stage(stage, {"value": 5})
            return result
        
        result = asyncio.run(run_test())
        self.assertEqual(result["result"], 10)


if __name__ == '__main__':
    unittest.main()
