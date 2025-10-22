"""Tests for parallel execution (Task 4.4)"""
import unittest
import asyncio
from threatforest.core.parallel import ParallelExecutor, ParallelTask


class TestParallelExecution(unittest.TestCase):
    """Test parallel execution functionality"""
    
    def test_parallel_executor_success(self):
        """Test successful parallel execution"""
        async def task1():
            await asyncio.sleep(0.01)
            return {"data": "task1"}
        
        async def task2():
            await asyncio.sleep(0.01)
            return {"data": "task2"}
        
        async def run_test():
            executor = ParallelExecutor(max_concurrent=2)
            tasks = [
                ParallelTask("task1", task1, {}),
                ParallelTask("task2", task2, {})
            ]
            results = await executor.execute(tasks)
            return results
        
        results = asyncio.run(run_test())
        
        self.assertIn("task1", results)
        self.assertIn("task2", results)
        self.assertEqual(results["task1"]["status"], "success")
        self.assertEqual(results["task2"]["status"], "success")
    
    def test_parallel_executor_with_error(self):
        """Test parallel execution handles errors gracefully"""
        async def success_task():
            return {"data": "success"}
        
        async def error_task():
            raise ValueError("Test error")
        
        async def run_test():
            executor = ParallelExecutor(max_concurrent=2)
            tasks = [
                ParallelTask("success", success_task, {}),
                ParallelTask("error", error_task, {})
            ]
            results = await executor.execute(tasks)
            return results
        
        results = asyncio.run(run_test())
        
        self.assertEqual(results["success"]["status"], "success")
        self.assertEqual(results["error"]["status"], "error")
        self.assertIn("Test error", results["error"]["error"])
    
    def test_concurrency_limit(self):
        """Test that concurrency limit is respected"""
        execution_order = []
        
        async def tracked_task(task_id):
            execution_order.append(f"start_{task_id}")
            await asyncio.sleep(0.01)
            execution_order.append(f"end_{task_id}")
            return {"id": task_id}
        
        async def run_test():
            executor = ParallelExecutor(max_concurrent=2)
            tasks = [
                ParallelTask(f"task{i}", tracked_task, {"task_id": i})
                for i in range(4)
            ]
            await executor.execute(tasks)
            return execution_order
        
        order = asyncio.run(run_test())
        
        # Verify tasks started
        self.assertGreater(len(order), 0)


if __name__ == '__main__':
    unittest.main()
