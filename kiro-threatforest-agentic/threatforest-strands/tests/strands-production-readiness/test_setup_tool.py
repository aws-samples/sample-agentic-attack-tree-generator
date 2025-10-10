"""Test SetupTool with real Strands framework"""
import unittest
import asyncio
from pathlib import Path
from threatforest.tools.setup_tool import SetupTool


class TestSetupTool(unittest.TestCase):
    """Test SetupTool with real Strands framework"""
    
    def test_setup_tool_initialization(self):
        """Test that SetupTool initializes with Strands framework"""
        tool = SetupTool()
        
        self.assertEqual(tool.name, "setup")
        self.assertIsNotNone(tool.description)
        self.assertTrue(hasattr(tool, 'execute'))
        self.assertTrue(callable(tool.execute))

    def test_setup_tool_execute(self):
        """Test that SetupTool execute method works"""
        async def run_test():
            tool = SetupTool()
            result = await tool.execute(
                project_path=str(Path.cwd()),
                interactive=False
            )
            return result
        
        result = asyncio.run(run_test())
        self.assertIsInstance(result, dict)


if __name__ == '__main__':
    unittest.main()
    assert 'project_path' in result
    assert 'setup_complete' in result


if __name__ == "__main__":
    # Run tests
    asyncio.run(test_setup_tool_initialization())
    asyncio.run(test_setup_tool_execute())
    print("✅ SetupTool tests passed!")
