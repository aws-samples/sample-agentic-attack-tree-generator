"""Test SetupTool with real Strands framework"""
import pytest
import asyncio
from pathlib import Path
from threatforest.tools.setup_tool import SetupTool


@pytest.mark.asyncio
async def test_setup_tool_initialization():
    """Test that SetupTool initializes with Strands framework"""
    tool = SetupTool()
    
    assert tool.name == "setup"
    assert tool.description is not None
    assert hasattr(tool, 'execute')
    assert hasattr(tool.execute, '_is_tool')


@pytest.mark.asyncio
async def test_setup_tool_execute():
    """Test that SetupTool execute method works"""
    tool = SetupTool()
    
    # Test with minimal parameters
    result = await tool.execute(
        project_path=str(Path.cwd()),
        interactive=False
    )
    
    assert isinstance(result, dict)
    assert 'project_path' in result
    assert 'setup_complete' in result


if __name__ == "__main__":
    # Run tests
    asyncio.run(test_setup_tool_initialization())
    asyncio.run(test_setup_tool_execute())
    print("✅ SetupTool tests passed!")
