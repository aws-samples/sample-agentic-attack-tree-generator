"""Integration tests for Strands framework implementation"""
import asyncio
from pathlib import Path
from threatforest.core import Tool, Agent, Context, tool, agent_step
from threatforest.strands_agent import ThreatForestOrchestrator, ThreatForestConfig
from threatforest.tools.setup_tool import SetupTool
from threatforest.tools.context_analysis_tool import ContextAnalysisTool


def test_tool_base_class():
    """Test that Tool base class works correctly"""
    tool = SetupTool()
    assert isinstance(tool, Tool)
    assert tool.name == "setup"
    assert hasattr(tool, 'execute')
    print("✓ Tool base class works")


def test_tool_decorator():
    """Test that @tool decorator is applied"""
    tool = SetupTool()
    assert hasattr(tool.execute, '_is_tool')
    assert tool.execute._tool_name == "setup"
    print("✓ @tool decorator works")


def test_agent_base_class():
    """Test that Agent base class works correctly"""
    config = ThreatForestConfig(project_path=Path.cwd())
    orchestrator = ThreatForestOrchestrator(config)
    
    assert isinstance(orchestrator, Agent)
    assert orchestrator.name == "ThreatForestOrchestrator"
    assert len(orchestrator.tools) == 6
    print("✓ Agent base class works")


def test_agent_tool_registration():
    """Test that tools are properly registered with agent"""
    config = ThreatForestConfig(project_path=Path.cwd())
    orchestrator = ThreatForestOrchestrator(config)
    
    expected_tools = [
        'setup', 'context_analysis', 'information_extraction',
        'attack_tree_generator', 'ttc_mapping', 'summary_generator'
    ]
    
    for tool_name in expected_tools:
        assert tool_name in orchestrator.tools
        assert isinstance(orchestrator.tools[tool_name], Tool)
    
    print("✓ All tools registered with agent")


async def test_agent_use_tool():
    """Test that agent can use tools"""
    config = ThreatForestConfig(project_path=Path.cwd())
    orchestrator = ThreatForestOrchestrator(config)
    
    # Test using setup tool
    result = await orchestrator.use_tool("setup", {
        "project_path": str(Path.cwd()),
        "interactive": False
    })
    
    assert isinstance(result, dict)
    assert 'setup_complete' in result
    print("✓ Agent can use tools")


def test_context_class():
    """Test that Context class works correctly"""
    context = Context()
    
    context.add("key1", "value1")
    context.add("key2", {"nested": "value"})
    
    assert context.get("key1") == "value1"
    assert context.get("key2")["nested"] == "value"
    assert context.get("nonexistent", "default") == "default"
    
    data = context.to_dict()
    assert "key1" in data
    assert "key2" in data
    
    print("✓ Context class works")


async def test_full_tool_chain():
    """Test that multiple tools can be chained together"""
    config = ThreatForestConfig(project_path=Path.cwd())
    orchestrator = ThreatForestOrchestrator(config)
    context = Context()
    
    # Step 1: Setup
    setup_result = await orchestrator.use_tool("setup", {
        "project_path": str(Path.cwd()),
        "interactive": False
    })
    context.add("setup", setup_result)
    assert 'setup_complete' in setup_result
    print("  ✓ Setup tool executed")
    
    # Step 2: Context analysis
    context_result = await orchestrator.use_tool("context_analysis", {
        "project_path": str(Path.cwd())
    })
    context.add("context_files", context_result)
    assert 'discovered_files' in context_result
    print("  ✓ Context analysis tool executed")
    
    # Verify context maintains state
    assert context.get("setup") is not None
    assert context.get("context_files") is not None
    
    print("✓ Tool chain works with context")


def test_no_mock_classes():
    """Verify no mock Strands classes are being used"""
    from threatforest.core import Tool as CoreTool, Agent as CoreAgent
    
    tool = SetupTool()
    config = ThreatForestConfig(project_path=Path.cwd())
    orchestrator = ThreatForestOrchestrator(config)
    
    # Verify they're using real classes, not mocks
    assert type(tool).__bases__[0] == CoreTool
    assert type(orchestrator).__bases__[0] == CoreAgent
    
    print("✓ No mock classes in use")


def run_all_tests():
    """Run all integration tests"""
    print("\n🧪 Running Strands Framework Integration Tests\n")
    
    # Synchronous tests
    test_tool_base_class()
    test_tool_decorator()
    test_agent_base_class()
    test_agent_tool_registration()
    test_context_class()
    test_no_mock_classes()
    
    # Asynchronous tests
    asyncio.run(test_agent_use_tool())
    asyncio.run(test_full_tool_chain())
    
    print("\n✅ All integration tests passed!")


if __name__ == "__main__":
    run_all_tests()
