"""Tests for state management functionality"""
from pathlib import Path
from threatforest.core import ThreatForestState, WorkflowStage, StateManager


def test_state_model_creation():
    """Test creating a state model"""
    state = ThreatForestState(
        project_path="/test/path",
        bedrock_model="test-model"
    )
    
    assert state.current_stage == WorkflowStage.SETUP
    assert state.project_path == "/test/path"
    assert not state.setup_complete
    print("✓ State model creation works")


def test_state_transitions():
    """Test state transition validation"""
    state = ThreatForestState(
        project_path="/test/path",
        bedrock_model="test-model"
    )
    
    # Valid transition
    assert state.can_transition_to(WorkflowStage.CONTEXT_ANALYSIS)
    state.advance_to(WorkflowStage.CONTEXT_ANALYSIS)
    assert state.current_stage == WorkflowStage.CONTEXT_ANALYSIS
    
    # Invalid transition
    assert not state.can_transition_to(WorkflowStage.SUMMARY)
    
    print("✓ State transitions work")


def test_state_manager_save_load():
    """Test saving and loading state"""
    import tempfile
    
    with tempfile.TemporaryDirectory() as tmpdir:
        manager = StateManager(Path(tmpdir))
        
        # Create and save state
        state = ThreatForestState(
            project_path="/test/path",
            bedrock_model="test-model"
        )
        state.setup_complete = True
        manager.save_checkpoint(state, "test")
        
        # Load state
        loaded_state = manager.load_checkpoint("test")
        assert loaded_state is not None
        assert loaded_state.setup_complete
        assert loaded_state.project_path == "/test/path"
        
        print("✓ State save/load works")


def test_state_manager_cleanup():
    """Test checkpoint cleanup"""
    import tempfile
    
    with tempfile.TemporaryDirectory() as tmpdir:
        manager = StateManager(Path(tmpdir))
        
        # Create multiple checkpoints
        for i in range(3):
            state = ThreatForestState(
                project_path=f"/test/path{i}",
                bedrock_model="test-model"
            )
            manager.save_checkpoint(state, f"checkpoint{i}")
        
        # List checkpoints
        checkpoints = manager.list_checkpoints()
        assert len(checkpoints) == 3
        
        # Delete one
        manager.delete_checkpoint("checkpoint1")
        checkpoints = manager.list_checkpoints()
        assert len(checkpoints) == 2
        
        print("✓ State cleanup works")


def run_all_tests():
    """Run all state management tests"""
    print("\n🧪 Running State Management Tests\n")
    
    test_state_model_creation()
    test_state_transitions()
    test_state_manager_save_load()
    test_state_manager_cleanup()
    
    print("\n✅ All state management tests passed!")


if __name__ == "__main__":
    run_all_tests()
