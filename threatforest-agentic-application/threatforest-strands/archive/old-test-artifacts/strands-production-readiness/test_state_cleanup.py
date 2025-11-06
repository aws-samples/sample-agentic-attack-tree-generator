"""Tests for state cleanup functionality (Task 5.6)"""
import unittest
import tempfile
import json
from pathlib import Path
from datetime import datetime, timedelta
from threatforest.core.state_manager import StateManager
from threatforest.core.state import ThreatForestState, WorkflowStage


class TestStateCleanup(unittest.TestCase):
    """Test state cleanup and archival functionality"""
    
    def setUp(self):
        """Create temporary state directory for tests"""
        self.temp_dir = tempfile.mkdtemp()
        self.state_manager = StateManager(state_dir=Path(self.temp_dir))
    
    def test_archive_checkpoint(self):
        """Test archiving a checkpoint"""
        state = ThreatForestState(
            project_path="/test/path",
            bedrock_model="test-model"
        )
        
        # Save checkpoint
        self.state_manager.save_checkpoint(state)
        
        # Archive it
        archive_path = self.state_manager.archive_checkpoint("latest")
        
        self.assertIsNotNone(archive_path)
        self.assertTrue(archive_path.exists())
        self.assertIn("archive", str(archive_path))
    
    def test_archive_nonexistent_checkpoint(self):
        """Test archiving non-existent checkpoint returns None"""
        archive_path = self.state_manager.archive_checkpoint("nonexistent")
        self.assertIsNone(archive_path)
    
    def test_cleanup_completed_states(self):
        """Test cleanup removes completed workflow states"""
        # Create completed state
        completed_state = ThreatForestState(
            project_path="/test/path",
            bedrock_model="test-model",
            current_stage=WorkflowStage.COMPLETE
        )
        self.state_manager.save_checkpoint(completed_state, "completed")
        
        # Create in-progress state
        active_state = ThreatForestState(
            project_path="/test/path",
            bedrock_model="test-model",
            current_stage=WorkflowStage.EXTRACTION
        )
        self.state_manager.save_checkpoint(active_state, "active")
        
        # Cleanup
        self.state_manager.cleanup_completed_states()
        
        # Verify completed removed, active remains
        self.assertIsNone(self.state_manager.load_checkpoint("completed"))
        self.assertIsNotNone(self.state_manager.load_checkpoint("active"))
    
    def test_cleanup_old_checkpoints(self):
        """Test cleanup removes old checkpoints"""
        state = ThreatForestState(
            project_path="/test/path",
            bedrock_model="test-model"
        )
        
        # Save checkpoint
        self.state_manager.save_checkpoint(state, "old")
        checkpoint_file = self.state_manager.state_dir / "old.json"
        
        # Modify timestamp to be 10 days old
        old_time = (datetime.now() - timedelta(days=10)).timestamp()
        checkpoint_file.touch()
        import os
        os.utime(checkpoint_file, (old_time, old_time))
        
        # Cleanup checkpoints older than 7 days
        self.state_manager.cleanup_old_checkpoints(days=7)
        
        # Verify removed
        self.assertFalse(checkpoint_file.exists())
    
    def test_list_checkpoints(self):
        """Test listing available checkpoints"""
        state = ThreatForestState(
            project_path="/test/path",
            bedrock_model="test-model"
        )
        
        self.state_manager.save_checkpoint(state, "checkpoint1")
        self.state_manager.save_checkpoint(state, "checkpoint2")
        
        checkpoints = self.state_manager.list_checkpoints()
        
        self.assertIn("checkpoint1", checkpoints)
        self.assertIn("checkpoint2", checkpoints)
        self.assertEqual(len(checkpoints), 2)


if __name__ == '__main__':
    unittest.main()
