"""State Manager for persisting and managing workflow state"""
import json
from pathlib import Path
from typing import Optional
from datetime import datetime, timedelta
from .state import ThreatForestState, WorkflowStage


class StateManager:
    """Manages workflow state persistence and recovery"""
    
    def __init__(self, state_dir: Optional[Path] = None):
        self.state_dir = state_dir or Path.home() / ".threatforest" / "state"
        self.state_dir.mkdir(parents=True, exist_ok=True)
    
    def save_checkpoint(self, state: ThreatForestState, checkpoint_name: str = "latest"):
        """Save state checkpoint to disk"""
        checkpoint_file = self.state_dir / f"{checkpoint_name}.json"
        
        with open(checkpoint_file, 'w') as f:
            f.write(state.model_dump_json(indent=2))
    
    def load_checkpoint(self, checkpoint_name: str = "latest") -> Optional[ThreatForestState]:
        """Load state checkpoint from disk"""
        checkpoint_file = self.state_dir / f"{checkpoint_name}.json"
        
        if not checkpoint_file.exists():
            return None
        
        with open(checkpoint_file) as f:
            data = json.load(f)
            return ThreatForestState(**data)
    
    def list_checkpoints(self) -> list[str]:
        """List available checkpoints"""
        return [f.stem for f in self.state_dir.glob("*.json")]
    
    def delete_checkpoint(self, checkpoint_name: str):
        """Delete a specific checkpoint"""
        checkpoint_file = self.state_dir / f"{checkpoint_name}.json"
        if checkpoint_file.exists():
            checkpoint_file.unlink()
    
    def cleanup_old_checkpoints(self, days: int = 7):
        """Remove checkpoints older than specified days"""
        cutoff = datetime.now() - timedelta(days=days)
        
        for checkpoint_file in self.state_dir.glob("*.json"):
            if checkpoint_file.stat().st_mtime < cutoff.timestamp():
                checkpoint_file.unlink()
    
    def archive_checkpoint(self, checkpoint_name: str = "latest") -> Optional[Path]:
        """Archive a checkpoint with timestamp"""
        checkpoint_file = self.state_dir / f"{checkpoint_name}.json"
        
        if not checkpoint_file.exists():
            return None
        
        # Create archive directory
        archive_dir = self.state_dir / "archive"
        archive_dir.mkdir(exist_ok=True)
        
        # Archive with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        archive_file = archive_dir / f"{checkpoint_name}_{timestamp}.json"
        
        # Copy to archive
        archive_file.write_text(checkpoint_file.read_text())
        
        return archive_file
    
    def cleanup_completed_states(self):
        """Remove states for completed workflows"""
        for checkpoint_file in self.state_dir.glob("*.json"):
            try:
                with open(checkpoint_file) as f:
                    data = json.load(f)
                    if data.get("current_stage") == WorkflowStage.COMPLETE.value:
                        checkpoint_file.unlink()
            except (json.JSONDecodeError, KeyError):
                continue
