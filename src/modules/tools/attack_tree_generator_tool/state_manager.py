"""State management for attack tree generation tracking"""
import json
import time
from typing import Dict
from pathlib import Path


class StateManager:
    """Manages state tracking for attack tree generation"""
    
    def __init__(self, logger):
        """Initialize state manager
        
        Args:
            logger: Logger instance
        """
        self.logger = logger
    
    def load_state(self, output_dir: str) -> Dict[str, str]:
        """Load threat generation state from file
        
        Args:
            output_dir: Directory containing state file
            
        Returns:
            Dict mapping threat_id to status ('success'/'failed')
        """
        state_file = Path(output_dir) / ".threatforest_state.json"
        if state_file.exists():
            try:
                with open(state_file) as f:
                    data = json.load(f)
                    self.logger.info(f"Loaded state: {len(data.get('threat_status', {}))} threats tracked")
                    return data.get('threat_status', {})
            except Exception as e:
                self.logger.warning(f"Failed to load state file: {e}")
        return {}
    
    def save_state(self, output_dir: str, threat_status: Dict[str, str]) -> None:
        """Save threat generation state to file
        
        Args:
            output_dir: Directory to save state file
            threat_status: Dict mapping threat_id to status
        """
        state_file = Path(output_dir) / ".threatforest_state.json"
        try:
            state_file.parent.mkdir(parents=True, exist_ok=True)
            with open(state_file, 'w') as f:
                json.dump({
                    'threat_status': threat_status,
                    'last_updated': time.strftime('%Y-%m-%d %H:%M:%S')
                }, f, indent=2)
            self.logger.info(f"Saved state: {len(threat_status)} threats tracked")
        except Exception as e:
            self.logger.warning(f"Failed to save state file: {e}")
    
    @staticmethod
    def filter_threats_to_process(high_threats: list, existing_status: Dict[str, str]) -> tuple:
        """Filter out already-successful threats
        
        Args:
            high_threats: List of high-severity threats
            existing_status: Dict of existing threat statuses
            
        Returns:
            Tuple of (threats_to_process, skipped_count)
        """
        existing_status = existing_status or {}
        threats_to_process = [
            t for t in high_threats 
            if existing_status.get(t.get("id", ""), "") != "success"
        ]
        
        skipped_count = len(high_threats) - len(threats_to_process)
        return threats_to_process, skipped_count
