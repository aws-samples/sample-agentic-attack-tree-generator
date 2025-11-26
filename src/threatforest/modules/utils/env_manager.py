"""Environment variable management utilities"""
import os
from pathlib import Path
from typing import Dict, Optional
from dotenv import load_dotenv


class EnvManager:
    """Manages .env file operations"""
    
    def __init__(self):
        # Import ROOT_DIR from config to use CLI-managed .env location
        from threatforest.config import ROOT_DIR
        self.env_file = ROOT_DIR / ".threatforest" / ".env"
        # Ensure directory exists
        self.env_file.parent.mkdir(parents=True, exist_ok=True)
    
    def get_value(self, key: str) -> Optional[str]:
        """Get value from .env file or environment"""
        # Check environment first
        value = os.getenv(key)
        if value:
            return value
        
        # Check .env file
        if self.env_file.exists():
            with open(self.env_file) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        env_key, env_value = line.split('=', 1)
                        if env_key.strip() == key:
                            return env_value.strip()
        return None
    
    def set_value(self, key: str, value: str):
        """Set value in .env file"""
        # Read existing .env
        lines = []
        key_found = False
        
        if self.env_file.exists():
            with open(self.env_file) as f:
                for line in f:
                    if line.strip().startswith(f"{key}="):
                        lines.append(f"{key}={value}\n")
                        key_found = True
                    else:
                        lines.append(line)
        
        # Add key if not found
        if not key_found:
            lines.append(f"{key}={value}\n")
        
        # Write back
        with open(self.env_file, 'w') as f:
            f.writelines(lines)
    
    def ensure_exists(self):
        """Ensure .env file exists"""
        if not self.env_file.exists():
            # Create from .env.example if available
            example_file = Path.cwd() / ".env.example"
            if example_file.exists():
                import shutil
                shutil.copy(example_file, self.env_file)
            else:
                # Create empty .env
                self.env_file.touch()
