"""Progress emitter for streaming workflow updates to UI"""
import sys
import threading
from typing import Optional
from .progress_events import ProgressEvent


class ProgressEmitter:
    """Thread-safe progress event emitter"""
    
    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self._lock = threading.Lock()
    
    def emit(self, event: ProgressEvent):
        """Emit a progress event to stdout
        
        Events are prefixed with PROGRESS: for easy parsing by UI.
        Failures are silently ignored to prevent workflow crashes.
        """
        if not self.enabled:
            return
        
        try:
            with self._lock:
                event_json = event.model_dump_json()
                print(f"PROGRESS:{event_json}", flush=True, file=sys.stdout)
        except Exception:
            # Silently ignore emission failures
            pass
