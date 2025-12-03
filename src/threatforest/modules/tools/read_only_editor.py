"""Read-only editor tool wrapper for safe repository analysis.

This module provides a restricted version of the editor tool that only allows
read operations (view and find_line), preventing any file modifications during
autonomous repository exploration.
"""

from typing import Any, Dict, List, Optional
from strands_tools import editor
from strands import tool


@tool
def read_only_editor(
    command: str,
    path: str,
    search_text: Optional[str] = None,
    fuzzy: bool = False,
    view_range: Optional[List[int]] = None,
) -> Dict[str, Any]:
    """
    Read-only editor tool - restricts editor to view and find_line operations only.
    
    This wrapper prevents any file modifications while preserving the rich display
    features of the editor tool (syntax highlighting, directory trees, etc.).
    
    Allowed commands:
    - view: Display file content with syntax highlighting or directory structure
    - find_line: Search for text in files
    
    Blocked commands (will return error):
    - create: Create new files
    - str_replace: Replace text in files
    - pattern_replace: Pattern-based text replacement
    - insert: Insert text into files
    - undo_edit: Restore file backups
    
    Args:
        command: The command to run ('view' or 'find_line')
        path: Absolute path to file or directory, e.g. `/repo/file.py` or `/repo`.
              User paths with tilde (~) are automatically expanded.
        search_text: Text to search for in `find_line` command. Supports fuzzy matching.
        fuzzy: Enable fuzzy matching for `find_line` command.
        view_range: Optional parameter of `view` command. Line range to show [start, end].
                   Supports negative indices.
        
    Returns:
        Dict containing status and response content in the format:
        {
            "status": "success|error",
            "content": [{"text": "Response message"}]
        }
        
    Examples:
        1. View a file:
           read_only_editor(command="view", path="/path/to/file.py")
        
        2. View a directory structure:
           read_only_editor(command="view", path="/path/to/directory")
        
        3. View specific line range:
           read_only_editor(command="view", path="/path/to/file.py", view_range=[10, 20])
        
        4. Find text in a file:
           read_only_editor(command="find_line", path="/path/to/file.py", search_text="import os")
        
        5. Fuzzy search:
           read_only_editor(command="find_line", path="/path/to/file.py", search_text="def main", fuzzy=True)
    """
    # Whitelist only read operations
    ALLOWED_COMMANDS = ["view", "find_line"]
    
    if command not in ALLOWED_COMMANDS:
        return {
            "status": "error",
            "content": [{
                "text": (
                    f"❌ Command '{command}' is not allowed in read-only mode.\n\n"
                    f"This tool only supports read operations to prevent accidental file modifications.\n\n"
                    f"Allowed commands: {', '.join(ALLOWED_COMMANDS)}\n"
                    f"Blocked commands: create, str_replace, pattern_replace, insert, undo_edit"
                )
            }]
        }
    
    # Call original editor with only safe parameters
    # Note: We explicitly don't pass any write-related parameters
    return editor(
        command=command,
        path=path,
        search_text=search_text,
        fuzzy=fuzzy,
        view_range=view_range
    )
