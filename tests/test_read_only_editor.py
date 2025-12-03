"""Test suite for read-only editor tool to verify write operations are blocked."""

import os
import sys
import tempfile
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

# Import the module directly to avoid package initialization
import importlib.util
spec = importlib.util.spec_from_file_location(
    "read_only_editor",
    Path(__file__).parent.parent / "src" / "threatforest" / "modules" / "tools" / "read_only_editor.py"
)
read_only_editor_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(read_only_editor_module)
read_only_editor = read_only_editor_module.read_only_editor


def test_view_command_allowed():
    """Test that view command works (read-only operation)."""
    # Create a temporary file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write("print('Hello, World!')\n")
        temp_path = f.name
    
    try:
        result = read_only_editor(
            command="view",
            path=temp_path
        )
        
        assert result["status"] == "success", "View command should succeed"
        print("✓ View command allowed (as expected)")
        
    finally:
        os.unlink(temp_path)


def test_find_line_command_allowed():
    """Test that find_line command works (read-only operation)."""
    # Create a temporary file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write("import os\nimport sys\nprint('test')\n")
        temp_path = f.name
    
    try:
        result = read_only_editor(
            command="find_line",
            path=temp_path,
            search_text="import os"
        )
        
        assert result["status"] == "success", "Find line command should succeed"
        print("✓ Find line command allowed (as expected)")
        
    finally:
        os.unlink(temp_path)


def test_create_command_blocked():
    """Test that create command is blocked."""
    temp_dir = tempfile.mkdtemp()
    temp_path = os.path.join(temp_dir, "test_file.txt")
    
    try:
        result = read_only_editor(
            command="create",
            path=temp_path
        )
        
        assert result["status"] == "error", "Create command should be blocked"
        assert "not allowed" in result["content"][0]["text"].lower(), "Error message should mention command not allowed"
        
        # Verify file was NOT created
        assert not os.path.exists(temp_path), "File should NOT have been created"
        print("✓ Create command blocked (as expected)")
        
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)
        os.rmdir(temp_dir)


def test_str_replace_command_blocked():
    """Test that str_replace command is blocked."""
    # Create a temporary file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        f.write("Hello World\n")
        temp_path = f.name
    
    try:
        original_content = open(temp_path).read()
        
        result = read_only_editor(
            command="str_replace",
            path=temp_path
        )
        
        assert result["status"] == "error", "str_replace command should be blocked"
        assert "not allowed" in result["content"][0]["text"].lower(), "Error message should mention command not allowed"
        
        # Verify file was NOT modified
        current_content = open(temp_path).read()
        assert current_content == original_content, "File content should NOT have changed"
        print("✓ str_replace command blocked (as expected)")
        
    finally:
        os.unlink(temp_path)


def test_pattern_replace_command_blocked():
    """Test that pattern_replace command is blocked."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        f.write("Test 123\n")
        temp_path = f.name
    
    try:
        original_content = open(temp_path).read()
        
        result = read_only_editor(
            command="pattern_replace",
            path=temp_path
        )
        
        assert result["status"] == "error", "pattern_replace command should be blocked"
        assert "not allowed" in result["content"][0]["text"].lower()
        
        # Verify file was NOT modified
        current_content = open(temp_path).read()
        assert current_content == original_content, "File content should NOT have changed"
        print("✓ pattern_replace command blocked (as expected)")
        
    finally:
        os.unlink(temp_path)


def test_insert_command_blocked():
    """Test that insert command is blocked."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        f.write("Line 1\nLine 2\n")
        temp_path = f.name
    
    try:
        original_content = open(temp_path).read()
        
        result = read_only_editor(
            command="insert",
            path=temp_path
        )
        
        assert result["status"] == "error", "insert command should be blocked"
        assert "not allowed" in result["content"][0]["text"].lower()
        
        # Verify file was NOT modified
        current_content = open(temp_path).read()
        assert current_content == original_content, "File content should NOT have changed"
        print("✓ insert command blocked (as expected)")
        
    finally:
        os.unlink(temp_path)


def test_undo_edit_command_blocked():
    """Test that undo_edit command is blocked."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        f.write("Some content\n")
        temp_path = f.name
    
    try:
        result = read_only_editor(
            command="undo_edit",
            path=temp_path
        )
        
        assert result["status"] == "error", "undo_edit command should be blocked"
        assert "not allowed" in result["content"][0]["text"].lower()
        print("✓ undo_edit command blocked (as expected)")
        
    finally:
        os.unlink(temp_path)


def run_all_tests():
    """Run all tests."""
    print("\n" + "="*60)
    print("Testing Read-Only Editor Wrapper")
    print("="*60 + "\n")
    
    tests = [
        ("View Command (Read)", test_view_command_allowed),
        ("Find Line Command (Read)", test_find_line_command_allowed),
        ("Create Command (Write)", test_create_command_blocked),
        ("String Replace Command (Write)", test_str_replace_command_blocked),
        ("Pattern Replace Command (Write)", test_pattern_replace_command_blocked),
        ("Insert Command (Write)", test_insert_command_blocked),
        ("Undo Edit Command (Write)", test_undo_edit_command_blocked),
    ]
    
    passed = 0
    failed = 0
    
    for test_name, test_func in tests:
        try:
            print(f"\nTesting: {test_name}")
            test_func()
            passed += 1
        except AssertionError as e:
            print(f"✗ FAILED: {test_name}")
            print(f"  Error: {e}")
            failed += 1
        except Exception as e:
            print(f"✗ ERROR: {test_name}")
            print(f"  Error: {e}")
            failed += 1
    
    print("\n" + "="*60)
    print(f"Test Results: {passed} passed, {failed} failed")
    print("="*60 + "\n")
    
    if failed == 0:
        print("✓ All tests passed! Read-only editor is properly secured.")
        return 0
    else:
        print("✗ Some tests failed. Please review the implementation.")
        return 1


if __name__ == "__main__":
    sys.exit(run_all_tests())
