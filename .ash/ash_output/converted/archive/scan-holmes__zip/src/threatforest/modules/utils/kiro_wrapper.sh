#!/bin/bash
#
# Kiro IDE Hook Wrapper for ThreatForest
# This wrapper script makes it easier to call the ThreatForest Kiro hook from Kiro IDE
#
# Usage: kiro_wrapper.sh <path-to-threatcomposer-file.tc.json>
#

set -e  # Exit on error

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# ThreatForest root directory (4 levels up from src/modules/utils/)
THREATFOREST_ROOT="$(dirname "$(dirname "$(dirname "$SCRIPT_DIR")")")"

# Path to the Python hook handler
HOOK_HANDLER="$SCRIPT_DIR/kiro_hook.py"

# Path to Python (try to use the virtualenv if it exists)
if [ -f "$THREATFOREST_ROOT/.venv/bin/python" ]; then
    PYTHON_BIN="$THREATFOREST_ROOT/.venv/bin/python"
    echo -e "${GREEN}✓ Using virtual environment: .venv${NC}"
elif [ -f "$THREATFOREST_ROOT/venv/bin/python" ]; then
    PYTHON_BIN="$THREATFOREST_ROOT/venv/bin/python"
    echo -e "${GREEN}✓ Using virtual environment: venv${NC}"
else
    PYTHON_BIN="python3"
    echo -e "${YELLOW}⚠️  No virtual environment found, using system Python${NC}"
    echo -e "${YELLOW}   For best results, create a venv:${NC}"
    echo -e "${YELLOW}   cd $THREATFOREST_ROOT && python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt${NC}"
    echo ""
fi

# Check if ThreatComposer file path is provided
if [ $# -eq 0 ]; then
    echo -e "${RED}Error: No ThreatComposer file path provided${NC}"
    echo "Usage: $0 <path-to-threatcomposer-file.tc.json>"
    exit 1
fi

THREATCOMPOSER_FILE="$1"

# Check if file exists
if [ ! -f "$THREATCOMPOSER_FILE" ]; then
    echo -e "${RED}Error: File not found: $THREATCOMPOSER_FILE${NC}"
    exit 1
fi

# Check if it's a .tc.json file
if [[ ! "$THREATCOMPOSER_FILE" =~ \.tc\.json$ ]]; then
    echo -e "${YELLOW}Warning: File does not have .tc.json extension${NC}"
    echo "File: $THREATCOMPOSER_FILE"
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Aborted."
        exit 1
    fi
fi

# Print info
echo -e "${GREEN}ThreatForest Kiro Hook${NC}"
echo "Python: $PYTHON_BIN"
echo "ThreatComposer file: $THREATCOMPOSER_FILE"
echo ""

# Make sure the Python script is executable
chmod +x "$HOOK_HANDLER"

# Call the Python hook handler
"$PYTHON_BIN" "$HOOK_HANDLER" "$THREATCOMPOSER_FILE"

# Capture exit code
EXIT_CODE=$?

# Print result
if [ $EXIT_CODE -eq 0 ]; then
    echo -e "\n${GREEN}✓ Hook completed successfully${NC}"
else
    echo -e "\n${RED}✗ Hook failed with exit code $EXIT_CODE${NC}"
fi

exit $EXIT_CODE
