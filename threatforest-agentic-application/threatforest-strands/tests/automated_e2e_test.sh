#!/bin/bash
set -e

echo "============================================================"
echo "AUTOMATED E2E TEST - Priority 1 Validation"
echo "============================================================"

# Configuration
BASE_DIR="/Users/dicorteg/Documents/ThreatForest/ThreatForest-internal/threatforest-agentic-application/threatforest-strands"
PROJECT_PATH="/Users/dicorteg/Documents/ThreatForest/ThreatForest-internal/threatforest-agentic-application/examples/hcls-example"
OUTPUT_DIR="$BASE_DIR/tests/test_output"
PROFILE="dicorteg+zetaworkload-test-Admin"
MODEL_ID="us.anthropic.claude-sonnet-4-20250514-v1:0"

echo ""
echo "[CONFIG]"
echo "  Project: $PROJECT_PATH"
echo "  Output: $OUTPUT_DIR"
echo "  Profile: $PROFILE"
echo "  Model: $MODEL_ID"

# Validate project exists
if [ ! -d "$PROJECT_PATH" ]; then
    echo ""
    echo "[ERROR] Project path not found: $PROJECT_PATH"
    exit 1
fi

# Clean output directory
if [ -d "$OUTPUT_DIR" ]; then
    rm -rf "$OUTPUT_DIR"
fi
mkdir -p "$OUTPUT_DIR"

# Activate venv
cd "$BASE_DIR"
source venv/bin/activate

echo ""
echo "[START] Running ThreatForest CLI..."
START_TIME=$(date +%s)

# Use expect to automate CLI wizard
expect << EOF
set timeout 600
spawn python3 -m threatforest run

expect "Enter the path to your project directory:"
send "$PROJECT_PATH\r"

expect "Enter the path to your threat model file"
send "\r"

expect "Enter AWS profile name"
send "$PROFILE\r"

expect "Enter Bedrock model ID"
send "$MODEL_ID\r"

expect "Enter output directory"
send "$OUTPUT_DIR\r"

expect {
    "Workflow completed successfully" {
        puts "\n[SUCCESS] Workflow completed"
    }
    timeout {
        puts "\n[TIMEOUT] Workflow exceeded 10 minutes"
        exit 1
    }
    eof {
        puts "\n[COMPLETE] Process finished"
    }
}
EOF

END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))

echo ""
echo "[COMPLETE] Workflow finished in ${ELAPSED}s"

# Validate output
echo ""
echo "[VALIDATION] Checking output files..."

ISSUES=0
for file in threat_model.json attack_trees.json mitre_mappings.json; do
    filepath="$OUTPUT_DIR/$file"
    if [ ! -f "$filepath" ]; then
        echo "  - Missing: $file"
        ISSUES=$((ISSUES + 1))
    else
        # Check if valid JSON
        if ! python3 -c "import json; json.load(open('$filepath'))" 2>/dev/null; then
            echo "  - Invalid JSON: $file"
            ISSUES=$((ISSUES + 1))
        else
            size=$(stat -f%z "$filepath" 2>/dev/null || stat -c%s "$filepath" 2>/dev/null)
            echo "  ✓ $file: $size bytes"
        fi
    fi
done

if [ $ISSUES -gt 0 ]; then
    echo ""
    echo "[FAILED] $ISSUES validation issues found"
    exit 1
else
    echo ""
    echo "[PASSED] All output files validated successfully"
    exit 0
fi
