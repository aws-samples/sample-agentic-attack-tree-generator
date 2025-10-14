#!/bin/bash
# comprehensive_e2e_test.sh
# End-to-end test suite for ThreatForest improvements validation

set -e

echo "=========================================="
echo "ThreatForest End-to-End Test Suite"
echo "=========================================="
echo "Started: $(date)"
echo ""

# Activate virtual environment
VENV_PATH="../venv"
if [ -d "$VENV_PATH" ]; then
    echo "Activating virtual environment..."
    source "$VENV_PATH/bin/activate"
    echo "✅ Virtual environment activated"
else
    echo "❌ Virtual environment not found at $VENV_PATH"
    exit 1
fi

# Configuration
PROFILE="dicorteg+zetaworkload-test-Admin"
TEST_DIR="test_outputs"
BASELINE_DIR="baseline_outputs"

# Create directories
mkdir -p "$TEST_DIR" "$BASELINE_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counter
TESTS_PASSED=0
TESTS_FAILED=0

# Function to log test result
log_test() {
    if [ $1 -eq 0 ]; then
        echo -e "${GREEN}✅ PASS${NC}: $2"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo -e "${RED}❌ FAIL${NC}: $2"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

# Function to log warning
log_warning() {
    echo -e "${YELLOW}⚠️  WARNING${NC}: $1"
}

# Verify AWS profile exists
echo "Verifying AWS profile..."
if aws configure list-profiles | grep -q "$PROFILE"; then
    log_test 0 "AWS profile '$PROFILE' exists"
else
    log_test 1 "AWS profile '$PROFILE' not found"
    echo "Please configure the profile: aws configure --profile $PROFILE"
    exit 1
fi

echo "DEBUG: After profile check, continuing to Test 1..."

# Test 1: Simple Threat Model (hcls-example)
echo ""
echo "=========================================="
echo "Test 1: Simple Threat Model (hcls-example)"
echo "=========================================="

PROJECT_PATH="/Users/dicorteg/Documents/ThreatForest/ThreatForest-internal/threatforest-agentic-application/examples/hcls-example"

if [ ! -d "$PROJECT_PATH" ]; then
    log_test 1 "Test project not found: $PROJECT_PATH"
    exit 1
fi

echo "Running workflow..."
python3 ../threatforest.py \
  --project "$PROJECT_PATH" \
  --aws-profile "$PROFILE" \
  --bedrock-model "us.anthropic.claude-sonnet-4-20250514-v1:0" \
  2>&1 | tee "$TEST_DIR/hcls_test.log"

EXIT_CODE=${PIPESTATUS[0]}
log_test $EXIT_CODE "Workflow execution completed"

# Check for errors in log
echo "Analyzing logs..."
if grep -i "error\|exception\|failed" "$TEST_DIR/hcls_test.log" | grep -v "No errors" | grep -v "0 errors" > "$TEST_DIR/hcls_errors.txt"; then
    log_test 1 "Errors found in execution"
    echo "Error details:"
    cat "$TEST_DIR/hcls_errors.txt"
else
    log_test 0 "No errors in execution"
    rm -f "$TEST_DIR/hcls_errors.txt"
fi

# Verify outputs exist
echo "Verifying outputs..."
REQUIRED_FILES=(
    "output/threatforest_analysis_report.md"
    "output/json_export.json"
)

for file in "${REQUIRED_FILES[@]}"; do
    if [ -e "$file" ]; then
        log_test 0 "Output file exists: $file"
    else
        log_test 1 "Output file missing: $file"
    fi
done

# Check for attack trees directory
if [ -d "output/attack_trees" ]; then
    TREE_COUNT=$(find output/attack_trees -name "*.md" -type f | wc -l)
    if [ $TREE_COUNT -gt 0 ]; then
        log_test 0 "Attack trees generated: $TREE_COUNT files"
    else
        log_test 1 "No attack tree files found"
    fi
else
    log_test 1 "Attack trees directory not created"
fi

# Save outputs for comparison
cp -r output "$TEST_DIR/hcls_output" 2>/dev/null || true

# Test 2: ThreatComposer (genai-chatbot)
echo ""
echo "=========================================="
echo "Test 2: ThreatComposer (genai-chatbot)"
echo "=========================================="

PROJECT_PATH="/Users/dicorteg/Documents/ThreatForest/ThreatForest-internal/threatforest-agentic-application/examples/genai-chatbot"

if [ ! -d "$PROJECT_PATH" ]; then
    log_test 1 "Test project not found: $PROJECT_PATH"
    exit 1
fi

# Clean previous output
rm -rf output

echo "Running workflow..."
python3 ../threatforest.py \
  --project "$PROJECT_PATH" \
  --aws-profile "$PROFILE" \
  --bedrock-model "us.anthropic.claude-sonnet-4-20250514-v1:0" \
  2>&1 | tee "$TEST_DIR/genai_test.log"

EXIT_CODE=${PIPESTATUS[0]}
log_test $EXIT_CODE "Workflow execution completed"

# Check for errors in log
echo "Analyzing logs..."
if grep -i "error\|exception\|failed" "$TEST_DIR/genai_test.log" | grep -v "No errors" | grep -v "0 errors" > "$TEST_DIR/genai_errors.txt"; then
    log_test 1 "Errors found in execution"
    echo "Error details:"
    cat "$TEST_DIR/genai_errors.txt"
else
    log_test 0 "No errors in execution"
    rm -f "$TEST_DIR/genai_errors.txt"
fi

# Verify ThreatComposer-specific parsing
echo "Verifying ThreatComposer parsing..."
if grep -q "ThreatComposer\|\.tc\.json" "$TEST_DIR/genai_test.log"; then
    log_test 0 "ThreatComposer format detected"
else
    log_warning "ThreatComposer format not explicitly mentioned in logs"
fi

# Check for structured fields in output
if [ -f "output/json_export.json" ]; then
    if grep -q "threatSource\|prerequisites\|threatAction" "output/json_export.json"; then
        log_test 0 "Structured threat fields present in JSON export"
    else
        log_test 1 "Structured threat fields missing from JSON export"
    fi
fi

# Save outputs for comparison
cp -r output "$TEST_DIR/genai_output" 2>/dev/null || true

# Syntax Validation
echo ""
echo "=========================================="
echo "Syntax Validation"
echo "=========================================="

echo "Checking Python syntax for all source files..."
SYNTAX_ERRORS=0
while IFS= read -r file; do
    if ! python3 -m py_compile "$file" 2>"$TEST_DIR/syntax_error_temp.log"; then
        echo "Syntax error in: $file"
        cat "$TEST_DIR/syntax_error_temp.log"
        ((SYNTAX_ERRORS++))
    fi
done < <(find src/modules -name "*.py" -type f)

if [ $SYNTAX_ERRORS -eq 0 ]; then
    log_test 0 "No syntax errors in source files"
else
    log_test 1 "Found $SYNTAX_ERRORS files with syntax errors"
fi
rm -f "$TEST_DIR/syntax_error_temp.log"

# Log Analysis
echo ""
echo "=========================================="
echo "Log Analysis"
echo "=========================================="

echo "Checking for common issues..."

# Check for deprecation warnings
if grep -i "deprecat" "$TEST_DIR"/*.log > "$TEST_DIR/deprecation_warnings.txt" 2>/dev/null; then
    log_warning "Deprecation warnings found"
    head -5 "$TEST_DIR/deprecation_warnings.txt"
else
    log_test 0 "No deprecation warnings"
fi

# Check for Pydantic warnings
if grep -i "pydantic" "$TEST_DIR"/*.log | grep -i "warn" > "$TEST_DIR/pydantic_warnings.txt" 2>/dev/null; then
    log_warning "Pydantic warnings found"
    head -5 "$TEST_DIR/pydantic_warnings.txt"
else
    log_test 0 "No Pydantic warnings"
fi

# Check for boto3/botocore errors
if grep -i "boto3\|botocore" "$TEST_DIR"/*.log | grep -i "error" > "$TEST_DIR/boto_errors.txt" 2>/dev/null; then
    log_test 1 "Boto3/Botocore errors found"
    head -10 "$TEST_DIR/boto_errors.txt"
else
    log_test 0 "No Boto3/Botocore errors"
fi

# Check for import errors
if grep -i "importerror\|modulenotfounderror" "$TEST_DIR"/*.log > "$TEST_DIR/import_errors.txt" 2>/dev/null; then
    log_test 1 "Import errors found"
    cat "$TEST_DIR/import_errors.txt"
else
    log_test 0 "No import errors"
fi

# Performance Metrics
echo ""
echo "=========================================="
echo "Performance Metrics"
echo "=========================================="

# Extract execution times from logs
HCLS_TIME=$(grep -i "workflow complete\|total.*time\|duration" "$TEST_DIR/hcls_test.log" | tail -1 || echo "Not found")
GENAI_TIME=$(grep -i "workflow complete\|total.*time\|duration" "$TEST_DIR/genai_test.log" | tail -1 || echo "Not found")

echo "HCLS Example: $HCLS_TIME"
echo "GenAI Chatbot: $GENAI_TIME"

# Summary
echo ""
echo "=========================================="
echo "Test Summary"
echo "=========================================="
echo -e "${GREEN}Tests Passed: $TESTS_PASSED${NC}"
echo -e "${RED}Tests Failed: $TESTS_FAILED${NC}"
echo ""
echo "Test outputs saved to: $TEST_DIR"
echo "Logs available:"
echo "  - $TEST_DIR/hcls_test.log"
echo "  - $TEST_DIR/genai_test.log"
echo ""
echo "Completed: $(date)"
echo "=========================================="

# Exit with failure if any tests failed
if [ $TESTS_FAILED -gt 0 ]; then
    exit 1
fi

exit 0
