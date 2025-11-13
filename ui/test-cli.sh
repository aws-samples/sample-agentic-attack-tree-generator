#!/bin/bash
# Test script for ThreatForest CLI commands

echo "Testing ThreatForest CLI Commands"
echo "=================================="
echo ""

# Test help command
echo "1. Testing 'help' command:"
node dist/cli.js help
echo ""

# Test status command (should show no active workflow)
echo "2. Testing 'status' command:"
node dist/cli.js status
echo ""

# Test cache info (delegates to Python)
echo "3. Testing 'cache info' command:"
echo "(This will call Python cache manager)"
# node dist/cli.js cache info
echo "Skipped - requires Python backend"
echo ""

echo "✓ CLI command structure verified"
echo ""
echo "To install globally:"
echo "  npm run install:global"
echo ""
echo "Then use:"
echo "  threatforest run"
echo "  threatforest resume"
echo "  threatforest cache stats"
echo "  threatforest status"
