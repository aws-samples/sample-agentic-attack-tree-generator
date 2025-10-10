#!/bin/bash
# ThreatForest Setup Script

echo "🚀 Setting up ThreatForest..."

# Install Python dependencies
echo "📦 Installing Python dependencies..."
pip install -r requirements.txt

# Build React UI
echo "📦 Building React UI..."
cd ui
npm install
npm run build:cli
cd ..

echo "✅ Setup complete!"
echo ""
echo "Run ThreatForest with: python threatforest.py"
