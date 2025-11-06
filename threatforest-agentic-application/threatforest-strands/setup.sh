#!/bin/bash
# ThreatForest Setup Script

echo "🚀 Setting up ThreatForest..."

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "📦 Creating Python virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "📦 Activating virtual environment..."
source venv/bin/activate

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
echo "Note: The virtual environment will be activated automatically"
