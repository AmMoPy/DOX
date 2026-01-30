#!/bin/bash
# DOX - Setup Wrapper Script

echo "🤖 DOX - Basic Setup"
echo "===================="

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not found. Please install Python 3.10+"
    exit 1
fi

# Run the complete setup
cd "$(dirname "$0")"
python3 setup.py

exit $?