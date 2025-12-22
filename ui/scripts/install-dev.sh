#!/bin/bash
#
# Development environment setup for MS SSO OpenConnect UI
#
# This script sets up a development environment with all required
# dependencies installed in a virtual environment.
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$SCRIPT_DIR/.."
VENV_DIR="$PROJECT_DIR/.venv"

echo "=== MS SSO OpenConnect UI - Development Setup ==="
echo ""

# Check Python version
PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo "Python version: $PYTHON_VERSION"

if [[ "$PYTHON_VERSION" < "3.10" ]]; then
    echo "Error: Python 3.10 or later is required"
    exit 1
fi

# Create virtual environment if it doesn't exist
if [ ! -d "$VENV_DIR" ]; then
    echo "Creating virtual environment..."
    python3 -m venv "$VENV_DIR"
fi

# Activate virtual environment
source "$VENV_DIR/bin/activate"

# Upgrade pip
echo "Upgrading pip..."
pip install --upgrade pip wheel

# Install dependencies
echo "Installing dependencies..."
pip install -r "$PROJECT_DIR/requirements.txt"

# Install development dependencies
echo "Installing development dependencies..."
pip install pytest pytest-qt black isort mypy

# Install the package in editable mode
echo "Installing package in editable mode..."
pip install -e "$PROJECT_DIR"

# Install Playwright browsers
echo ""
echo "Installing Playwright Chromium browser..."
playwright install chromium

echo ""
echo "=== Setup Complete ==="
echo ""
echo "To activate the environment:"
echo "  source $VENV_DIR/bin/activate"
echo ""
echo "To run the application:"
echo "  python -m vpn_ui"
echo ""
echo "To run tests:"
echo "  pytest"
echo ""
echo "To format code:"
echo "  black src/"
echo "  isort src/"
