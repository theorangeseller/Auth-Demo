#!/bin/bash

echo "=== Azure Web App Startup Script ==="
echo "Working directory: $(pwd)"
echo "Python version: $(python --version)"
echo "Pip version: $(pip --version)"

# Install dependencies if they're not already installed
echo "=== Installing Python dependencies ==="
pip install -r requirements.txt

# Verify jwt package is installed
echo "=== Verifying jwt package installation ==="
python -c "import jwt; print('JWT package successfully imported')" || {
    echo "ERROR: JWT package not found after installation"
    echo "Trying alternative installation..."
    pip install --force-reinstall pyjwt>=2.8.0
    python -c "import jwt; print('JWT package successfully imported after reinstall')"
}

# List installed packages for debugging
echo "=== Installed packages ==="
pip list | grep -E "(jwt|flask|msal)"

# Start the application
echo "=== Starting Gunicorn ==="
exec gunicorn main:app --bind=0.0.0.0:8000 --timeout 600 --workers 1 --access-logfile - --error-logfile - 