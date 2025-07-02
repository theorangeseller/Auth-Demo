#!/usr/bin/env python3
"""
Azure Web App Startup Script
Ensures all dependencies are installed before starting the Flask application
"""

import subprocess
import sys
import os

def install_dependencies():
    """Install dependencies from requirements.txt"""
    print("=== Installing Python dependencies ===")
    try:
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'])
        print("✅ Dependencies installed successfully")
    except subprocess.CalledProcessError as e:
        print(f"❌ Error installing dependencies: {e}")
        # Try installing critical packages individually
        critical_packages = ['flask>=3.0.0', 'pyjwt>=2.8.0', 'msal>=1.24.0', 'gunicorn>=21.2.0']
        for package in critical_packages:
            try:
                subprocess.check_call([sys.executable, '-m', 'pip', 'install', package])
                print(f"✅ Installed {package}")
            except Exception as pkg_error:
                print(f"❌ Failed to install {package}: {pkg_error}")

def verify_imports():
    """Verify that critical imports work"""
    print("=== Verifying critical imports ===")
    try:
        import jwt
        print("✅ JWT import successful")
    except ImportError as e:
        print(f"❌ JWT import failed: {e}")
        print("Attempting to install pyjwt...")
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', '--force-reinstall', 'pyjwt>=2.8.0'])
        import jwt
        print("✅ JWT import successful after reinstall")
    
    try:
        import flask
        print("✅ Flask import successful")
    except ImportError as e:
        print(f"❌ Flask import failed: {e}")
        sys.exit(1)

def main():
    """Main startup function"""
    print("=== Azure Web App Python Startup ===")
    print(f"Python version: {sys.version}")
    print(f"Working directory: {os.getcwd()}")
    
    # Install dependencies
    install_dependencies()
    
    # Verify imports
    verify_imports()
    
    # Import and start the Flask application
    print("=== Starting Flask Application ===")
    try:
        from main import app
        print("✅ Main application imported successfully")
        
        # For Azure, we'll let gunicorn handle the actual serving
        # This script just ensures dependencies are ready
        return app
    except Exception as e:
        print(f"❌ Error importing main application: {e}")
        sys.exit(1)

if __name__ == '__main__':
    app = main()
    # If running directly, start the development server
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 8000)), debug=False) 