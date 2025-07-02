#!/usr/bin/env python3
"""
Authentication Demo Application Runner

This script provides an easy way to run the authentication demo application
with proper environment setup and error handling.
"""

import os
import sys
from dotenv import load_dotenv

def check_environment():
    """Check if environment variables are set, but don't require them for demo"""
    required_vars = ['TENANT_ID', 'CLIENT_ID', 'CLIENT_SECRET']
    missing_vars = []
    
    for var in required_vars:
        if not os.getenv(var) or os.getenv(var) == f'your-{var.lower().replace("_", "-")}-here':
            missing_vars.append(var)
    
    if missing_vars:
        print("⚠️  Azure AD configuration not found in environment variables:")
        for var in missing_vars:
            print(f"   - {var}")
        print("\n💡 Don't worry! You can configure these settings in the web interface.")
        print("🌐 The demo app will start and you can enter your Azure AD details there.")
        return False
    else:
        print("✅ Azure AD configuration found in environment")
        return True

def main():
    """Main application runner"""
    print("🚀 Starting Authentication Demo Application...")
    
    # Load environment variables
    if os.path.exists('.env'):
        load_dotenv()
        print("✅ Loaded environment variables from .env file")
    else:
        print("⚠️  No .env file found. Using system environment variables.")
    
    # Check environment configuration (but don't exit if missing)
    env_configured = check_environment()
    
    try:
        # Import and run the Flask app
        from main import app
        
        if env_configured:
            print("🔐 Azure AD pre-configured - ready for authentication flows")
        else:
            print("🔧 Azure AD configuration needed - use the web interface to set up")
        
        print("🌐 Starting web server at http://localhost:3000")
        print("📖 Visit the URL above to access the authentication demo")
        print("🛑 Press Ctrl+C to stop the server")
        print("-" * 50)
        
        app.run(
            debug=os.getenv('FLASK_DEBUG', 'True').lower() == 'true',
            host='0.0.0.0',
            port=int(os.getenv('PORT', 3000))
        )
        
    except ImportError as e:
        print(f"❌ Failed to import application: {e}")
        print("💡 Make sure all dependencies are installed: uv sync")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n👋 Application stopped by user")
    except Exception as e:
        print(f"❌ Error starting application: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main() 