import os
import json
import uuid
from datetime import datetime, timedelta
from urllib.parse import urlencode, urlparse, parse_qs
import base64
import jwt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption

from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from flask_session import Session
import msal
import requests
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'your-secret-key-change-in-production')

# Configure session
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False
Session(app)

# Default Azure AD Configuration (can be overridden by session or environment)
DEFAULT_REDIRECT_URI = 'http://localhost:3000/auth/callback'
DEFAULT_SCOPE = ["https://graph.microsoft.com/User.Read"]

def get_azure_config():
    """Get Azure AD configuration from session or environment variables"""
    # Check session first, then environment variables, then defaults
    config = {
        'tenant_id': session.get('azure_config', {}).get('tenant_id') or 
                    os.getenv('TENANT_ID') or 'your-tenant-id',
        'client_id': session.get('azure_config', {}).get('client_id') or 
                    os.getenv('CLIENT_ID') or 'your-client-id',
        'client_secret': session.get('azure_config', {}).get('client_secret') or 
                        os.getenv('CLIENT_SECRET') or 'your-client-secret',
        'redirect_uri': session.get('azure_config', {}).get('redirect_uri') or 
                       os.getenv('REDIRECT_URI') or DEFAULT_REDIRECT_URI
    }
    return config

def is_azure_configured():
    """Check if Azure AD is properly configured"""
    config = get_azure_config()
    return (config['tenant_id'] != 'your-tenant-id' and 
            config['client_id'] != 'your-client-id' and 
            config['client_secret'] != 'your-client-secret')

def is_saml_configured():
    """Check if SAML is configured (only needs tenant ID)"""
    config = get_azure_config()
    return config['tenant_id'] != 'your-tenant-id'

def get_authority():
    """Get authority URL based on current configuration"""
    config = get_azure_config()
    return f"https://login.microsoftonline.com/{config['tenant_id']}"

def _build_msal_app(cache=None, authority=None):
    """Build MSAL application using current configuration"""
    config = get_azure_config()
    return msal.ConfidentialClientApplication(
        config['client_id'], 
        authority=authority or get_authority(),
        client_credential=config['client_secret'], 
        token_cache=cache)

def _build_auth_code_flow(authority=None, scopes=None):
    """Build authorization code flow using current configuration"""
    config = get_azure_config()
    return _build_msal_app(authority=authority).initiate_auth_code_flow(
        scopes or DEFAULT_SCOPE,
        redirect_uri=config['redirect_uri'])

@app.route('/')
def index():
    """Main page with authentication method selection"""
    config = get_azure_config()
    is_configured = is_azure_configured()
    return render_template('index.html', azure_config=config, is_configured=is_configured)

@app.route('/configure', methods=['GET', 'POST'])
def configure():
    """Configure Azure AD settings"""
    if request.method == 'POST':
        # Save configuration to session
        azure_config = {
            'tenant_id': request.form.get('tenant_id', '').strip(),
            'client_id': request.form.get('client_id', '').strip(),
            'client_secret': request.form.get('client_secret', '').strip(),
            'redirect_uri': request.form.get('redirect_uri', DEFAULT_REDIRECT_URI).strip()
        }
        
        # Validate required fields
        if not all([azure_config['tenant_id'], azure_config['client_id'], azure_config['client_secret']]):
            flash('All fields except Redirect URI are required', 'error')
            return render_template('configure.html', config=azure_config)
        
        session['azure_config'] = azure_config
        flash('Azure AD configuration saved successfully!', 'success')
        return redirect(url_for('index'))
    
    # GET request - show configuration form
    current_config = get_azure_config()
    return render_template('configure.html', config=current_config)

@app.route('/api/config/clear', methods=['POST'])
def clear_config():
    """Clear Azure AD configuration from session"""
    if 'azure_config' in session:
        del session['azure_config']
    return jsonify({'success': True, 'message': 'Configuration cleared'})

@app.route('/oauth2')
def oauth2_builder():
    """OAuth 2.0 URL Builder page"""
    config = get_azure_config()
    is_configured = is_azure_configured()
    return render_template('oauth2.html', azure_config=config, is_configured=is_configured)

@app.route('/oidc')
def oidc_builder():
    """OpenID Connect URL Builder page"""
    config = get_azure_config()
    is_configured = is_azure_configured()
    return render_template('oidc.html', azure_config=config, is_configured=is_configured)

@app.route('/saml')
def saml_builder():
    """SAML SSO Configuration page"""
    config = get_azure_config()
    is_configured = is_saml_configured()  # For SAML, only check if tenant ID is configured
    return render_template('saml.html', azure_config=config, is_configured=is_configured)

@app.route('/api/oauth2/build-url', methods=['POST'])
def build_oauth2_url():
    """Build OAuth 2.0 authorization URL"""
    try:
        data = request.get_json()
        
        # Extract parameters from request
        tenant_id = data.get('tenant_id', get_azure_config()['tenant_id'])
        client_id = data.get('client_id', get_azure_config()['client_id'])
        redirect_uri = data.get('redirect_uri', get_azure_config()['redirect_uri'])
        scopes = data.get('scopes', 'openid profile email').split()
        response_type = data.get('response_type', 'code')
        response_mode = data.get('response_mode', 'query')
        state = data.get('state', str(uuid.uuid4()))
        nonce = data.get('nonce', str(uuid.uuid4()))
        prompt = data.get('prompt', '')
        
        # Build authority URL
        authority_base = data.get('authority_base', 'https://login.microsoftonline.com')
        authority = f"{authority_base}/{tenant_id}"
        
        # Build authorization URL
        params = {
            'client_id': client_id,
            'response_type': response_type,
            'redirect_uri': redirect_uri,
            'scope': ' '.join(scopes),
            'state': state,
            'response_mode': response_mode
        }
        
        if nonce:
            params['nonce'] = nonce
        if prompt:
            params['prompt'] = prompt
            
        auth_url = f"{authority}/oauth2/v2.0/authorize?" + urlencode(params)
        
        return jsonify({
            'success': True,
            'auth_url': auth_url,
            'parameters': params
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/oidc/build-url', methods=['POST'])
def build_oidc_url():
    """Build OpenID Connect authorization URL"""
    try:
        data = request.get_json()
        
        # Extract parameters from request
        tenant_id = data.get('tenant_id', get_azure_config()['tenant_id'])
        client_id = data.get('client_id', get_azure_config()['client_id'])
        redirect_uri = data.get('redirect_uri', get_azure_config()['redirect_uri'])
        scopes = data.get('scopes', 'openid profile email').split()
        response_type = data.get('response_type', 'code')
        state = data.get('state', str(uuid.uuid4()))
        nonce = data.get('nonce', str(uuid.uuid4()))
        
        # Build authority URL
        authority_base = data.get('authority_base', 'https://login.microsoftonline.com')
        authority = f"{authority_base}/{tenant_id}"
        
        # Build authorization URL with OIDC specific parameters
        params = {
            'client_id': client_id,
            'response_type': response_type,
            'redirect_uri': redirect_uri,
            'scope': ' '.join(scopes),
            'state': state,
            'nonce': nonce
        }
        
        auth_url = f"{authority}/oauth2/v2.0/authorize?" + urlencode(params)
        
        return jsonify({
            'success': True,
            'auth_url': auth_url,
            'parameters': params
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/saml/build-url', methods=['POST'])
def build_saml_url():
    """Build SAML SSO URL"""
    try:
        data = request.get_json()
        
        # Extract SAML parameters
        tenant_id = data.get('tenant_id', get_azure_config()['tenant_id'])
        app_id = data.get('app_id', get_azure_config()['client_id'])
        relay_state = data.get('relay_state', '')
        
        # Build SAML SSO URL
        saml_url = f"https://login.microsoftonline.com/{tenant_id}/saml2"
        
        params = {
            'SAMLRequest': 'base64_encoded_saml_request_here',
            'RelayState': relay_state
        }
        
        if relay_state:
            saml_url += "?" + urlencode(params)
        
        return jsonify({
            'success': True,
            'saml_url': saml_url,
            'parameters': {
                'tenant_id': tenant_id,
                'app_id': app_id,
                'relay_state': relay_state
            }
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/auth/login/<method>')
def login(method):
    """Initiate authentication flow based on method"""
    if method == 'oauth2':
        return redirect('/oauth2/login')
    elif method == 'oidc':
        return redirect('/oidc/login')
    elif method == 'saml':
        return redirect('/saml/login')
    else:
        flash('Invalid authentication method', 'error')
        return redirect(url_for('index'))

@app.route('/oauth2/login')
def oauth2_login():
    """Initiate OAuth 2.0 login flow"""
    try:
        # Check if Azure AD is configured
        if not is_azure_configured():
            flash('Please configure Azure AD settings before testing authentication flows', 'warning')
            return redirect(url_for('configure'))
        
        # Store authentication method in session
        session['auth_method'] = 'oauth2'
        
        # Build authentication flow
        flow = _build_auth_code_flow(scopes=DEFAULT_SCOPE)
        session['flow'] = flow
        
        return redirect(flow['auth_uri'])
        
    except Exception as e:
        flash(f'OAuth 2.0 login error: {str(e)}', 'error')
        return redirect(url_for('index'))

@app.route('/oidc/login')
def oidc_login():
    """Initiate OpenID Connect login flow"""
    try:
        # Check if Azure AD is configured
        if not is_azure_configured():
            flash('Please configure Azure AD settings before testing authentication flows', 'warning')
            return redirect(url_for('configure'))
        
        # Store authentication method in session
        session['auth_method'] = 'oidc'
        
        # Build authentication flow with OIDC scopes
        oidc_scopes = ["openid", "profile", "email"] + DEFAULT_SCOPE
        flow = _build_auth_code_flow(scopes=oidc_scopes)
        session['flow'] = flow
        
        return redirect(flow['auth_uri'])
        
    except Exception as e:
        flash(f'OpenID Connect login error: {str(e)}', 'error')
        return redirect(url_for('index'))

@app.route('/saml/login')
def saml_login():
    """Initiate SAML SSO login flow"""
    try:
        # For SAML, we only need tenant ID (no client secret required)
        if not is_saml_configured():
            flash('Please configure your Tenant ID for SAML SSO testing', 'warning')
            return redirect(url_for('configure'))
        
        # Store authentication method in session
        session['auth_method'] = 'saml'
        
        # Generate SAML AuthnRequest
        config = get_azure_config()
        tenant_id = config['tenant_id']
        
        # SAML SSO URL for Azure AD
        saml_sso_url = f"https://login.microsoftonline.com/{tenant_id}/saml2"
        
        # For demo purposes, we'll redirect directly to Azure AD SAML endpoint
        # In a real implementation, you'd generate a proper SAML AuthnRequest
        saml_params = {
            'RelayState': 'saml-demo-state'
        }
        
        # Store SAML session info
        session['saml_relay_state'] = saml_params['RelayState']
        
        flash('SAML SSO flow initiated - redirecting to Azure AD SAML endpoint', 'info')
        
        # For demo: redirect to SAML SSO URL (this would normally include a SAMLRequest parameter)
        return redirect(f"{saml_sso_url}?{urlencode(saml_params)}")
        
    except Exception as e:
        flash(f'SAML SSO login error: {str(e)}', 'error')
        return redirect(url_for('index'))

@app.route('/auth/callback')
def auth_callback():
    """Handle authentication callback"""
    try:
        if 'error' in request.args:
            return render_template('error.html', error=request.args.get('error_description', 'Authentication failed'))
        
        if 'flow' not in session:
            flash('Authentication session expired', 'error')
            return redirect(url_for('index'))
        
        # Complete the authentication flow
        result = _build_msal_app().acquire_token_by_auth_code_flow(
            session.get('flow', {}), request.args)
        
        if 'error' in result:
            return render_template('error.html', error=result.get('error_description', 'Token acquisition failed'))
        
        # Store tokens and user info in session
        session['user'] = result.get('id_token_claims')
        session['tokens'] = {
            'access_token': result.get('access_token'),
            'id_token': result.get('id_token'),
            'refresh_token': result.get('refresh_token'),
            'token_type': result.get('token_type', 'Bearer'),
            'expires_in': result.get('expires_in'),
            'scope': result.get('scope')
        }
        
        # Get authentication method from session
        auth_method = session.get('auth_method', 'oauth2')
        
        return redirect(url_for('dashboard', method=auth_method))
        
    except Exception as e:
        return render_template('error.html', error=f'Callback processing error: {str(e)}')

@app.route('/auth/saml/callback', methods=['GET', 'POST'])
def saml_callback():
    """Handle SAML response from Azure AD"""
    try:
        # In a real implementation, you'd validate the SAML response here
        saml_response = request.form.get('SAMLResponse') or request.args.get('SAMLResponse')
        relay_state = request.form.get('RelayState') or request.args.get('RelayState')
        
        if not saml_response:
            flash('No SAML response received', 'error')
            return redirect(url_for('index'))
        
        # For demo purposes, we'll simulate processing the SAML response
        # In reality, you'd parse and validate the XML SAML response
        
        # Simulate user info from SAML assertion
        session['user'] = {
            'name': 'SAML Demo User',
            'email': 'saml.user@demo.com',
            'oid': 'saml-user-id-demo',
            'preferred_username': 'saml.user@demo.com',
            'auth_method': 'SAML SSO'
        }
        
        # Store SAML response info
        session['saml_response'] = {
            'saml_response': saml_response[:100] + '...' if len(saml_response) > 100 else saml_response,
            'relay_state': relay_state,
            'assertion_consumer_url': request.url,
            'timestamp': datetime.now().isoformat()
        }
        
        flash('SAML SSO authentication successful!', 'success')
        return redirect(url_for('dashboard', method='saml'))
        
    except Exception as e:
        return render_template('error.html', error=f'SAML callback processing error: {str(e)}')

@app.route('/dashboard/<method>')
def dashboard(method):
    """Display authentication results dashboard"""
    if 'user' not in session:
        flash('Please authenticate first', 'warning')
        return redirect(url_for('index'))
    
    user_info = session.get('user', {})
    tokens = session.get('tokens', {})
    
    # Decode ID token for display
    id_token_decoded = None
    if tokens.get('id_token'):
        try:
            # Decode without verification for demo purposes
            id_token_decoded = jwt.decode(tokens['id_token'], options={"verify_signature": False})
        except Exception as e:
            id_token_decoded = {'error': f'Failed to decode ID token: {str(e)}'}
    
    return render_template('dashboard.html', 
                         method=method, 
                         user=user_info, 
                         tokens=tokens,
                         id_token_decoded=id_token_decoded)

@app.route('/logout')
def logout():
    """Logout user and clear session"""
    session.clear()
    logout_url = f"{get_authority()}/oauth2/v2.0/logout?post_logout_redirect_uri={request.host_url}"
    return redirect(logout_url)

@app.route('/api/validate-token', methods=['POST'])
def validate_token():
    """Validate and decode JWT token"""
    try:
        data = request.get_json()
        token = data.get('token')
        
        if not token:
            return jsonify({'success': False, 'error': 'No token provided'}), 400
        
        # Decode token without verification for demo purposes
        decoded = jwt.decode(token, options={"verify_signature": False})
        
        return jsonify({
            'success': True,
            'decoded_token': decoded,
            'is_valid': True  # For demo purposes
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=3000)
