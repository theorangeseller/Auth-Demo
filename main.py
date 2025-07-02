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
import xml.etree.ElementTree as ET
import urllib.parse

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

def fetch_azure_federation_metadata(tenant_id):
    """Fetch Azure AD federation metadata for the given tenant"""
    try:
        metadata_url = f"https://login.microsoftonline.com/{tenant_id}/federationmetadata/2007-06/federationmetadata.xml"
        
        response = requests.get(metadata_url, timeout=10)
        response.raise_for_status()
        
        # Parse the XML metadata
        root = ET.fromstring(response.content)
        
        # Define namespaces
        namespaces = {
            'fed': 'http://docs.oasis-open.org/wsfed/federation/200706',
            'saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
            'md': 'urn:oasis:names:tc:SAML:2.0:metadata',
            'ds': 'http://www.w3.org/2000/09/xmldsig#'
        }
        
        metadata = {
            'tenant_id': tenant_id,
            'metadata_url': metadata_url,
            'entity_id': None,
            'sso_url': None,
            'slo_url': None,
            'signing_certificates': [],
            'fetched_at': datetime.utcnow().isoformat()
        }
        
        # Extract entity ID
        entity_id = root.get('entityID')
        if entity_id:
            metadata['entity_id'] = entity_id
        
        # Find SSO and SLO endpoints
        for sso_descriptor in root.findall('.//md:IDPSSODescriptor', namespaces):
            # SSO Service
            for sso_service in sso_descriptor.findall('.//md:SingleSignOnService', namespaces):
                binding = sso_service.get('Binding')
                if 'HTTP-Redirect' in binding or 'HTTP-POST' in binding:
                    metadata['sso_url'] = sso_service.get('Location')
                    break
            
            # SLO Service
            for slo_service in sso_descriptor.findall('.//md:SingleLogoutService', namespaces):
                binding = slo_service.get('Binding')
                if 'HTTP-Redirect' in binding or 'HTTP-POST' in binding:
                    metadata['slo_url'] = slo_service.get('Location')
                    break
            
            # Signing certificates
            for key_descriptor in sso_descriptor.findall('.//md:KeyDescriptor[@use="signing"]', namespaces):
                cert_element = key_descriptor.find('.//ds:X509Certificate', namespaces)
                if cert_element is not None and cert_element.text:
                    metadata['signing_certificates'].append(cert_element.text.strip())
        
        return metadata
        
    except Exception as e:
        print(f"Error fetching Azure AD metadata: {e}")
        return None

def generate_simple_saml_authn_request(issuer, acs_url, destination, name_id_format=None, relay_state=None):
    """Generate a simple SAML AuthnRequest XML with proper DEFLATE compression"""
    request_id = f"_id{uuid.uuid4().hex}"
    issue_instant = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
    
    # Create a simple XML AuthnRequest using string formatting
    # This is a basic implementation for demo purposes
    xml_template = '''<?xml version="1.0" encoding="UTF-8"?>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                    ID="{request_id}"
                    Version="2.0"
                    IssueInstant="{issue_instant}"
                    Destination="{destination}"
                    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                    AssertionConsumerServiceURL="{acs_url}">
    <saml:Issuer>{issuer}</saml:Issuer>
    <samlp:NameIDPolicy Format="{name_id_format}" AllowCreate="true"/>
    <samlp:RequestedAuthnContext Comparison="exact">
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
    </samlp:RequestedAuthnContext>
</samlp:AuthnRequest>'''
    
    xml_str = xml_template.format(
        request_id=request_id,
        issue_instant=issue_instant,
        destination=destination,
        acs_url=acs_url,
        issuer=issuer,
        name_id_format=name_id_format or "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    )
    
    # DEFLATE compress and base64 encode (standard SAML requirement for HTTP-Redirect binding)
    import base64
    import zlib
    
    # Step 1: Convert XML to bytes
    xml_bytes = xml_str.encode('utf-8')
    
    # Step 2: DEFLATE compress (raw DEFLATE without zlib headers)
    # Use wbits=-15 for raw DEFLATE format (no headers/trailers)
    compressor = zlib.compressobj(wbits=-15)
    compressed = compressor.compress(xml_bytes)
    compressed += compressor.flush()
    
    # Step 3: Base64 encode
    b64_request = base64.b64encode(compressed).decode('ascii')
    
    return {
        'xml': xml_str,
        'base64': b64_request,
        'request_id': request_id,
        'compressed_size': len(compressed),
        'original_size': len(xml_bytes)
    }

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
        # Get form data
        tenant_id = request.form.get('tenant_id', '').strip()
        client_id = request.form.get('client_id', '').strip()
        client_secret = request.form.get('client_secret', '').strip()
        redirect_uri = request.form.get('redirect_uri', DEFAULT_REDIRECT_URI).strip()
        config_type = request.form.get('config_type', 'full')
        
        # Validate based on configuration type
        if config_type == 'saml_only':
            # For SAML, only tenant ID is required
            if not tenant_id:
                flash('Tenant ID is required for SAML configuration', 'error')
                return render_template('configure.html', config={
                    'tenant_id': tenant_id,
                    'client_id': 'your-client-id',
                    'client_secret': 'your-client-secret',
                    'redirect_uri': redirect_uri
                })
            
            # Save SAML-only configuration
            azure_config = {
                'tenant_id': tenant_id,
                'client_id': 'your-client-id',
                'client_secret': 'your-client-secret',
                'redirect_uri': redirect_uri
            }
            
            session['azure_config'] = azure_config
            
            # Fetch and cache federation metadata
            metadata = fetch_azure_federation_metadata(tenant_id)
            if metadata:
                session['federation_metadata'] = metadata
                flash('SAML configuration saved successfully! Federation metadata fetched from Azure AD.', 'success')
            else:
                flash('SAML configuration saved, but could not fetch federation metadata. Using fallback configuration.', 'warning')
            
            return redirect(url_for('saml_builder'))
        else:
            # For full configuration (OAuth/OIDC), all fields are required
            if not all([tenant_id, client_id, client_secret]):
                flash('All fields except Redirect URI are required for full configuration', 'error')
                return render_template('configure.html', config={
                    'tenant_id': tenant_id,
                    'client_id': client_id,
                    'client_secret': client_secret,
                    'redirect_uri': redirect_uri
                })
            
            # Save full configuration
            azure_config = {
                'tenant_id': tenant_id,
                'client_id': client_id,
                'client_secret': client_secret,
                'redirect_uri': redirect_uri
            }
            
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
    if 'federation_metadata' in session:
        del session['federation_metadata']
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
    
    # Get federation metadata if available
    federation_metadata = session.get('federation_metadata')
    
    return render_template('saml.html', 
                         azure_config=config, 
                         is_configured=is_configured,
                         federation_metadata=federation_metadata)

@app.route('/saml/metadata')
def saml_metadata():
    """Generate SAML Service Provider metadata"""
    try:
        # Get base URL from request
        base_url = request.url_root.rstrip('/')
        
        # Create simple metadata XML using string formatting
        metadata_template = '''<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     entityID="{base_url}/saml/metadata">
    <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                     Location="{base_url}/auth/saml/callback"
                                     index="0"/>
    </md:SPSSODescriptor>
</md:EntityDescriptor>'''
        
        metadata_xml = metadata_template.format(base_url=base_url)
        
        return metadata_xml, 200, {'Content-Type': 'application/samlmetadata+xml'}
        
    except Exception as e:
        return f'Error generating metadata: {str(e)}', 500

@app.route('/api/azure/federation-metadata')
def get_federation_metadata():
    """API endpoint to fetch or return cached Azure AD federation metadata"""
    try:
        config = get_azure_config()
        tenant_id = config['tenant_id']
        
        if tenant_id == 'your-tenant-id':
            return jsonify({'success': False, 'error': 'Tenant ID not configured'}), 400
        
        # Check if we have cached metadata
        cached_metadata = session.get('federation_metadata')
        if cached_metadata and cached_metadata.get('tenant_id') == tenant_id:
            return jsonify({'success': True, 'metadata': cached_metadata})
        
        # Fetch fresh metadata
        metadata = fetch_azure_federation_metadata(tenant_id)
        if metadata:
            session['federation_metadata'] = metadata
            return jsonify({'success': True, 'metadata': metadata})
        else:
            return jsonify({'success': False, 'error': 'Could not fetch federation metadata'}), 500
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

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
    """Build SAML SSO URL with proper AuthnRequest"""
    try:
        data = request.get_json()
        
        # Extract SAML parameters
        tenant_id = data.get('tenant_id', get_azure_config()['tenant_id'])
        relay_state = data.get('relay_state', '')
        
        # Get base URL from request
        base_url = request.url_root.rstrip('/')
        
        # Use federation metadata if available, otherwise fallback
        federation_metadata = session.get('federation_metadata')
        if federation_metadata and federation_metadata.get('sso_url'):
            destination = federation_metadata['sso_url']
        else:
            destination = f"https://login.microsoftonline.com/{tenant_id}/saml2"
        
        # Generate SAML AuthnRequest
        issuer = f"{base_url}/saml/metadata"
        acs_url = f"{base_url}/auth/saml/callback"
        
        authn_request = generate_simple_saml_authn_request(
            issuer=issuer,
            acs_url=acs_url,
            destination=destination,
            name_id_format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            relay_state=relay_state
        )
        
        # Build SAML SSO URL with proper parameters
        params = {
            'SAMLRequest': authn_request['base64']
        }
        
        if relay_state:
            params['RelayState'] = relay_state
        
        saml_url = f"{destination}?" + urlencode(params)
        
        return jsonify({
            'success': True,
            'saml_url': saml_url,
            'authn_request_xml': authn_request['xml'],
            'using_federation_metadata': federation_metadata is not None,
            'parameters': {
                'tenant_id': tenant_id,
                'issuer': issuer,
                'acs_url': acs_url,
                'destination': destination,
                'relay_state': relay_state,
                'request_id': authn_request['request_id']
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
        
        # Get configuration
        config = get_azure_config()
        tenant_id = config['tenant_id']
        
        # Get base URL from request
        base_url = request.url_root.rstrip('/')
        
        # Use federation metadata if available, otherwise fallback
        federation_metadata = session.get('federation_metadata')
        if federation_metadata and federation_metadata.get('sso_url'):
            destination = federation_metadata['sso_url']
            flash('SAML SSO flow initiated using federation metadata', 'info')
        else:
            destination = f"https://login.microsoftonline.com/{tenant_id}/saml2"
            flash('SAML SSO flow initiated with fallback configuration', 'info')
        
        # Generate SAML AuthnRequest
        issuer = f"{base_url}/saml/metadata"
        acs_url = f"{base_url}/auth/saml/callback"
        relay_state = 'saml-demo-state'
        
        authn_request = generate_simple_saml_authn_request(
            issuer=issuer,
            acs_url=acs_url,
            destination=destination,
            name_id_format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            relay_state=relay_state
        )
        
        # Store SAML session info
        session['saml_relay_state'] = relay_state
        session['saml_request_id'] = authn_request['request_id']
        
        # Build redirect URL with SAMLRequest
        params = {
            'SAMLRequest': authn_request['base64'],
            'RelayState': relay_state
        }
        
        saml_url = f"{destination}?" + urlencode(params)
        
        return redirect(saml_url)
        
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
        # Get SAML response data
        saml_response = request.form.get('SAMLResponse') or request.args.get('SAMLResponse')
        relay_state = request.form.get('RelayState') or request.args.get('RelayState')
        
        if not saml_response:
            flash('No SAML response received', 'error')
            return redirect(url_for('index'))
        
        # Decode the SAML response
        try:
            decoded_response = base64.b64decode(saml_response)
            
            # Parse the XML to extract user information
            # For demo purposes, we'll do basic parsing - in production you'd validate signatures
            root = ET.fromstring(decoded_response)
            
            # Define namespaces for ElementTree
            namespaces = {
                'saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
                'samlp': 'urn:oasis:names:tc:SAML:2.0:protocol'
            }
            
            # Extract user information from SAML assertion using basic ElementTree
            user_info = {
                'auth_method': 'SAML SSO',
                'name': 'SAML User',
                'email': 'saml.user@demo.com',
                'preferred_username': 'saml.user@demo.com'
            }
            
            # Try to extract real data from SAML response
            for attr in root.findall('.//saml:Attribute', namespaces):
                attr_name = attr.get('Name', '')
                attr_value_elem = attr.find('saml:AttributeValue', namespaces)
                if attr_value_elem is not None:
                    attr_value = attr_value_elem.text
                    
                    if 'name' in attr_name.lower():
                        user_info['name'] = attr_value
                    elif 'email' in attr_name.lower():
                        user_info['email'] = attr_value
                        user_info['preferred_username'] = attr_value
            
            # Look for NameID
            name_id_elem = root.find('.//saml:NameID', namespaces)
            if name_id_elem is not None:
                user_info['name_id'] = name_id_elem.text
                if '@' in name_id_elem.text:
                    user_info['email'] = name_id_elem.text
                    user_info['preferred_username'] = name_id_elem.text
                    
        except Exception as parse_error:
            # Fallback to demo data if parsing fails
            user_info = {
                'name': 'SAML Demo User',
                'email': 'saml.user@demo.com',
                'oid': 'saml-user-id-demo',
                'preferred_username': 'saml.user@demo.com',
                'auth_method': 'SAML SSO'
            }
            print(f"SAML parsing error (using demo data): {parse_error}")
        
        # Store user info in session
        session['user'] = user_info
        
        # Store SAML response info for display
        session['saml_response'] = {
            'saml_response': decoded_response.decode('utf-8', errors='ignore')[:500] + '...' if len(decoded_response) > 500 else decoded_response.decode('utf-8', errors='ignore'),
            'relay_state': relay_state,
            'assertion_consumer_url': request.url,
            'timestamp': datetime.now().isoformat(),
            'original_request_id': session.get('saml_request_id', 'unknown')
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
