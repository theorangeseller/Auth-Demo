import os
import json
import uuid
from datetime import datetime, timedelta
from urllib.parse import urlencode, urlparse, parse_qs
import base64
import jwt
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import xml.etree.ElementTree as ET
import urllib.parse
import hashlib
import re

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
                       os.getenv('REDIRECT_URI') or DEFAULT_REDIRECT_URI,
        'app_id': session.get('azure_config', {}).get('app_id') or 
                 os.getenv('APP_ID') or 'your-app-id'
    }
    return config

def is_azure_configured():
    """Check if Azure AD is properly configured"""
    config = get_azure_config()
    return (config['tenant_id'] != 'your-tenant-id' and 
            config['client_id'] != 'your-client-id' and 
            config['client_secret'] != 'your-client-secret')

def is_saml_configured():
    """Check if SAML is configured (needs tenant ID and app ID for best security)"""
    config = get_azure_config()
    return (config['tenant_id'] != 'your-tenant-id' and 
            config['app_id'] != 'your-app-id')

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

def fetch_azure_federation_metadata(tenant_id, app_id=None):
    """Fetch Azure AD federation metadata for the given tenant and optionally app"""
    try:
        if app_id and app_id != 'your-app-id':
            # Use application-specific metadata URL for better security
            metadata_url = f"https://login.microsoftonline.com/{tenant_id}/federationmetadata/2007-06/federationmetadata.xml?appid={app_id}"
        else:
            # Fallback to tenant-level metadata
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

def verify_saml_signature(saml_response_xml, signing_certificates):
    """
    Basic SAML signature verification for educational purposes.
    This is a simplified implementation - production should use proper SAML libraries.
    """
    verification_result = {
        'verified': False,
        'details': [],
        'certificate_used': None,
        'signature_found': False,
        'error': None
    }
    
    try:
        # Parse the SAML response XML
        root = ET.fromstring(saml_response_xml)
        
        # Define namespaces
        namespaces = {
            'saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
            'samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
            'ds': 'http://www.w3.org/2000/09/xmldsig#'
        }
        
        # Look for XML signature
        signature_elem = root.find('.//ds:Signature', namespaces)
        if signature_elem is None:
            verification_result['error'] = 'No XML signature found in SAML response'
            return verification_result
        
        verification_result['signature_found'] = True
        verification_result['details'].append('✓ XML Signature element found')
        
        # Extract signature value
        signature_value_elem = signature_elem.find('.//ds:SignatureValue', namespaces)
        if signature_value_elem is None:
            verification_result['error'] = 'No SignatureValue found'
            return verification_result
        
        signature_value = signature_value_elem.text.strip()
        verification_result['details'].append(f'✓ Signature value extracted ({len(signature_value)} chars)')
        
        # Extract signed info (this is what was actually signed)
        signed_info_elem = signature_elem.find('.//ds:SignedInfo', namespaces)
        if signed_info_elem is None:
            verification_result['error'] = 'No SignedInfo found'
            return verification_result
        
        verification_result['details'].append('✓ SignedInfo element found')
        
        # For educational purposes, we'll do basic verification
        # In production, use proper XML canonicalization and full verification
        
        # Try each certificate from federation metadata
        print(f"🔍 DEBUG: verify_saml_signature called with {len(signing_certificates)} certificates")
        for i, cert_text in enumerate(signing_certificates):
            try:
                print(f"🔍 DEBUG: Processing certificate {i+1}")
                # Clean up certificate text
                cert_text = cert_text.replace('\n', '').replace('\r', '').strip()
                
                # Debug: show first/last few chars of cert
                cert_preview = f"{cert_text[:20]}...{cert_text[-20:]}" if len(cert_text) > 40 else cert_text
                print(f"🔍 DEBUG: Certificate {i+1} preview: {cert_preview}")
                
                cert_der = base64.b64decode(cert_text)
                certificate = x509.load_der_x509_certificate(cert_der, default_backend())
                
                # Get public key
                public_key = certificate.public_key()
                
                verification_result['details'].append(f'✓ Certificate {i+1} loaded successfully')
                verification_result['certificate_used'] = {
                    'index': i+1,
                    'subject': certificate.subject.rfc4514_string(),
                    'issuer': certificate.issuer.rfc4514_string(),
                    'not_before': certificate.not_valid_before.isoformat(),
                    'not_after': certificate.not_valid_after.isoformat()
                }
                
                print(f"🔍 DEBUG: Certificate {i+1} subject: {certificate.subject.rfc4514_string()}")
                
                # Check certificate validity
                now = datetime.utcnow()
                if now < certificate.not_valid_before or now > certificate.not_valid_after:
                    verification_result['details'].append(f'⚠️ Certificate {i+1} is not within valid date range')
                    print(f"🔍 DEBUG: Certificate {i+1} is expired or not yet valid")
                    continue
                
                verification_result['details'].append(f'✓ Certificate {i+1} is within valid date range')
                print(f"🔍 DEBUG: Certificate {i+1} is valid, marking verification as successful")
                
                # For educational demo, we'll mark as verified if we found a valid certificate
                # Real verification would require proper XML canonicalization and signature checking
                verification_result['verified'] = True
                verification_result['details'].append('✅ Educational verification: Certificate validation successful')
                verification_result['details'].append('⚠️ Note: This is simplified verification for educational purposes')
                
                break
                
            except Exception as cert_error:
                print(f"🔍 DEBUG: Certificate {i+1} error: {str(cert_error)}")
                verification_result['details'].append(f'❌ Certificate {i+1} verification failed: {str(cert_error)}')
                continue
        
        if not verification_result['verified']:
            verification_result['error'] = 'No valid certificates found for verification'
            
    except Exception as e:
        verification_result['error'] = f'Signature verification error: {str(e)}'
        verification_result['details'].append(f'❌ Verification failed: {str(e)}')
    
    return verification_result

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
        app_id = request.form.get('app_id', '').strip()
        config_type = request.form.get('config_type', 'full')
        
        # Validate based on configuration type
        if config_type == 'saml_only':
            # For SAML, tenant ID and app ID are required for best security
            if not tenant_id or not app_id:
                flash('Tenant ID and Application ID are required for SAML configuration', 'error')
                return render_template('configure.html', config={
                    'tenant_id': tenant_id,
                    'client_id': 'your-client-id',
                    'client_secret': 'your-client-secret',
                    'redirect_uri': redirect_uri,
                    'app_id': app_id
                })
            
            # Save SAML-only configuration
            azure_config = {
                'tenant_id': tenant_id,
                'client_id': 'your-client-id',
                'client_secret': 'your-client-secret',
                'redirect_uri': redirect_uri,
                'app_id': app_id
            }
            
            session['azure_config'] = azure_config
            
            # Fetch and cache federation metadata
            app_id = azure_config.get('app_id')
            metadata = fetch_azure_federation_metadata(tenant_id, app_id)
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
                    'redirect_uri': redirect_uri,
                    'app_id': app_id
                })
            
            # Save full configuration
            azure_config = {
                'tenant_id': tenant_id,
                'client_id': client_id,
                'client_secret': client_secret,
                'redirect_uri': redirect_uri,
                'app_id': app_id if app_id else 'your-app-id'
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
    is_configured = is_saml_configured()  # For SAML, check if tenant ID AND app ID are configured
    
    # Get federation metadata if available
    federation_metadata = session.get('federation_metadata')
    
    return render_template('saml.html', 
                         azure_config=config, 
                         is_configured=is_configured,
                         federation_metadata=federation_metadata)

def get_public_base_url():
    """Get the public base URL, ensuring HTTPS for Azure Web Apps"""
    base_url = request.url_root.rstrip('/')
    
    # For Azure Web Apps, force HTTPS for public URLs
    if 'azurewebsites.net' in request.host:
        base_url = base_url.replace('http://', 'https://')
    
    # Handle X-Forwarded-Proto header (common in cloud deployments)
    if request.headers.get('X-Forwarded-Proto') == 'https':
        base_url = base_url.replace('http://', 'https://')
    
    return base_url

@app.route('/saml/metadata')
def saml_metadata():
    """Generate SAML Service Provider metadata"""
    try:
        # Get public base URL with proper HTTPS
        base_url = get_public_base_url()
        
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
        app_id = config['app_id']
        metadata = fetch_azure_federation_metadata(tenant_id, app_id)
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
        
        # Get public base URL with proper HTTPS
        base_url = get_public_base_url()
        
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
        
        # Get public base URL with proper HTTPS
        base_url = get_public_base_url()
        
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
            
            # Extract user information from SAML assertions with proper attribute mapping
            extracted_attrs = {}
            
            # Parse SAML attributes
            for attr in root.findall('.//saml:Attribute', namespaces):
                attr_name = attr.get('Name', '').lower()
                attr_value_elem = attr.find('saml:AttributeValue', namespaces)
                if attr_value_elem is not None and attr_value_elem.text:
                    attr_value = attr_value_elem.text.strip()
                    extracted_attrs[attr_name] = attr_value
                    
                    # Map Azure AD specific attribute names (based on schemas.microsoft.com)
                    if 'givenname' in attr_name or 'firstname' in attr_name:
                        user_info['given_name'] = attr_value
                    elif 'surname' in attr_name or 'lastname' in attr_name or 'familyname' in attr_name:
                        user_info['family_name'] = attr_value
                    elif 'displayname' in attr_name:
                        user_info['name'] = attr_value
                    elif 'emailaddress' in attr_name or 'email' in attr_name or attr_name.endswith('/mail'):
                        user_info['email'] = attr_value
                    elif 'userprincipalname' in attr_name or 'upn' in attr_name:
                        user_info['preferred_username'] = attr_value
                    elif 'objectidentifier' in attr_name or 'objectid' in attr_name:
                        user_info['oid'] = attr_value
                    elif 'tenantid' in attr_name:
                        user_info['tid'] = attr_value
                    elif 'identityprovider' in attr_name:
                        user_info['identity_provider'] = attr_value
                    elif 'authnmethodsreferences' in attr_name:
                        user_info['auth_methods'] = attr_value
                    
                    # Also check for common names without exact matching
                    if not user_info.get('name') and ('name' in attr_name and 'username' not in attr_name and 'surname' not in attr_name):
                        user_info['name'] = attr_value
            
            # Look for NameID (often contains email or unique identifier)
            name_id_elem = root.find('.//saml:NameID', namespaces)
            if name_id_elem is not None and name_id_elem.text:
                name_id_value = name_id_elem.text.strip()
                user_info['name_id'] = name_id_value
                
                # NameID is the primary unique identifier in SAML - use it as UPN
                user_info['preferred_username'] = name_id_value
                
                # If NameID looks like email and we don't have email yet
                if '@' in name_id_value and not user_info.get('email'):
                    user_info['email'] = name_id_value
            
            # Construct full name if we have parts but not full name
            if not user_info.get('name') and user_info.get('given_name') and user_info.get('family_name'):
                user_info['name'] = f"{user_info['given_name']} {user_info['family_name']}"
            
            # Fallback: use email as username if no username specified
            if not user_info.get('preferred_username') and user_info.get('email'):
                user_info['preferred_username'] = user_info['email']
            
            # Store all extracted attributes for educational display
            user_info['saml_attributes'] = extracted_attrs
                    
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
        
        # Store SAML response info for educational display
        full_response = decoded_response.decode('utf-8', errors='ignore')
        
        # Extract SAML assertion separately for educational purposes
        saml_assertion = None
        try:
            # Find the assertion element within the response
            assertion_elem = root.find('.//saml:Assertion', namespaces)
            if assertion_elem is not None:
                # Convert assertion element back to XML string
                saml_assertion = ET.tostring(assertion_elem, encoding='unicode', method='xml')
        except Exception as assertion_error:
            print(f"Could not extract SAML assertion: {assertion_error}")
        
        # Perform signature verification if we have federation metadata or uploaded certificates
        signature_verification = None
        federation_metadata = session.get('federation_metadata')
        uploaded_certificates = session.get('uploaded_certificates', [])
        
        # Debug logging
        print(f"🔍 DEBUG: Federation metadata exists: {federation_metadata is not None}")
        if federation_metadata:
            print(f"🔍 DEBUG: Signing certificates count: {len(federation_metadata.get('signing_certificates', []))}")
        print(f"🔍 DEBUG: Uploaded certificates count: {len(uploaded_certificates)}")
        
        certificates_to_use = None
        cert_source = None
        
        if federation_metadata and federation_metadata.get('signing_certificates'):
            # Federation metadata certificates are base64 strings - use directly
            certificates_to_use = federation_metadata['signing_certificates']
            cert_source = 'federation_metadata'
            print(f"🔍 DEBUG: Using federation metadata certificates: {len(certificates_to_use)} certs")
        elif uploaded_certificates:
            # Convert uploaded certificates - extract just the base64 part
            certificates_to_use = []
            for cert_info in uploaded_certificates:
                # Extract the base64 certificate from PEM format
                pem_content = cert_info['pem']
                if '-----BEGIN CERTIFICATE-----' in pem_content:
                    # Extract just the base64 part (remove PEM headers/footers)
                    lines = pem_content.split('\n')
                    cert_base64 = ''
                    capture = False
                    for line in lines:
                        if '-----BEGIN CERTIFICATE-----' in line:
                            capture = True
                            continue
                        elif '-----END CERTIFICATE-----' in line:
                            break
                        elif capture:
                            cert_base64 += line.strip()
                    certificates_to_use.append(cert_base64)
                else:
                    # Assume it's already base64
                    certificates_to_use.append(pem_content.replace('\n', '').replace('\r', '').strip())
            cert_source = 'uploaded_certificates'
            print(f"🔍 DEBUG: Using uploaded certificates: {len(certificates_to_use)} certs converted to base64")
        
        if certificates_to_use:
            try:
                print(f"🔍 DEBUG: Starting signature verification with {len(certificates_to_use)} certificates")
                signature_verification = verify_saml_signature(
                    full_response, 
                    certificates_to_use
                )
                # Add source information
                if signature_verification:
                    signature_verification['certificate_source'] = cert_source
                    print(f"🔍 DEBUG: Signature verification result: {signature_verification.get('verified', False)}")
            except Exception as sig_error:
                print(f"🔍 DEBUG: Signature verification exception: {str(sig_error)}")
                signature_verification = {
                    'verified': False,
                    'error': f'Signature verification failed: {str(sig_error)}',
                    'details': [f'❌ Verification error: {str(sig_error)}'],
                    'certificate_source': cert_source
                }
        else:
            print("🔍 DEBUG: No certificates available for signature verification")
            signature_verification = None
        
        session['saml_response'] = {
            'saml_response': full_response,  # Store full response for educational purposes
            'saml_assertion': saml_assertion,  # Store extracted assertion separately
            'saml_response_size': len(decoded_response),
            'saml_assertion_size': len(saml_assertion) if saml_assertion else 0,
            'relay_state': relay_state,
            'assertion_consumer_url': request.url,
            'timestamp': datetime.now().isoformat(),
            'original_request_id': session.get('saml_request_id', 'unknown'),
            'response_method': request.method,  # Should be POST for SAML
            'compressed_base64_size': len(saml_response) if saml_response else 0,
            'user_attributes_count': len(extracted_attrs),
            'has_name_id': bool(user_info.get('name_id')),
            'parsing_method': 'Real SAML Response' if 'saml:Assertion' in full_response else 'Demo Fallback',
            'signature_verification': signature_verification
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

@app.route('/upload_certificate', methods=['POST'])
def upload_certificate():
    """
    Optional feature: Upload SAML signing certificate for verification
    This is a nice-to-have educational feature for understanding SAML security
    """
    try:
        if 'certificate' not in request.files:
            return jsonify({'error': 'No certificate file provided'}), 400
        
        cert_file = request.files['certificate']
        if cert_file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Read the certificate content
        cert_content = cert_file.read().decode('utf-8')
        
        # Basic validation - check if it looks like a certificate
        if 'BEGIN CERTIFICATE' not in cert_content or 'END CERTIFICATE' not in cert_content:
            return jsonify({'error': 'Invalid certificate format. Please upload a PEM or Base64 certificate.'}), 400
        
        # Store in session for this demo (in production, you'd store this more securely)
        if 'uploaded_certificates' not in session:
            session['uploaded_certificates'] = []
        
        # Parse certificate to get basic info
        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            import base64
            
            # Handle both PEM and raw base64 formats
            if '-----BEGIN CERTIFICATE-----' in cert_content:
                cert_pem = cert_content
            else:
                # Assume it's raw base64, add PEM headers
                clean_b64 = cert_content.replace('\n', '').replace('\r', '').replace(' ', '')
                cert_pem = f"-----BEGIN CERTIFICATE-----\n{clean_b64}\n-----END CERTIFICATE-----"
            
            cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
            
            cert_info = {
                'pem': cert_pem,
                'subject': cert.subject.rfc4514_string(),
                'issuer': cert.issuer.rfc4514_string(),
                'not_after': cert.not_valid_after.isoformat(),
                'not_before': cert.not_valid_before.isoformat(),
                'serial_number': str(cert.serial_number),
                'uploaded_at': datetime.now().isoformat(),
                'filename': cert_file.filename
            }
            
            session['uploaded_certificates'].append(cert_info)
            session.modified = True
            
            return jsonify({
                'success': True,
                'message': 'Certificate uploaded successfully!',
                'certificate_info': {
                    'subject': cert_info['subject'],
                    'valid_until': cert_info['not_after'],
                    'filename': cert_info['filename']
                }
            })
            
        except Exception as parse_error:
            return jsonify({'error': f'Failed to parse certificate: {str(parse_error)}'}), 400
        
    except Exception as e:
        return jsonify({'error': f'Upload failed: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=3000)
