from flask import Flask, request, redirect, url_for, session, jsonify, render_template_string
from authlib.integrations.flask_client import OAuth
from authlib.common.security import generate_token
import requests
import os
from functools import wraps
import jwt
from datetime import datetime, timedelta
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'your-secret-key-change-this')

# Authentik OIDC Configuration with manual configuration
AUTHENTIK_BASE_URL = os.environ.get('AUTHENTIK_BASE_URL', 'http://localhost:9000')
AUTHENTIK_PUBLIC_URL = os.environ.get('AUTHENTIK_PUBLIC_URL', 'http://localhost:9000')
AUTHENTIK_CLIENT_ID = os.environ.get('AUTHENTIK_CLIENT_ID', 'your-client-id')
AUTHENTIK_CLIENT_SECRET = os.environ.get('AUTHENTIK_CLIENT_SECRET', 'your-client-secret')
FLASK_BASE_URL = os.environ.get('FLASK_BASE_URL', 'http://localhost:5000')

# OAuth2 Setup with manual configuration instead of server_metadata_url
oauth = OAuth(app)
oauth.register(
    name='authentik',
    client_id=AUTHENTIK_CLIENT_ID,
    client_secret=AUTHENTIK_CLIENT_SECRET,
    authorize_url=f'{AUTHENTIK_PUBLIC_URL}/application/o/authorize/',
    access_token_url=f'{AUTHENTIK_BASE_URL}/application/o/token/',
    userinfo_endpoint=f'{AUTHENTIK_BASE_URL}/application/o/userinfo/',
    jwks_uri=f'{AUTHENTIK_BASE_URL}/application/o/flask-app/jwks/',
    client_kwargs={
        'scope': 'openid profile email groups'
    }
)

# Role-based access control decorator
def require_role(required_roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user' not in session:
                return redirect(url_for('login'))
            
            user_groups = session.get('user', {}).get('groups', [])
            # Handle both string and dict group formats
            if user_groups and isinstance(user_groups[0], dict):
                user_roles = [group.get('name', '') for group in user_groups]
            else:
                user_roles = user_groups if isinstance(user_groups, list) else []
            
            # Check if user has any of the required roles
            if not any(role in user_roles for role in required_roles):
                return jsonify({
                    'error': 'Insufficient permissions',
                    'required_roles': required_roles,
                    'user_roles': user_roles
                }), 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def get_user_groups(user_data):
    """Extract group names from user data, handling different formats"""
    groups = user_data.get('groups', [])
    if not groups:
        return []
    
    # Handle different group formats
    if isinstance(groups[0], dict):
        return [group.get('name', '') for group in groups if group.get('name')]
    elif isinstance(groups[0], str):
        return groups
    else:
        return []

def get_available_dashboards(user_groups):
    """Determine which dashboards a user can access based on their groups"""
    dashboards = []
    
    # Define role mappings - adjust these based on your Authentik groups
    role_dashboard_map = {
        'authentik Admins': ['admin', 'manager', 'user'],
        'Administrators': ['admin', 'manager', 'user'],
        'Admin': ['admin', 'manager', 'user'],
        'Managers': ['manager', 'user'],
        'manager': ['manager', 'user'],
        'users': ['user'],
        'user': ['user'],
        'Staff': ['user'],
        'Employee': ['user']
    }
    
    user_dashboards = set()
    for group in user_groups:
        if group in role_dashboard_map:
            user_dashboards.update(role_dashboard_map[group])
    
    return list(user_dashboards)

# Routes
@app.route('/')
def index():
    if 'user' in session:
        user = session['user']
        user_groups = get_user_groups(user)
        available_dashboards = get_available_dashboards(user_groups)
        
        # Generate dashboard links based on user's groups
        dashboard_links = []
        if 'admin' in available_dashboards:
            dashboard_links.append('<a href="/admin">Admin Dashboard</a>')
        if 'manager' in available_dashboards:
            dashboard_links.append('<a href="/manager">Manager Dashboard</a>')
        if 'user' in available_dashboards:
            dashboard_links.append('<a href="/user">User Dashboard</a>')
        
        return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Flask SSO App</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; }
                .container { max-width: 800px; margin: 0 auto; }
                .user-info { background: #f0f0f0; padding: 20px; border-radius: 5px; margin: 20px 0; }
                .nav { margin: 20px 0; }
                .nav a { margin-right: 15px; padding: 10px 15px; background: #007bff; color: white; text-decoration: none; border-radius: 3px; display: inline-block; margin-bottom: 10px; }
                .nav a:hover { background: #0056b3; }
                .logout { background: #dc3545 !important; }
                .logout:hover { background: #c82333 !important; }
                .dashboard-info { background: #e7f3ff; padding: 15px; border-radius: 5px; margin: 15px 0; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Welcome to Flask SSO Application</h1>
                <div class="user-info">
                    <h3>User Information</h3>
                    <p><strong>Name:</strong> {{ user.get('name', 'N/A') }}</p>
                    <p><strong>Email:</strong> {{ user.get('email', 'N/A') }}</p>
                    <p><strong>Username:</strong> {{ user.get('preferred_username', 'N/A') }}</p>
                    <p><strong>Groups:</strong> {{ ', '.join(user_groups) if user_groups else 'None' }}</p>
                </div>
                
                <div class="dashboard-info">
                    <h3>Available Dashboards</h3>
                    <p>Based on your group memberships, you have access to:</p>
                    <ul>
                        {% for dashboard in available_dashboards %}
                            <li>{{ dashboard.title() }} Dashboard</li>
                        {% endfor %}
                    </ul>
                </div>
                
                <div class="nav">
                    <a href="{{ url_for('profile') }}">Profile</a>
                    {% if 'admin' in available_dashboards %}
                        <a href="{{ url_for('admin_dashboard') }}">Admin Dashboard</a>
                    {% endif %}
                    {% if 'manager' in available_dashboards %}
                        <a href="{{ url_for('manager_dashboard') }}">Manager Dashboard</a>
                    {% endif %}
                    {% if 'user' in available_dashboards %}
                        <a href="{{ url_for('user_dashboard') }}">User Dashboard</a>
                    {% endif %}
                    <a href="{{ url_for('debug_groups') }}">Debug Groups</a>
                    <a href="{{ url_for('logout') }}" class="logout">Logout</a>
                </div>
            </div>
        </body>
        </html>
        ''', user=user, user_groups=user_groups, available_dashboards=available_dashboards)
    else:
        return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Flask SSO App - Login</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; text-align: center; }
                .container { max-width: 400px; margin: 0 auto; }
                .login-btn { padding: 15px 30px; background: #007bff; color: white; text-decoration: none; border-radius: 5px; font-size: 16px; }
                .login-btn:hover { background: #0056b3; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Flask SSO Application</h1>
                <p>Please login to access the application</p>
                <a href="{{ url_for('login') }}" class="login-btn">Login with Authentik</a>
            </div>
        </body>
        </html>
        ''')

@app.route('/login')
def login():
    redirect_uri = url_for('auth_callback', _external=True)
    return oauth.authentik.authorize_redirect(redirect_uri)

@app.route('/callback')
def auth_callback():
    try:
        token = oauth.authentik.authorize_access_token()
        user_info = token.get('userinfo')
        
        if user_info:
            # Fetch additional user information including groups
            access_token = token.get('access_token')
            headers = {'Authorization': f'Bearer {access_token}'}
            
            # Method 1: Try to get groups from userinfo endpoint first
            logger.info(f"Initial userinfo groups: {user_info.get('groups', [])}")
            
            # Method 2: Get user details from Authentik API for more detailed group info
            try:
                user_response = requests.get(
                    f'{AUTHENTIK_BASE_URL}/api/v3/core/users/me/',
                    headers=headers,
                    timeout=10
                )
                
                if user_response.status_code == 200:
                    user_data = user_response.json()
                    logger.info(f"API user data groups: {user_data.get('groups_obj', [])}")
                    
                    # Use groups from API if available, otherwise fall back to userinfo
                    if user_data.get('groups_obj'):
                        user_info['groups'] = user_data.get('groups_obj', [])
                    elif user_data.get('groups'):
                        user_info['groups'] = user_data.get('groups', [])
                    # If no groups in API response, keep the ones from userinfo
                else:
                    logger.warning(f"Failed to fetch user details from API: {user_response.status_code}")
                    
            except requests.exceptions.RequestException as e:
                logger.error(f"Error fetching user details: {str(e)}")
                # Continue with userinfo groups if API call fails
            
            # Method 3: Also try to get groups from the token claims
            if not user_info.get('groups') and 'id_token' in token:
                try:
                    import jwt
                    # Don't verify signature for debugging - in production you should verify
                    decoded_token = jwt.decode(token['id_token'], options={"verify_signature": False})
                    if 'groups' in decoded_token:
                        user_info['groups'] = decoded_token['groups']
                        logger.info(f"Token groups: {decoded_token.get('groups', [])}")
                except Exception as e:
                    logger.error(f"Error decoding token: {str(e)}")
            
            session['user'] = user_info
            session['access_token'] = access_token
            
            print(f"DEBUG - Raw user_info: {user_info}")
            print(f"DEBUG - Groups in user_info: {user_info.get('groups', 'NO GROUPS KEY')}")
            final_groups = get_user_groups(user_info)
            logger.info(f"User {user_info.get('email')} logged in successfully with groups: {final_groups}")
            
            return redirect(url_for('index'))
        else:
            logger.error("Failed to get user info from token")
            return 'Login failed', 400
            
    except Exception as e:
        logger.error(f"Login callback error: {str(e)}")
        return f'Login failed: {str(e)}', 400

@app.route('/logout')
def logout():
    # Get the access token for logout
    access_token = session.get('access_token')
    user = session.get('user', {})
    
    # Clear session
    session.clear()
    
    # Perform logout at Authentik
    if access_token:
        try:
            logout_url = f'{AUTHENTIK_PUBLIC_URL}/application/o/flask-app/end-session/'
            post_logout_redirect_uri = url_for('index', _external=True)
            
            return redirect(f'{logout_url}?post_logout_redirect_uri={post_logout_redirect_uri}')
        except Exception as e:
            logger.error(f"Logout error: {str(e)}")
    
    return redirect(url_for('index'))

@app.route('/profile')
@require_auth
def profile():
    user = session['user']
    user_groups = get_user_groups(user)
    
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Profile</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; }
            .container { max-width: 600px; margin: 0 auto; }
            .profile-info { background: #f8f9fa; padding: 20px; border-radius: 5px; margin: 20px 0; }
            .back-btn { padding: 10px 15px; background: #6c757d; color: white; text-decoration: none; border-radius: 3px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>User Profile</h1>
            <div class="profile-info">
                <h3>Profile Information</h3>
                <p><strong>Name:</strong> {{ user.get('name', 'N/A') }}</p>
                <p><strong>Email:</strong> {{ user.get('email', 'N/A') }}</p>
                <p><strong>Username:</strong> {{ user.get('preferred_username', 'N/A') }}</p>
                <p><strong>Email Verified:</strong> {{ user.get('email_verified', False) }}</p>
                <p><strong>Groups:</strong></p>
                <ul>
                    {% for group in user_groups %}
                        <li>{{ group }}</li>
                    {% endfor %}
                </ul>
            </div>
            <a href="{{ url_for('index') }}" class="back-btn">Back to Home</a>
        </div>
    </body>
    </html>
    ''', user=user, user_groups=user_groups)

@app.route('/admin')
@require_role(['authentik Admins', 'Administrators', 'Admin'])
def admin_dashboard():
    user_groups = get_user_groups(session['user'])
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Admin Dashboard</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; }
            .container { max-width: 800px; margin: 0 auto; }
            .dashboard { background: #d4edda; padding: 20px; border-radius: 5px; margin: 20px 0; border-left: 5px solid #28a745; }
            .back-btn { padding: 10px 15px; background: #6c757d; color: white; text-decoration: none; border-radius: 3px; }
            .user-groups { background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 15px 0; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Admin Dashboard</h1>
            <div class="user-groups">
                <h4>Your Groups:</h4>
                <p>{{ ', '.join(user_groups) if user_groups else 'None' }}</p>
            </div>
            <div class="dashboard">
                <h3>Administrative Functions</h3>
                <p>Welcome to the admin dashboard. You have administrative privileges.</p>
                <ul>
                    <li>User Management</li>
                    <li>System Configuration</li>
                    <li>Security Settings</li>
                    <li>Audit Logs</li>
                </ul>
            </div>
            <a href="{{ url_for('index') }}" class="back-btn">Back to Home</a>
        </div>
    </body>
    </html>
    ''', user_groups=user_groups)

@app.route('/user')
@require_role(['user'])
def user_dashboard():
    user_groups = get_user_groups(session['user'])
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>User Dashboard</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; }
            .container { max-width: 800px; margin: 0 auto; }
            .dashboard { background: #cce5ff; padding: 20px; border-radius: 5px; margin: 20px 0; border-left: 5px solid #007bff; }
            .back-btn { padding: 10px 15px; background: #6c757d; color: white; text-decoration: none; border-radius: 3px; }
            .user-groups { background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 15px 0; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>User Dashboard</h1>
            <div class="user-groups">
                <h4>Your Groups:</h4>
                <p>{{ ', '.join(user_groups) if user_groups else 'None' }}</p>
            </div>
            <div class="dashboard">
                <h3>User Functions</h3>
                <p>Welcome to the user dashboard. Standard user access.</p>
                <ul>
                    <li>View Personal Data</li>
                    <li>Update Profile</li>
                    <li>Change Password</li>
                    <li>Download Reports</li>
                </ul>
            </div>
            <a href="{{ url_for('index') }}" class="back-btn">Back to Home</a>
        </div>
    </body>
    </html>
    ''', user_groups=user_groups)

@app.route('/manager')
@require_role(['manager'])
def manager_dashboard():
    user_groups = get_user_groups(session['user'])
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Manager Dashboard</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; }
            .container { max-width: 800px; margin: 0 auto; }
            .dashboard { background: #fff3cd; padding: 20px; border-radius: 5px; margin: 20px 0; border-left: 5px solid #ffc107; }
            .back-btn { padding: 10px 15px; background: #6c757d; color: white; text-decoration: none; border-radius: 3px; }
            .user-groups { background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 15px 0; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Manager Dashboard</h1>
            <div class="user-groups">
                <h4>Your Groups:</h4>
                <p>{{ ', '.join(user_groups) if user_groups else 'None' }}</p>
            </div>
            <div class="dashboard">
                <h3>Management Functions</h3>
                <p>Welcome to the manager dashboard. You have management privileges.</p>
                <ul>
                    <li>Team Management</li>
                    <li>Project Oversight</li>
                    <li>Resource Allocation</li>
                    <li>Performance Reports</li>
                </ul>
            </div>
            <a href="{{ url_for('index') }}" class="back-btn">Back to Home</a>
        </div>
    </body>
    </html>
    ''', user_groups=user_groups)

@app.route('/debug/groups')
@require_auth
def debug_groups():
    """Debug endpoint to see all group information"""
    user = session['user']
    access_token = session.get('access_token')
    
    debug_info = {
        'userinfo_groups': user.get('groups', []),
        'processed_groups': get_user_groups(user),
        'available_dashboards': get_available_dashboards(get_user_groups(user))
    }
    
    # Try to get additional group info from API
    if access_token:
        try:
            headers = {'Authorization': f'Bearer {access_token}'}
            user_response = requests.get(
                f'{AUTHENTIK_BASE_URL}/api/v3/core/users/me/',
                headers=headers,
                timeout=10
            )
            if user_response.status_code == 200:
                api_data = user_response.json()
                debug_info['api_groups'] = api_data.get('groups', [])
                debug_info['api_groups_obj'] = api_data.get('groups_obj', [])
        except Exception as e:
            debug_info['api_error'] = str(e)
    
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Group Debug Information</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; }
            .container { max-width: 800px; margin: 0 auto; }
            .debug-section { background: #f8f9fa; padding: 20px; border-radius: 5px; margin: 20px 0; }
            .back-btn { padding: 10px 15px; background: #6c757d; color: white; text-decoration: none; border-radius: 3px; }
            pre { background: #e9ecef; padding: 15px; border-radius: 3px; overflow-x: auto; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Group Debug Information</h1>
            <div class="debug-section">
                <h3>Debug Information</h3>
                <pre>{{ debug_info | tojson(indent=2) }}</pre>
            </div>
            <a href="{{ url_for('index') }}" class="back-btn">Back to Home</a>
        </div>
    </body>
    </html>
    ''', debug_info=debug_info)

@app.route('/api/user-info')
@require_auth
def api_user_info():
    """API endpoint to get current user information"""
    user = session['user']
    user_groups = get_user_groups(user)
    
    return jsonify({
        'name': user.get('name'),
        'email': user.get('email'),
        'username': user.get('preferred_username'),
        'groups': user_groups,
        'available_dashboards': get_available_dashboards(user_groups),
        'email_verified': user.get('email_verified', False)
    })

@app.route('/health')
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'timestamp': datetime.utcnow().isoformat()})

@app.route('/debug/config')
def debug_config():
    """Debug endpoint to check OAuth configuration"""
    return jsonify({
        'authentik_base_url': AUTHENTIK_BASE_URL,
        'authentik_public_url': AUTHENTIK_PUBLIC_URL,
        'client_id': AUTHENTIK_CLIENT_ID,
        'flask_base_url': FLASK_BASE_URL,
        'oauth_endpoints': {
            'authorize_url': f'{AUTHENTIK_PUBLIC_URL}/application/o/authorize/',
            'access_token_url': f'{AUTHENTIK_BASE_URL}/application/o/token/',
            'userinfo_endpoint': f'{AUTHENTIK_BASE_URL}/application/o/userinfo/',
            'jwks_uri': f'{AUTHENTIK_BASE_URL}/application/o/flask-app/jwks/'
        }
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)