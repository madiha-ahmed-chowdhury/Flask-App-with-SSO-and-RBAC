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

# Authentik OIDC Configuration
AUTHENTIK_BASE_URL = os.environ.get('AUTHENTIK_BASE_URL', 'http://servert:9000')  # For internal API calls
AUTHENTIK_PUBLIC_URL = os.environ.get('AUTHENTIK_PUBLIC_URL', 'http://localhost:9000')  # For browser redirects
AUTHENTIK_CLIENT_ID = os.environ.get('AUTHENTIK_CLIENT_ID', 'your-client-id')
AUTHENTIK_CLIENT_SECRET = os.environ.get('AUTHENTIK_CLIENT_SECRET', 'your-client-secret')
FLASK_BASE_URL = os.environ.get('FLASK_BASE_URL', 'http://localhost:5000')

# OAuth2 Setup
oauth = OAuth(app)
oauth.register(
    name='authentik',
    client_id=AUTHENTIK_CLIENT_ID,
    client_secret=AUTHENTIK_CLIENT_SECRET,
    server_metadata_url=f'{AUTHENTIK_BASE_URL}/application/o/flask-app/.well-known/openid-configuration',
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
            user_roles = [group.get('name', '') for group in user_groups if isinstance(group, dict)]
            
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

# Routes
@app.route('/')
def index():
    if 'user' in session:
        user = session['user']
        groups = user.get('groups', [])
        group_names = [group.get('name', 'Unknown') for group in groups if isinstance(group, dict)]
        
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
                .nav a { margin-right: 15px; padding: 10px 15px; background: #007bff; color: white; text-decoration: none; border-radius: 3px; }
                .nav a:hover { background: #0056b3; }
                .logout { background: #dc3545 !important; }
                .logout:hover { background: #c82333 !important; }
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
                    <p><strong>Groups:</strong> {{ ', '.join(group_names) if group_names else 'None' }}</p>
                </div>
                <div class="nav">
                    <a href="{{ url_for('profile') }}">Profile</a>
                    <a href="{{ url_for('admin_dashboard') }}">Admin Dashboard</a>
                    <a href="{{ url_for('user_dashboard') }}">User Dashboard</a>
                    <a href="{{ url_for('manager_dashboard') }}">Manager Dashboard</a>
                    <a href="{{ url_for('logout') }}" class="logout">Logout</a>
                </div>
            </div>
        </body>
        </html>
        ''', user=user, group_names=group_names)
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
            
            # Get user details from Authentik API
            user_response = requests.get(
                f'{AUTHENTIK_BASE_URL}/api/v3/core/users/me/',
                headers=headers
            )
            
            if user_response.status_code == 200:
                user_data = user_response.json()
                user_info['groups'] = user_data.get('groups_obj', [])
            
            session['user'] = user_info
            session['access_token'] = access_token
            logger.info(f"User {user_info.get('email')} logged in successfully")
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
            logout_url = f'{AUTHENTIK_BASE_URL}/application/o/flask-app/end-session/'
            post_logout_redirect_uri = url_for('index', _external=True)
            
            return redirect(f'{logout_url}?post_logout_redirect_uri={post_logout_redirect_uri}')
        except Exception as e:
            logger.error(f"Logout error: {str(e)}")
    
    return redirect(url_for('index'))

@app.route('/profile')
@require_auth
def profile():
    user = session['user']
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
                    {% for group in user.get('groups', []) %}
                        <li>{{ group.get('name', 'Unknown Group') }}</li>
                    {% endfor %}
                </ul>
            </div>
            <a href="{{ url_for('index') }}" class="back-btn">Back to Home</a>
        </div>
    </body>
    </html>
    ''', user=user)

@app.route('/admin')
@require_role(['Admin', 'Administrators'])
def admin_dashboard():
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
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Admin Dashboard</h1>
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
    ''')

@app.route('/user')
@require_role(['User', 'Users', 'Admin', 'Administrators'])
def user_dashboard():
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
        </style>
    </head>
    <body>
        <div class="container">
            <h1>User Dashboard</h1>
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
    ''')

@app.route('/manager')
@require_role(['Manager', 'Managers', 'Admin', 'Administrators'])
def manager_dashboard():
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
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Manager Dashboard</h1>
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
    ''')

@app.route('/api/user-info')
@require_auth
def api_user_info():
    """API endpoint to get current user information"""
    user = session['user']
    return jsonify({
        'name': user.get('name'),
        'email': user.get('email'),
        'username': user.get('preferred_username'),
        'groups': [group.get('name') for group in user.get('groups', []) if isinstance(group, dict)],
        'email_verified': user.get('email_verified', False)
    })

@app.route('/health')
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'timestamp': datetime.utcnow().isoformat()})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)