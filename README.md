# Complete Authentik SSO Integration Guide with Flask

## Table of Contents
1. [Overview](#overview)
2. [Understanding the Technologies](#understanding-the-technologies)
3. [Project Architecture](#project-architecture)
4. [System Configuration](#system-configuration)
5. [Connection to Application Layer](#connection-to-application-layer)
6. [Docker & Docker Compose Setup](#docker--docker-compose-setup)
7. [Prerequisites](#prerequisites)
8. [Step-by-Step Setup](#step-by-step-setup)


## Overview

This guide demonstrates how to implement Single Sign-On (SSO) authentication using Authentik as an Identity Provider (IdP) with a Flask web application. The setup provides role-based access control, secure token-based authentication, and a modern SSO experience.

### What You'll Build
- A Flask web application with protected routes
- Authentik as the identity provider
- Role-based access control (Admin, Manager, User)
- Secure OIDC-based authentication flow
- Docker-containerized environment

## Understanding the Technologies

### OAuth 2.0
OAuth 2.0 is an authorization framework that enables applications to obtain limited access to user accounts. It works by delegating user authentication to the service that hosts the user account and authorizing third-party applications to access the user account.

**Key Components:**
- **Resource Owner**: The user who authorizes an application to access their account
- **Client**: The application that wants to access the user's account
- **Resource Server**: The server hosting the protected resources
- **Authorization Server**: The server issuing access tokens after successfully authenticating the resource owner

### OpenID Connect (OIDC)
OpenID Connect is an identity layer built on top of OAuth 2.0. While OAuth 2.0 is primarily about authorization, OIDC adds authentication capabilities.

**Key Features:**
- **ID Token**: A JWT containing identity information about the user
- **UserInfo Endpoint**: Provides additional user profile information
- **Standardized Claims**: Common user attributes like name, email, etc.
- **Discovery**: Automatic configuration discovery

### Authentik
Authentik is an open-source Identity Provider focused on flexibility and versatility. It can be used for:
- Single Sign-On (SSO)
- Multi-Factor Authentication (MFA)
- User provisioning and management
- Application proxy and authorization

**Key Benefits:**
- Modern web UI for administration
- Support for multiple protocols (OIDC, SAML, LDAP)
- Flexible policy engine
- Built-in application proxy
- Extensive customization options

## Project Architecture
This section provides visual representations of the system architecture and component interactions.

### Authentik Core Flow Diagram

![Authentik Flow Diagram](./assets/authentik%20architecture.png)

**Figure 1: Authentik Internal Architecture**

This diagram illustrates the internal component structure of Authentik and how they interact with the data layer:

### Core Components
- **User** - End users accessing the authentication system
- **Authentik Server** - Main entry point that handles user requests and coordinates between components
- **Authentik Server Core** - The primary processing engine that manages authentication logic
- **Embedded Outpost** - Handles proxy authentication and protocol translation
- **Background Worker** - Processes asynchronous tasks and background operations

### Data Storage
- **PostgreSQL** - Primary database storing user accounts, configurations, and persistent data
- **Redis** - Caching layer for sessions, temporary data, and performance optimization

### Key Interactions
The diagram shows how user requests flow through the server to either the core processing engine or embedded outpost, with both components having access to the PostgreSQL database for persistent operations and Redis for caching and session management.

---
### Directory Structure
```
authentik-flask-sso/
├── docker-compose.yml          # Container orchestration
├── .env                        # Environment variables
├── flask-app/                  # Flask application
│   ├── Dockerfile             # Flask container definition
│   ├── requirements.txt       # Python dependencies
│   └── app.py                 # Main Flask application
├── media/                     # Authentik media files
├── custom-templates/          # Custom Authentik templates
└── certs/                     # SSL certificates (if needed)
```

### Application Architecture Diagram

![Application Architecture](./assets/Architecture.svg)

**Figure 2: Complete System Architecture with Flask Integration**

This diagram shows the complete authentication flow including the custom Flask application integration:

#### User Authentication Flow
1. **Access App** - User attempts to access the Flask application (port 5000)
2. **OAuth Request** - Flask redirects unauthenticated users to Authentik Server for login
3. **Auth Code & Token Exchange** - Authentik handles authentication and returns authorization codes/tokens to Flask

#### Service Components
- **Flask App (Port 5000)** - Custom application requiring authentication
- **Authentik Server (Port 9000)** - Authentication service handling login and OAuth flows
- **Authentik Worker** - Background task processor for notifications and data sync

#### Data Layer
- **PostgreSQL** - Stores user accounts, application configurations, and authentication data
- **Redis** - Handles session caching and provides fast access to temporary data

#### System Interactions
- **Query Users/Groups** - Server retrieves user and group information from PostgreSQL
- **Update Data** - Database modifications for user management and configuration changes
- **Cache Sessions** - Redis stores session data for performance
- **Process Tasks** - Worker handles background operations and communicates with both databases
- **Background Tasks** - Asynchronous operations between server and worker components

This architecture ensures secure, scalable authentication where Authentik manages all identity operations while the Flask application focuses on business logic.


## System Configuration

### Step 1: Environment Variables Setup

```python
# Authentik OIDC Configuration with manual configuration
AUTHENTIK_BASE_URL = os.environ.get('AUTHENTIK_BASE_URL', 'http://server:9000')
AUTHENTIK_PUBLIC_URL = os.environ.get('AUTHENTIK_PUBLIC_URL', 'http://localhost:9000')
AUTHENTIK_CLIENT_ID = os.environ.get('AUTHENTIK_CLIENT_ID', 'your-client-id')
AUTHENTIK_CLIENT_SECRET = os.environ.get('AUTHENTIK_CLIENT_SECRET', 'your-client-secret')
FLASK_BASE_URL = os.environ.get('FLASK_BASE_URL', 'http://localhost:5000')
```

**Configuration Details:**
- **`AUTHENTIK_BASE_URL`**: Internal server-to-server communication URL
- **`AUTHENTIK_PUBLIC_URL`**: User-facing URL for browser redirects
- **`CLIENT_ID/SECRET`**: OAuth2 credentials registered in Authentik
- **`FLASK_BASE_URL`**: Your Flask app's external URL for callbacks

### Step 2: Flask Application Secret Configuration

```python
app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'your-secret-key-change-this')
```

**Configuration Details:**
- **`secret_key`**: Critical for session security and cookie signing
- Should be a strong, random string in production
- Used by Flask to encrypt session data

### Step 3: OAuth Client Library Setup

```python
from authlib.integrations.flask_client import OAuth

# OAuth2 Setup with manual configuration instead of server_metadata_url
oauth = OAuth(app)
```

**Configuration Details:**
- Creates OAuth manager instance
- Integrates with Flask app for session management
- Handles OAuth2 protocol complexities

### Step 4: OAuth Provider Registration

```python
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
```

**Configuration Details:**
- **`name`**: Identifier for this OAuth provider ('authentik')
- **`client_id/secret`**: Authentication credentials
- **`authorize_url`**: Where users are redirected for login (PUBLIC_URL)
- **`access_token_url`**: Backend endpoint for token exchange (BASE_URL)
- **`userinfo_endpoint`**: Where to fetch user profile data (BASE_URL)
- **`jwks_uri`**: JSON Web Key Set for token verification
- **`scope`**: Data permissions requested (profile, email, groups)

### Step 5: Logging Configuration

```python
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
```

**Configuration Details:**
- Sets up application logging for debugging
- INFO level captures authentication events
- Used throughout the app for error tracking

---

## Connection to Application Layer

### Step 1: Login Initiation - Configuration Usage

```python
@app.route('/login')
def login():
    redirect_uri = url_for('auth_callback', _external=True)
    return oauth.authentik.authorize_redirect(redirect_uri)
```

**Connection Details:**
- **`oauth.authentik`**: Uses the registered OAuth provider from configuration
- **`authorize_redirect()`**: Internally uses `authorize_url` from Step 4
- **`redirect_uri`**: Points to callback route using `FLASK_BASE_URL`
- **Flow**: User → Authentik login page → Back to Flask callback

### Step 2: OAuth Callback - Token Exchange

```python
@app.route('/callback')
def auth_callback():
    try:
        # Uses access_token_url from configuration
        token = oauth.authentik.authorize_access_token()
        user_info = token.get('userinfo')
```

**Connection Details:**
- **`authorize_access_token()`**: Uses `access_token_url` from configuration
- **Exchanges**: Authorization code → Access token
- **Backend communication**: Flask server → Authentik server
- **Security**: Uses CLIENT_SECRET for authentication

### Step 3: Additional User Data Fetching

```python
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
```

**Connection Details:**
- **`AUTHENTIK_BASE_URL`**: Used for direct API calls
- **Bearer token**: Access token from OAuth flow
- **Additional data**: Fetches group memberships not in basic userinfo
- **Session storage**: Combines OAuth userinfo with API data

### Step 4: Session Management

```python
            session['user'] = user_info
            session['access_token'] = access_token
            logger.info(f"User {user_info.get('email')} logged in successfully")
            return redirect(url_for('index'))
```

**Connection Details:**
- **Flask session**: Uses `secret_key` from configuration for encryption
- **Persistent storage**: User data available across requests
- **Logging**: Uses configured logger for audit trail

### Step 5: Role-Based Access Control

```python
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
```

**Connection Details:**
- **Session dependency**: Uses stored user data from Step 4
- **Group data**: From additional API call in Step 3
- **Authorization logic**: Compares user groups with required roles
- **Error handling**: Returns structured JSON response with role information

### Step 6: Logout Process

```python
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
```

**Connection Details:**
- **Session cleanup**: Clears Flask session data
- **`AUTHENTIK_PUBLIC_URL`**: Uses public URL for user browser redirect
- **Complete logout**: Ensures logout from both Flask and Authentik
- **Redirect chain**: Authentik logout → Back to Flask index

### Step 7: Protected Routes Implementation

```python
@app.route('/admin')
@require_role(['Admin', 'Administrators'])
def admin_dashboard():
    return render_template_string('''...''')

@app.route('/user')
@require_role(['User', 'Users', 'Admin', 'Administrators'])
def user_dashboard():
    return render_template_string('''...''')
```

**Connection Details:**
- **Decorator usage**: Applies role checking from Step 5
- **Configuration dependency**: Roles come from Authentik groups (Step 3)
- **Hierarchical access**: Admin can access user routes
- **Session reliance**: All data comes from authenticated session

---

## Docker & Docker Compose Setup

This section covers the containerization architecture, configuration, and deployment instructions for the Authentik authentication system with Flask application integration.

### Architecture Overview

The application stack consists of five containerized services orchestrated through Docker Compose:

- **PostgreSQL Database** - Primary data storage for Authentik
- **Redis Cache** - Session storage and caching layer
- **Authentik Server** - Main authentication service
- **Authentik Worker** - Background task processor
- **Flask Application** - Custom application integrated with Authentik

All services communicate through a dedicated Docker network (`authentik_network`) for security and isolation.

### Prerequisites

- Docker Engine 20.10+ 
- Docker Compose 2.0+
- Minimum 2GB RAM available for containers
- Ports 5000, 9000, and 9443 available on host system

### Environment Configuration

The application requires a `.env` file in your project root containing database credentials, authentication keys, and OAuth configuration. Ensure all required environment variables are properly configured before deployment.

### Service Configurations

#### PostgreSQL Database
- **Image**: `postgres:16-alpine`
- **Health Check**: Validates database connectivity every 30s
- **Persistence**: Data stored in named volume `database`
- **Network**: Internal communication only via `authentik_network`

#### Redis Cache
- **Image**: `redis:alpine`
- **Configuration**: Persistence enabled (save every 60s if ≥1 key changed)
- **Health Check**: Redis PING command validation
- **Performance**: Optimized for session storage

#### Authentik Server
- **Image**: `ghcr.io/goauthentik/server:2025.4.0`
- **Ports**: 
  - HTTP: `9000` (configurable via `COMPOSE_PORT_HTTP`)
  - HTTPS: `9443` (configurable via `COMPOSE_PORT_HTTPS`)
- **Dependencies**: Waits for healthy PostgreSQL and Redis services
- **Volumes**: 
  - `./media` - User uploads and media files
  - `./custom-templates` - Custom UI templates

#### Authentik Worker
- **Purpose**: Handles background tasks (email, LDAP sync, etc.)
- **Privileges**: Runs as root with Docker socket access
- **Volumes**:
  - `/var/run/docker.sock` - Docker API access for container management
  - `./certs` - SSL certificate storage
  - Additional shared volumes with server

#### Flask Application
- **Build Context**: `./flask-app/`
- **Port**: `5000`
- **Integration**: OAuth2 client for Authentik authentication
- **Health Check**: HTTP endpoint monitoring at `/health`

## Prerequisites

### Software Requirements
- Docker and Docker Compose
- Web browser for testing
- Text editor for configuration

### Knowledge Requirements
- Basic understanding of web authentication
- Familiarity with Docker containers
- Basic knowledge of Python/Flask (helpful but not required)

### System Requirements
- 4GB RAM minimum (8GB recommended)
- 2GB free disk space
- Network access for Docker image downloads

## Step-by-Step Setup

### Step 1: Clone the Repository

1. **Clone the GitHub repository:**
   ```bash
   git clone https://github.com/madiha-ahmed-chowdhury/Flask-application-with-SSO.git
   ```

2. **Verify the project structure:**
   ```bash
   ls -la
   ```
   You should see:
   - `docker-compose.yml` ✅ (already in repo)
   - `flask-app/` directory with Flask application files ✅ (already in repo)
   - Other directories like `media/`, `custom-templates/`, `certs/` ✅ (already in repo)

### Step 2: Create the Environment File

Since the `.env` file is not included in the repository (for security reasons), you need to create it:

1. **Create the `.env` file in the root directory:**
   ```bash
   touch .env
   ```

2. **Add the following content to `.env`:**
   ```bash
   # PostgreSQL Database Configuration
   PG_PASS=your-secure-database-password-change-this
   PG_USER=authentik
   PG_DB=authentik

   # Authentik Configuration
   AUTHENTIK_SECRET_KEY=this-is-your-secret-key-make-it-at-least-50-characters-long-and-random
   AUTHENTIK_ERROR_REPORTING__ENABLED=true

   # Flask Application (These will be updated later)
   AUTHENTIK_CLIENT_ID=placeholder-will-be-updated-from-authentik
   AUTHENTIK_CLIENT_SECRET=placeholder-will-be-updated-from-authentik
   AUTHENTIK_SERVER_URL=http://localhost:9000
   FLASK_SECRET_KEY=your-flask-secret-key-change-this-too

   # Optional: Authentik Image Configuration
   AUTHENTIK_IMAGE=ghcr.io/goauthentik/authentik
   AUTHENTIK_TAG=2024.2.2

   # Optional: Port Configuration
   COMPOSE_PORT_HTTP=9000
   COMPOSE_PORT_HTTPS=9443
   ```

3. **Generate secure passwords and keys:**
   ```bash
   # Generate a secure database password
   openssl rand -base64 32

   # Generate a secure Authentik secret key
   openssl rand -base64 60

   # Generate a secure Flask secret key
   openssl rand -base64 32
   ```

4. **Update the `.env` file with the generated values**

⚠️ **Security Note**: Never commit the `.env` file to version control as it contains sensitive credentials.

### Step 3: Start Authentik Services

1. **Start only Authentik services first (not the Flask app yet):**
   ```bash
   docker-compose up -d postgresql redis server worker
   ```

2. **Wait for services to be healthy (this may take 2-3 minutes):**
   ```bash
   docker-compose ps
   ```
   All services should show as "healthy" or "running"

3. **Check logs if there are any issues:**
   ```bash
   # Check server logs
   docker-compose logs -f server

   # Check all services
   docker-compose logs
   ```

### Step 4: Configure Authentik

1. **Access Authentik Web Interface:**
   - Open your browser and go to `http://localhost:9000`
   - You'll see the initial setup wizard

2. **Complete Initial Setup:**
   - Create admin account with a strong password
   - Set admin email address
   - Complete the welcome setup wizard

3. **Access Admin Interface:**
   - Go to `http://localhost:9000/if/admin/`
   - Login with your admin credentials
   - You should see the Authentik administration dashboard

### Step 5: Create User Groups in Authentik

Groups are used for role-based access control in the Flask application.

1. **Navigate to Directory → Groups**
2. **Create the following groups:**

   **Administrators Group:**
   - Name: `Administrators`
   - Add your admin user to this group

   **Managers Group:**
   - Name: `Managers`

   **Users Group:**
   - Name: `Users`

3. **Add your admin user to the Administrators group:**
   - Click on the `Administrators` group
   - Go to the "Users" tab
   - Add your admin user

### Step 6: Create OIDC Provider

This is the core configuration that enables OIDC authentication for your Flask app.

1. **Navigate to Applications → Providers**
2. **Click "Create"**
3. **Select "OAuth2/OpenID Provider"**
4. **Configure Provider with these settings:**

   **Basic Settings:**
   - **Name:** `flask-app-provider`
   - **Authorization flow:** `default-authorization-flow (Authorize application)`
   - **Client type:** `Confidential`
   - **Client ID:** Leave auto-generated (you'll copy this later)
   - **Client Secret:** Leave auto-generated (you'll copy this later)

   **URLs:**
   - **Redirect URIs:** `http://localhost:5000/callback`
   - **Scopes:** `openid profile email`

   **Token Settings:**
   - **Subject mode:** `Based on the User's hashed ID`
   - **Include claims in id_token:** ✅ (checked)
   - **Access token validity:** `minutes=10`
   - **Refresh token validity:** `days=30`

5. **Click "Create"**

6. **Copy the credentials:**
   - After creation, copy the `Client ID` and `Client Secret`
   - You'll need these for the Flask app configuration

### Step 7: Create Application in Authentik

1. **Navigate to Applications → Applications**
2. **Click "Create"**
3. **Configure Application:**
   - **Name:** `Flask SSO App`
   - **Slug:** `flask-app`
   - **Provider:** Select `flask-app-provider` (created in previous step)
   - **Launch URL:** `http://localhost:5000`
   - **Open in new tab:** ✅ (optional)

4. **Click "Create"**

### Step 8: Update Environment Configuration

Now update your `.env` file with the actual credentials from Authentik.

1. **Copy the Client ID and Secret:**
   - Go to Applications → Providers → flask-app-provider
   - Copy the `Client ID` and `Client Secret`

2. **Update your `.env` file:**
   ```bash
   # Replace the placeholder values with actual values from Authentik
   AUTHENTIK_CLIENT_ID=your-actual-client-id-from-authentik-provider
   AUTHENTIK_CLIENT_SECRET=your-actual-client-secret-from-authentik-provider
   ```

### Step 9: Start Flask Application

1. **Start the Flask application:**
   ```bash
   docker-compose up -d flask-app
   ```

2. **Verify all services are running:**
   ```bash
   docker-compose ps
   ```
   You should see all services (postgresql, redis, server, worker, flask-app) running

3. **Check Flask app logs:**
   ```bash
   docker-compose logs -f flask-app
   ```
   Look for "Running on http://0.0.0.0:5000" message