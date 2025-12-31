"""VK OAuth authentication handler."""
import json
import os
import secrets
import base64
from datetime import datetime, timedelta
from urllib.request import Request, urlopen
from urllib.parse import urlencode, parse_qs
from urllib.error import HTTPError

import jwt
import psycopg2

# =============================================================================
# CONSTANTS
# =============================================================================

VK_AUTHORIZE_URL = "https://oauth.vk.com/authorize"
VK_TOKEN_URL = "https://oauth.vk.com/access_token"
VK_API_URL = "https://api.vk.com/method"
VK_API_VERSION = "5.131"

ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 30

HEADERS = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Content-Type': 'application/json'
}


# =============================================================================
# DATABASE
# =============================================================================

def get_connection():
    """Get database connection."""
    return psycopg2.connect(os.environ['DATABASE_URL'])


def get_schema() -> str:
    """Get database schema prefix."""
    schema = os.environ.get('MAIN_DB_SCHEMA', 'public')
    return f"{schema}." if schema else ""


def escape(value):
    """Escape value for SQL."""
    if value is None:
        return 'NULL'
    if isinstance(value, bool):
        return 'TRUE' if value else 'FALSE'
    if isinstance(value, (int, float)):
        return str(value)
    escaped = str(value).replace("'", "''")
    return f"'{escaped}'"


# =============================================================================
# JWT
# =============================================================================

def create_access_token(user_id: int, email: str = None) -> tuple[str, int]:
    """Create JWT access token."""
    secret = os.environ.get('JWT_SECRET', '')
    expires_delta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    expire = datetime.utcnow() + expires_delta

    payload = {
        'sub': str(user_id),
        'exp': expire,
        'iat': datetime.utcnow(),
        'type': 'access'
    }
    if email:
        payload['email'] = email

    token = jwt.encode(payload, secret, algorithm='HS256')
    return token, int(expires_delta.total_seconds())


def create_refresh_token() -> str:
    """Create refresh token."""
    return secrets.token_urlsafe(32)


# =============================================================================
# VK API
# =============================================================================

def get_vk_auth_url(client_id: str, redirect_uri: str, state: str) -> str:
    """Generate VK authorization URL."""
    params = {
        'client_id': client_id,
        'redirect_uri': redirect_uri,
        'response_type': 'code',
        'scope': 'email',
        'state': state,
        'v': VK_API_VERSION
    }
    return f"{VK_AUTHORIZE_URL}?{urlencode(params)}"


def exchange_code_for_token(code: str, client_id: str, client_secret: str, redirect_uri: str) -> dict:
    """Exchange authorization code for access token."""
    params = {
        'client_id': client_id,
        'client_secret': client_secret,
        'redirect_uri': redirect_uri,
        'code': code,
        'v': VK_API_VERSION
    }

    url = f"{VK_TOKEN_URL}?{urlencode(params)}"
    request = Request(url, method='GET')

    with urlopen(request, timeout=10) as response:
        return json.loads(response.read().decode())


def get_vk_user_info(access_token: str, user_id: int) -> dict:
    """Get user info from VK API."""
    params = {
        'user_ids': user_id,
        'fields': 'photo_100,photo_200',
        'access_token': access_token,
        'v': VK_API_VERSION
    }

    url = f"{VK_API_URL}/users.get?{urlencode(params)}"
    request = Request(url, method='GET')

    with urlopen(request, timeout=10) as response:
        data = json.loads(response.read().decode())
        if 'response' in data and len(data['response']) > 0:
            return data['response'][0]
        return {}


# =============================================================================
# HELPERS
# =============================================================================

def response(status_code: int, body: dict, origin: str = '*') -> dict:
    """Create HTTP response."""
    headers = HEADERS.copy()
    headers['Access-Control-Allow-Origin'] = origin
    return {
        'statusCode': status_code,
        'headers': headers,
        'body': json.dumps(body)
    }


def error(status_code: int, message: str, origin: str = '*') -> dict:
    """Create error response."""
    return response(status_code, {'error': message}, origin)


def get_origin(event: dict) -> str:
    """Get request origin."""
    headers = event.get('headers', {}) or {}
    return headers.get('origin', headers.get('Origin', '*'))


# =============================================================================
# HANDLERS
# =============================================================================

def handle_auth_url(event: dict, origin: str) -> dict:
    """Generate VK authorization URL."""
    client_id = os.environ.get('VK_CLIENT_ID', '')
    redirect_uri = os.environ.get('VK_REDIRECT_URI', '')

    if not client_id or not redirect_uri:
        return error(500, 'VK credentials not configured', origin)

    # Generate state for CSRF protection
    state = secrets.token_urlsafe(16)

    auth_url = get_vk_auth_url(client_id, redirect_uri, state)

    return response(200, {
        'auth_url': auth_url,
        'state': state
    }, origin)


def handle_callback(event: dict, origin: str) -> dict:
    """Handle VK OAuth callback."""
    # Parse body or query params
    body_str = event.get('body', '{}')
    if event.get('isBase64Encoded'):
        body_str = base64.b64decode(body_str).decode('utf-8')

    try:
        payload = json.loads(body_str) if body_str else {}
    except json.JSONDecodeError:
        payload = {}

    # Get code from body or query
    code = payload.get('code', '')
    if not code:
        query = event.get('queryStringParameters', {}) or {}
        code = query.get('code', '')

    if not code:
        return error(400, 'Authorization code is required', origin)

    client_id = os.environ.get('VK_CLIENT_ID', '')
    client_secret = os.environ.get('VK_CLIENT_SECRET', '')
    redirect_uri = os.environ.get('VK_REDIRECT_URI', '')

    if not client_id or not client_secret:
        return error(500, 'VK credentials not configured', origin)

    try:
        # Exchange code for token
        token_data = exchange_code_for_token(code, client_id, client_secret, redirect_uri)

        if 'error' in token_data:
            return error(400, token_data.get('error_description', 'VK auth failed'), origin)

        vk_access_token = token_data.get('access_token')
        vk_user_id = token_data.get('user_id')
        vk_email = token_data.get('email')  # May be None if user didn't grant email permission

        # Get user info
        user_info = get_vk_user_info(vk_access_token, vk_user_id)
        first_name = user_info.get('first_name', '')
        last_name = user_info.get('last_name', '')
        photo_url = user_info.get('photo_200', user_info.get('photo_100', ''))
        full_name = f"{first_name} {last_name}".strip()

        # Find or create user
        S = get_schema()
        conn = get_connection()

        try:
            cur = conn.cursor()
            now = datetime.utcnow().isoformat()

            # Check if user exists by vk_id
            cur.execute(f"SELECT id, email, name FROM {S}users WHERE vk_id = {escape(str(vk_user_id))}")
            row = cur.fetchone()

            if row:
                user_id, email, name = row
                # Update last login
                cur.execute(f"UPDATE {S}users SET last_login_at = {escape(now)}, updated_at = {escape(now)} WHERE id = {escape(user_id)}")
            else:
                # Create new user
                cur.execute(f"""
                    INSERT INTO {S}users (vk_id, email, name, avatar_url, email_verified, created_at, updated_at, last_login_at)
                    VALUES ({escape(str(vk_user_id))}, {escape(vk_email)}, {escape(full_name)}, {escape(photo_url)}, TRUE, {escape(now)}, {escape(now)}, {escape(now)})
                    RETURNING id
                """)
                user_id = cur.fetchone()[0]
                email = vk_email
                name = full_name

            # Create tokens
            access_token, expires_in = create_access_token(user_id, email)
            refresh_token = create_refresh_token()
            refresh_expires = (datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)).isoformat()

            # Store refresh token
            cur.execute(f"""
                INSERT INTO {S}refresh_tokens (user_id, token_hash, expires_at, created_at)
                VALUES ({escape(user_id)}, {escape(refresh_token)}, {escape(refresh_expires)}, {escape(now)})
            """)

            conn.commit()

            return response(200, {
                'access_token': access_token,
                'refresh_token': refresh_token,
                'expires_in': expires_in,
                'user': {
                    'id': user_id,
                    'email': email,
                    'name': name or full_name,
                    'avatar_url': photo_url,
                    'vk_id': str(vk_user_id)
                }
            }, origin)

        except Exception as e:
            conn.rollback()
            return error(500, str(e), origin)
        finally:
            conn.close()

    except HTTPError as e:
        error_body = e.read().decode() if e.fp else str(e)
        return error(500, f'VK API error: {error_body}', origin)
    except Exception as e:
        return error(500, str(e), origin)


def handle_refresh(event: dict, origin: str) -> dict:
    """Refresh access token."""
    body_str = event.get('body', '{}')
    if event.get('isBase64Encoded'):
        body_str = base64.b64decode(body_str).decode('utf-8')

    try:
        payload = json.loads(body_str)
    except json.JSONDecodeError:
        return error(400, 'Invalid JSON', origin)

    refresh_token = payload.get('refresh_token', '')
    if not refresh_token:
        return error(400, 'refresh_token is required', origin)

    S = get_schema()
    conn = get_connection()

    try:
        cur = conn.cursor()
        now = datetime.utcnow()

        # Find refresh token
        cur.execute(f"""
            SELECT rt.user_id, u.email, u.name, u.avatar_url, u.vk_id
            FROM {S}refresh_tokens rt
            JOIN {S}users u ON u.id = rt.user_id
            WHERE rt.token_hash = {escape(refresh_token)} AND rt.expires_at > {escape(now.isoformat())}
        """)

        row = cur.fetchone()
        if not row:
            return error(401, 'Invalid or expired refresh token', origin)

        user_id, email, name, avatar_url, vk_id = row

        # Create new access token
        access_token, expires_in = create_access_token(user_id, email)

        return response(200, {
            'access_token': access_token,
            'expires_in': expires_in,
            'user': {
                'id': user_id,
                'email': email,
                'name': name,
                'avatar_url': avatar_url,
                'vk_id': vk_id
            }
        }, origin)

    except Exception as e:
        return error(500, str(e), origin)
    finally:
        conn.close()


def handle_logout(event: dict, origin: str) -> dict:
    """Logout user by invalidating refresh token."""
    body_str = event.get('body', '{}')
    if event.get('isBase64Encoded'):
        body_str = base64.b64decode(body_str).decode('utf-8')

    try:
        payload = json.loads(body_str)
    except json.JSONDecodeError:
        return error(400, 'Invalid JSON', origin)

    refresh_token = payload.get('refresh_token', '')
    if refresh_token:
        S = get_schema()
        conn = get_connection()
        try:
            cur = conn.cursor()
            cur.execute(f"DELETE FROM {S}refresh_tokens WHERE token_hash = {escape(refresh_token)}")
            conn.commit()
        except Exception:
            pass
        finally:
            conn.close()

    return response(200, {'message': 'Logged out'}, origin)


# =============================================================================
# MAIN HANDLER
# =============================================================================

def handler(event, context):
    """Main handler - routes to specific handlers based on action."""
    # CORS preflight
    if event.get('httpMethod') == 'OPTIONS':
        return {'statusCode': 200, 'headers': HEADERS, 'body': ''}

    origin = get_origin(event)
    query = event.get('queryStringParameters', {}) or {}
    action = query.get('action', '')

    handlers = {
        'auth-url': handle_auth_url,
        'callback': handle_callback,
        'refresh': handle_refresh,
        'logout': handle_logout,
    }

    if action not in handlers:
        return error(400, f'Unknown action: {action}. Available: {", ".join(handlers.keys())}', origin)

    return handlers[action](event, origin)
