"""VK OAuth authentication handler with PKCE."""
import json
import os
import secrets
import base64
import hashlib
from datetime import datetime, timedelta
from urllib.request import Request, urlopen
from urllib.parse import urlencode
from urllib.error import HTTPError

import jwt
import psycopg2

# =============================================================================
# CONSTANTS
# =============================================================================

VK_AUTHORIZE_URL = "https://id.vk.com/authorize"
VK_TOKEN_URL = "https://id.vk.com/oauth2/auth"
VK_USER_INFO_URL = "https://id.vk.com/oauth2/user_info"

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

def get_vk_auth_url(client_id: str, redirect_uri: str, state: str, code_challenge: str) -> str:
    """Generate VK ID authorization URL with PKCE."""
    params = {
        'client_id': client_id,
        'redirect_uri': redirect_uri,
        'response_type': 'code',
        'scope': 'email',
        'state': state,
        'code_challenge': code_challenge,
        'code_challenge_method': 'S256'
    }
    return f"{VK_AUTHORIZE_URL}?{urlencode(params)}"


def exchange_code_for_token(
    code: str,
    client_id: str,
    client_secret: str,
    redirect_uri: str,
    code_verifier: str,
    device_id: str = None
) -> dict:
    """Exchange authorization code for access token with PKCE."""
    data = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': redirect_uri,
        'client_id': client_id,
        'client_secret': client_secret,
        'code_verifier': code_verifier
    }

    if device_id:
        data['device_id'] = device_id

    request = Request(
        VK_TOKEN_URL,
        data=urlencode(data).encode('utf-8'),
        headers={'Content-Type': 'application/x-www-form-urlencoded'},
        method='POST'
    )

    try:
        with urlopen(request, timeout=10) as response:
            return json.loads(response.read().decode())
    except HTTPError as e:
        error_body = e.read().decode()
        try:
            return json.loads(error_body)
        except json.JSONDecodeError:
            return {'error': 'http_error', 'error_description': error_body}


def get_vk_user_info(access_token: str) -> dict:
    """Get user info from VK ID API."""
    request = Request(
        VK_USER_INFO_URL,
        headers={'Authorization': f'Bearer {access_token}'},
        method='GET'
    )

    with urlopen(request, timeout=10) as response:
        data = json.loads(response.read().decode())
        return data.get('user', {})


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
    """Generate VK authorization URL with PKCE."""
    client_id = os.environ.get('VK_CLIENT_ID', '')
    redirect_uri = os.environ.get('VK_REDIRECT_URI', '')

    if not client_id or not redirect_uri:
        return error(500, 'VK credentials not configured', origin)

    # Generate state for CSRF protection
    state = secrets.token_urlsafe(16)

    # Generate PKCE code_verifier and code_challenge
    code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode('utf-8')).digest()
    ).decode('utf-8').rstrip('=')

    auth_url = get_vk_auth_url(client_id, redirect_uri, state, code_challenge)

    return response(200, {
        'auth_url': auth_url,
        'state': state,
        'code_verifier': code_verifier
    }, origin)


def handle_callback(event: dict, origin: str) -> dict:
    """Handle VK OAuth callback with PKCE."""
    # Parse body
    body_str = event.get('body', '{}')
    if event.get('isBase64Encoded'):
        body_str = base64.b64decode(body_str).decode('utf-8')

    try:
        payload = json.loads(body_str) if body_str else {}
    except json.JSONDecodeError:
        payload = {}

    # Get code, code_verifier, and device_id
    code = payload.get('code', '')
    code_verifier = payload.get('code_verifier', '')
    device_id = payload.get('device_id', '')

    if not code:
        query = event.get('queryStringParameters', {}) or {}
        code = query.get('code', '')
        code_verifier = query.get('code_verifier', '')
        device_id = query.get('device_id', '')

    if not code:
        return error(400, 'Authorization code is required', origin)

    if not code_verifier:
        return error(400, 'Code verifier is required', origin)

    client_id = os.environ.get('VK_CLIENT_ID', '')
    client_secret = os.environ.get('VK_CLIENT_SECRET', '')
    redirect_uri = os.environ.get('VK_REDIRECT_URI', '')

    if not client_id or not client_secret:
        return error(500, 'VK credentials not configured', origin)

    try:
        # Exchange code for token with PKCE
        token_data = exchange_code_for_token(
            code, client_id, client_secret, redirect_uri, code_verifier, device_id
        )

        if 'error' in token_data:
            return error(400, token_data.get('error_description', 'VK auth failed'), origin)

        vk_access_token = token_data.get('access_token')

        # Get user info from VK ID API
        user_info = get_vk_user_info(vk_access_token)

        vk_user_id = user_info.get('user_id', user_info.get('id', ''))
        first_name = user_info.get('first_name', '')
        last_name = user_info.get('last_name', '')
        vk_email = user_info.get('email')
        photo_url = user_info.get('avatar', '')
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
                cur.execute(f"""
                    UPDATE {S}users
                    SET last_login_at = {escape(now)}, updated_at = {escape(now)}
                    WHERE id = {escape(user_id)}
                """)
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
