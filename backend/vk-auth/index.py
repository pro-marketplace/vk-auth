"""VK OAuth authentication handler with PKCE."""
import json
import os
import secrets
import base64
import hashlib
from datetime import datetime, timedelta, timezone
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


def cleanup_expired_tokens(cur, schema: str) -> None:
    """Delete expired refresh tokens."""
    now = datetime.now(timezone.utc).isoformat()
    cur.execute(f"DELETE FROM {schema}refresh_tokens WHERE expires_at < %s", (now,))


# =============================================================================
# SECURITY
# =============================================================================

def hash_token(token: str) -> str:
    """Hash token with SHA256 for secure storage."""
    return hashlib.sha256(token.encode('utf-8')).hexdigest()


def get_jwt_secret() -> str:
    """Get JWT secret with validation."""
    secret = os.environ.get('JWT_SECRET', '')
    if not secret or len(secret) < 32:
        raise ValueError('JWT_SECRET must be at least 32 characters')
    return secret


# =============================================================================
# JWT
# =============================================================================

def create_access_token(user_id: int, email: str | None = None) -> tuple[str, int]:
    """Create JWT access token."""
    secret = get_jwt_secret()
    expires_delta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    now = datetime.now(timezone.utc)
    expire = now + expires_delta

    payload = {
        'sub': str(user_id),
        'exp': expire,
        'iat': now,
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
    device_id: str | None = None
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
            return {'error': 'http_error', 'error_description': 'VK API request failed'}


def get_vk_user_info(access_token: str, client_id: str) -> dict:
    """Get user info from VK ID API (POST method)."""
    data = {
        'access_token': access_token,
        'client_id': client_id
    }

    request = Request(
        VK_USER_INFO_URL,
        data=urlencode(data).encode('utf-8'),
        headers={'Content-Type': 'application/x-www-form-urlencoded'},
        method='POST'
    )

    with urlopen(request, timeout=10) as response:
        result = json.loads(response.read().decode())
        return result.get('user', {})


# =============================================================================
# HELPERS
# =============================================================================

def get_allowed_origins() -> list[str]:
    """Get list of allowed origins from environment."""
    origins = os.environ.get('ALLOWED_ORIGINS', '')
    if origins:
        return [o.strip() for o in origins.split(',')]
    return []


def is_origin_allowed(origin: str) -> bool:
    """Check if origin is allowed."""
    allowed = get_allowed_origins()
    if not allowed:
        return True  # No restrictions if not configured
    return origin in allowed


def response(status_code: int, body: dict, origin: str = '*') -> dict:
    """Create HTTP response."""
    headers = HEADERS.copy()
    # Use specific origin if allowed, otherwise deny
    if origin != '*' and is_origin_allowed(origin):
        headers['Access-Control-Allow-Origin'] = origin
    elif not get_allowed_origins():
        headers['Access-Control-Allow-Origin'] = origin if origin != '*' else '*'
    else:
        headers['Access-Control-Allow-Origin'] = 'null'

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
        return error(500, 'Server configuration error', origin)

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
        return error(500, 'Server configuration error', origin)

    try:
        # Validate JWT_SECRET early
        get_jwt_secret()
    except ValueError:
        return error(500, 'Server configuration error', origin)

    try:
        # Exchange code for token with PKCE
        token_data = exchange_code_for_token(
            code, client_id, client_secret, redirect_uri, code_verifier, device_id
        )

        if 'error' in token_data:
            return error(400, token_data.get('error_description', 'VK auth failed'), origin)

        vk_access_token = token_data.get('access_token')

        # Get user info from VK ID API
        user_info = get_vk_user_info(vk_access_token, client_id)

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
            now = datetime.now(timezone.utc).isoformat()

            # Cleanup expired tokens periodically
            cleanup_expired_tokens(cur, S)

            # 1. Check if user exists by vk_id
            cur.execute(
                f"SELECT id, email, name, avatar_url FROM {S}users WHERE vk_id = %s",
                (str(vk_user_id),)
            )
            row = cur.fetchone()

            if row:
                # User found by vk_id - just login
                user_id, email, name, db_avatar = row
                cur.execute(
                    f"UPDATE {S}users SET last_login_at = %s, updated_at = %s WHERE id = %s",
                    (now, now, user_id)
                )
                email = email or vk_email
                name = name or full_name
                photo_url = db_avatar or photo_url
            else:
                # 2. Check if user exists by email - link VK account
                if vk_email:
                    cur.execute(
                        f"SELECT id, name, avatar_url FROM {S}users WHERE email = %s",
                        (vk_email,)
                    )
                    row = cur.fetchone()

                if vk_email and row:
                    # User found by email - link VK account
                    user_id, db_name, db_avatar = row
                    cur.execute(
                        f"""UPDATE {S}users
                            SET vk_id = %s, avatar_url = COALESCE(avatar_url, %s),
                                last_login_at = %s, updated_at = %s
                            WHERE id = %s""",
                        (str(vk_user_id), photo_url, now, now, user_id)
                    )
                    email = vk_email
                    name = db_name or full_name
                    photo_url = db_avatar or photo_url
                else:
                    # 3. Create new user
                    cur.execute(
                        f"""INSERT INTO {S}users
                            (vk_id, email, name, avatar_url, email_verified, created_at, updated_at, last_login_at)
                            VALUES (%s, %s, %s, %s, TRUE, %s, %s, %s)
                            RETURNING id""",
                        (str(vk_user_id), vk_email, full_name, photo_url, now, now, now)
                    )
                    user_id = cur.fetchone()[0]
                    email = vk_email
                    name = full_name

            # Create tokens
            access_token, expires_in = create_access_token(user_id, email)
            refresh_token = create_refresh_token()
            refresh_token_hash = hash_token(refresh_token)
            refresh_expires = (datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)).isoformat()

            # Store hashed refresh token
            cur.execute(
                f"""INSERT INTO {S}refresh_tokens (user_id, token_hash, expires_at, created_at)
                    VALUES (%s, %s, %s, %s)""",
                (user_id, refresh_token_hash, refresh_expires, now)
            )

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

        except Exception:
            conn.rollback()
            return error(500, 'Database error', origin)
        finally:
            conn.close()

    except HTTPError:
        return error(500, 'VK API error', origin)
    except Exception:
        return error(500, 'Internal server error', origin)


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

    try:
        get_jwt_secret()
    except ValueError:
        return error(500, 'Server configuration error', origin)

    S = get_schema()
    conn = get_connection()

    try:
        cur = conn.cursor()
        now = datetime.now(timezone.utc)

        # Cleanup expired tokens
        cleanup_expired_tokens(cur, S)

        # Hash the provided token to compare with stored hash
        token_hash = hash_token(refresh_token)

        cur.execute(
            f"""SELECT rt.user_id, u.email, u.name, u.avatar_url, u.vk_id
                FROM {S}refresh_tokens rt
                JOIN {S}users u ON u.id = rt.user_id
                WHERE rt.token_hash = %s AND rt.expires_at > %s""",
            (token_hash, now.isoformat())
        )

        row = cur.fetchone()
        if not row:
            conn.commit()  # Commit cleanup
            return error(401, 'Invalid or expired refresh token', origin)

        user_id, email, name, avatar_url, vk_id = row

        access_token, expires_in = create_access_token(user_id, email)

        conn.commit()

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

    except Exception:
        return error(500, 'Internal server error', origin)
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
            token_hash = hash_token(refresh_token)
            cur.execute(
                f"DELETE FROM {S}refresh_tokens WHERE token_hash = %s",
                (token_hash,)
            )
            # Also cleanup expired tokens
            cleanup_expired_tokens(cur, S)
            conn.commit()
        except Exception:
            pass
        finally:
            conn.close()

    return response(200, {'message': 'Logged out'}, origin)


# =============================================================================
# MAIN HANDLER
# =============================================================================

def handler(event: dict, context) -> dict:
    """Main handler - routes to specific handlers based on action."""
    origin = get_origin(event)

    if event.get('httpMethod') == 'OPTIONS':
        headers = HEADERS.copy()
        headers['Access-Control-Allow-Origin'] = origin if origin != '*' else '*'
        return {'statusCode': 200, 'headers': headers, 'body': ''}

    query = event.get('queryStringParameters', {}) or {}
    action = query.get('action', '')

    handlers = {
        'auth-url': handle_auth_url,
        'callback': handle_callback,
        'refresh': handle_refresh,
        'logout': handle_logout,
    }

    if action not in handlers:
        return error(400, f'Unknown action: {action}', origin)

    return handlers[action](event, origin)
