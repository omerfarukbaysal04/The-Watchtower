import os
import hashlib
from datetime import datetime, timedelta
from functools import wraps

from fastapi import Request
from fastapi.responses import RedirectResponse
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

# .env'den oku
SECRET_KEY      = os.getenv("SECRET_KEY", "fallback-secret")
ADMIN_USERNAME  = os.getenv("ADMIN_USERNAME", "admin")
raw_hash = os.getenv("ADMIN_PASSWORD_HASH", "")
ADMIN_HASH = raw_hash.replace("\\$", "$")

SESSION_COOKIE  = "wt_session"
SESSION_MAX_AGE = 60 * 60 * 8  # 8 saat

serializer = URLSafeTimedSerializer(SECRET_KEY)


def verify_password(plain: str, hashed: str) -> bool:
    try:
        salt = 'watchtower'
        h = hashlib.sha256(f'{salt}{plain}'.encode()).hexdigest()
        return h == hashed
    except Exception:
        return False


def create_session(username: str) -> str:
    """İmzalı session token üretir."""
    return serializer.dumps(username)


def verify_session(token: str) -> str | None:
    """Token geçerliyse username döner, değilse None."""
    try:
        username = serializer.loads(token, max_age=SESSION_MAX_AGE)
        return username
    except (BadSignature, SignatureExpired):
        return None


def get_current_user(request: Request) -> str | None:
    """Cookie'den kullanıcıyı okur."""
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    return verify_session(token)


def login_required(func):
    """Route'lara eklenecek decorator."""
    @wraps(func)
    async def wrapper(request: Request, *args, **kwargs):
        user = get_current_user(request)
        if not user:
            return RedirectResponse(url="/login", status_code=302)
        return await func(request, *args, **kwargs)
    return wrapper


