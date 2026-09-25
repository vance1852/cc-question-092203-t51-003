"""认证相关：密码哈希、JWT 签发与校验、当前用户依赖。

密码哈希使用标准库 hashlib.pbkdf2_hmac，无需额外依赖，跨平台稳定。
"""
import hashlib
import hmac
import os
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from .config import ACCESS_TOKEN_EXPIRE_MINUTES, ALGORITHM, SECRET_KEY
from .database import get_db
from .models import User

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/auth/login")

_PBKDF2_ROUNDS = 120_000


def hash_password(password: str) -> str:
    """生成 'salt$hash' 形式的密码哈希。"""
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _PBKDF2_ROUNDS)
    return f"{salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """校验明文密码与存储的哈希是否匹配。

    存储内容损坏（非 hex、缺少分隔符、编码异常等）时一律按不匹配处理，
    绝不把解析异常抛给调用方。
    """
    try:
        salt_hex, hash_hex = stored.split("$", 1)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
    except (AttributeError, TypeError, ValueError):
        return False
    if not salt or not expected:
        return False
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _PBKDF2_ROUNDS)
    return hmac.compare_digest(digest, expected)


def create_access_token(subject: str, token_version: int) -> str:
    """为给定用户签发携带凭据版本的 JWT。"""
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {"sub": subject, "ver": token_version, "exp": expire}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    """从 Bearer Token 解析并返回当前用户。

    令牌伪造、过期、编码异常或凭据版本过旧时统一返回 401，
    不向调用方泄露内部解析细节。
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="登录状态无效或已过期",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except Exception:
        # 畸形输入可能触发 PyJWTError 之外的解析异常，统一按无效令牌拒绝
        raise credentials_exception
    username = payload.get("sub")
    token_version = payload.get("ver")
    if not isinstance(username, str) or not username:
        raise credentials_exception
    if not isinstance(token_version, int) or isinstance(token_version, bool):
        raise credentials_exception

    user = db.query(User).filter(User.username == username).first()
    if user is None or user.token_version != token_version:
        raise credentials_exception
    return user
