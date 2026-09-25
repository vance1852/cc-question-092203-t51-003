"""认证相关：密码哈希、JWT 签发与校验、当前用户依赖。

密码哈希使用标准库 hashlib.pbkdf2_hmac，无需额外依赖，跨平台稳定。
JWT 携带凭据版本号（ver 声明），与用户表中的 token_version 比对，
密码重置后旧令牌立即失效。
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

    存储内容损坏（非十六进制、缺分隔符、未知编码、类型异常等）时一律
    返回 False，绝不向上抛出解析异常，由调用方统一按认证失败处理。
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
    """为给定用户名签发 JWT，绑定当前凭据版本号。"""
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {"sub": subject, "exp": expire, "ver": token_version}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    """从 Bearer Token 解析并返回当前用户。

    令牌伪造、过期、缺声明、凭据版本失效等任何校验失败都抛出同一个
    401，不向调用方泄露具体失败原因。
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="登录状态无效或已过期",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.PyJWTError:
        raise credentials_exception

    username = payload.get("sub")
    version = payload.get("ver")
    if not isinstance(username, str) or not username or not isinstance(version, int):
        raise credentials_exception

    user = db.query(User).filter(User.username == username).first()
    if user is None or user.token_version != version:
        raise credentials_exception
    return user
