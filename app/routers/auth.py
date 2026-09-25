"""认证路由：登录、修改密码、获取当前用户信息。"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from ..auth import create_access_token, get_current_user, hash_password, verify_password
from ..database import get_db
from ..models import User
from ..schemas import LoginRequest, PasswordChangeRequest, TokenResponse, UserOut

router = APIRouter(prefix="/api/auth", tags=["认证"])


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == payload.username).first()
    # 用户不存在与密码校验失败（含哈希损坏）返回同一个 401，不泄露内部细节
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="用户名或密码错误",
        )
    token = create_access_token(user.username, user.token_version)
    return TokenResponse(access_token=token)


@router.post("/password")
def change_password(
    payload: PasswordChangeRequest,
    db: Session = Depends(get_db),
    current: User = Depends(get_current_user),
):
    """修改当前用户密码。

    成功后凭据版本号递增并持久化，此前签发的所有令牌立即失效。
    """
    if not verify_password(payload.old_password, current.password_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="原密码不正确",
        )
    current.password_hash = hash_password(payload.new_password)
    current.token_version += 1
    db.commit()
    return {"detail": "密码已更新，请使用新密码重新登录"}


@router.get("/me", response_model=UserOut)
def me(current: User = Depends(get_current_user)):
    return current
