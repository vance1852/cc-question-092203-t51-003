"""认证安全加固测试：损坏哈希、无效令牌、启动配置检查、凭据版本失效。"""
import jwt as pyjwt
import pytest
from fastapi.testclient import TestClient

from app import config
from app.auth import create_access_token, hash_password, verify_password
from app.database import SessionLocal
from app.main import app
from app.models import User
from app.seed import init_db

init_db()
client = TestClient(app)

_CORRUPT_USERNAME = "corrupt-hash-case"


def _login(username: str = "admin", password: str = "admin123") -> str:
    resp = client.post("/api/auth/login", json={"username": username, "password": password})
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


def _me(token: str):
    return client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})


def _get_user(username: str) -> User:
    db = SessionLocal()
    try:
        return db.query(User).filter(User.username == username).first()
    finally:
        db.close()


@pytest.fixture
def corrupt_user():
    """提供一个一次性的测试用户，用例可随意破坏其哈希，结束后清理。"""
    db = SessionLocal()
    try:
        db.query(User).filter(User.username == _CORRUPT_USERNAME).delete()
        db.add(
            User(
                username=_CORRUPT_USERNAME,
                password_hash=hash_password("s3cret-password"),
                display_name="损坏哈希演练账号",
            )
        )
        db.commit()
    finally:
        db.close()
    yield _CORRUPT_USERNAME
    db = SessionLocal()
    try:
        db.query(User).filter(User.username == _CORRUPT_USERNAME).delete()
        db.commit()
    finally:
        db.close()


def _set_hash(username: str, stored) -> None:
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        user.password_hash = stored
        db.commit()
    finally:
        db.close()


# ---------- 损坏哈希 / 未知编码：统一拒绝，不泄露内部异常 ----------

def test_verify_password_tolerates_corrupted_storage():
    good = hash_password("pw")
    assert verify_password("pw", good) is True
    assert verify_password("nope", good) is False
    # 磁盘损坏演练中可能出现的各种脏数据：一律返回 False，不抛异常
    for bad in ["!!not-hex!!", "no-separator", "", "$", "zz$00", "aa$bb$cc", "  $  ", None, b"\xff\xfe"]:
        assert verify_password("pw", bad) is False


def test_login_with_corrupted_hash_returns_uniform_401(corrupt_user):
    for bad_hash in ["!!not-hex!!", "garbage-without-separator", "", "00$zz"]:
        _set_hash(corrupt_user, bad_hash)
        resp = client.post(
            "/api/auth/login", json={"username": corrupt_user, "password": "s3cret-password"}
        )
        # 不是 500，响应体与密码错误完全一致，不泄露解析细节
        assert resp.status_code == 401, resp.text
        assert resp.json() == {"detail": "用户名或密码错误"}


# ---------- 无效令牌：统一 401 ----------

def test_garbage_tokens_rejected_uniformly():
    for token in ["not-a-token", "aaa.bbb.ccc", "eyJhbGciOiJIUzI1NiJ9.bad.sig"]:
        resp = _me(token)
        assert resp.status_code == 401
        assert resp.json() == {"detail": "登录状态无效或已过期"}


def test_token_signed_with_wrong_key_rejected():
    token = pyjwt.encode({"sub": "admin", "ver": 1}, "attacker-controlled-key", algorithm="HS256")
    resp = _me(token)
    assert resp.status_code == 401
    assert resp.json() == {"detail": "登录状态无效或已过期"}


def test_token_without_version_claim_rejected():
    # 旧格式令牌（无凭据版本声明）一律视为无效
    token = pyjwt.encode({"sub": "admin"}, config.SECRET_KEY, algorithm="HS256")
    resp = _me(token)
    assert resp.status_code == 401
    assert resp.json() == {"detail": "登录状态无效或已过期"}


def test_token_with_stale_version_rejected():
    token = create_access_token("admin", 999_999)
    resp = _me(token)
    assert resp.status_code == 401
    assert resp.json() == {"detail": "登录状态无效或已过期"}


# ---------- 密码重置：旧令牌按持久化的凭据版本立即失效 ----------

def test_password_change_invalidates_old_tokens():
    token_v1 = _login()
    assert _me(token_v1).status_code == 200
    version_before = _get_user("admin").token_version

    new_password = "NewPassw0rd!2026"
    try:
        resp = client.post(
            "/api/auth/password",
            json={"old_password": "admin123", "new_password": new_password},
            headers={"Authorization": f"Bearer {token_v1}"},
        )
        assert resp.status_code == 200, resp.text

        # 旧令牌立即失效，凭据版本已持久化递增
        stale = _me(token_v1)
        assert stale.status_code == 401
        assert stale.json() == {"detail": "登录状态无效或已过期"}
        assert _get_user("admin").token_version == version_before + 1

        # 旧密码不能再登录，新密码可以正常登录并保持 /me 契约
        assert client.post(
            "/api/auth/login", json={"username": "admin", "password": "admin123"}
        ).status_code == 401
        token_v2 = _login(password=new_password)
        me = _me(token_v2)
        assert me.status_code == 200
        assert me.json()["username"] == "admin"
        assert me.json()["display_name"] == "平台管理员"
    finally:
        # 恢复默认口令，保证其他用例不受影响
        token_new = _login(password=new_password)
        client.post(
            "/api/auth/password",
            json={"old_password": new_password, "new_password": "admin123"},
            headers={"Authorization": f"Bearer {token_new}"},
        )


def test_password_change_wrong_old_password():
    token = _login()
    resp = client.post(
        "/api/auth/password",
        json={"old_password": "wrong-password", "new_password": "whatever-123"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 400
    # 密码未被修改，原令牌仍然有效
    assert _me(token).status_code == 200


def test_password_change_weak_new_password_rejected():
    token = _login()
    resp = client.post(
        "/api/auth/password",
        json={"old_password": "admin123", "new_password": "short"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 422


def test_password_change_requires_auth():
    resp = client.post(
        "/api/auth/password", json={"old_password": "admin123", "new_password": "whatever-123"}
    )
    assert resp.status_code == 401


# ---------- 启动配置检查 ----------

def _set_prod(monkeypatch, secret, admin_password):
    monkeypatch.setattr(config, "APP_ENV", "production")
    monkeypatch.setattr(config, "SECRET_KEY", secret)
    monkeypatch.setattr(config, "DEFAULT_ADMIN_PASSWORD", admin_password)


def test_validate_config_development_allows_defaults():
    # 当前测试进程即为开发环境默认配置，必须能稳定运行
    config.validate_config()


def test_validate_config_production_rejects_default_secret(monkeypatch):
    _set_prod(monkeypatch, "swap-station-admin-dev-secret-key-change-me", "Str0ng!Passw0rd-2026")
    with pytest.raises(config.ConfigError):
        config.validate_config()


def test_validate_config_production_rejects_missing_secret(monkeypatch):
    _set_prod(monkeypatch, "", "Str0ng!Passw0rd-2026")
    with pytest.raises(config.ConfigError):
        config.validate_config()


def test_validate_config_production_rejects_default_admin_password(monkeypatch):
    _set_prod(monkeypatch, "k" * 48, "admin123")
    with pytest.raises(config.ConfigError):
        config.validate_config()


def test_validate_config_production_accepts_strong_values(monkeypatch):
    _set_prod(monkeypatch, "k" * 48, "Str0ng!Passw0rd-2026")
    config.validate_config()


def test_app_refuses_to_start_with_insecure_production_config(monkeypatch):
    _set_prod(monkeypatch, "swap-station-admin-dev-secret-key-change-me", "admin123")
    with pytest.raises(config.ConfigError):
        with TestClient(app):
            pass
