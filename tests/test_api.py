"""接口冒烟测试：覆盖认证、鉴权、CRUD、换电与统计，并校验中文编码。"""
import uuid
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from fastapi.testclient import TestClient

from app import config
from app.config import ALGORITHM, SECRET_KEY
from app.database import SessionLocal
from app.main import app
from app.models import User
from app.seed import init_db

init_db()
client = TestClient(app)


def _login() -> str:
    resp = client.post("/api/auth/login", json={"username": "admin", "password": "admin123"})
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


def _auth_headers() -> dict:
    return {"Authorization": f"Bearer {_login()}"}


def test_health():
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_login_wrong_password():
    resp = client.post("/api/auth/login", json={"username": "admin", "password": "bad"})
    assert resp.status_code == 401


def test_requires_auth():
    # 未带 token 访问受保护资源应被拦截
    resp = client.get("/api/stations")
    assert resp.status_code == 401


def test_me_and_chinese_encoding():
    resp = client.get("/api/auth/me", headers=_auth_headers())
    assert resp.status_code == 200
    # 中文显示名必须正确返回，验证 UTF-8 编码无乱码
    assert resp.json()["display_name"] == "平台管理员"


def test_seed_stations_present_with_chinese():
    resp = client.get("/api/stations", headers=_auth_headers())
    assert resp.status_code == 200
    stations = resp.json()
    assert len(stations) >= 4
    assert any("换电站" in s["name"] for s in stations)


def test_station_crud_and_validation():
    headers = _auth_headers()
    # 非法数据：满电电池数 > 仓位总数
    bad = client.post("/api/stations", json={"name": "测试站", "slot_total": 2, "battery_ready": 5}, headers=headers)
    assert bad.status_code == 422

    created = client.post(
        "/api/stations",
        json={"name": "西站测试换电站", "address": "测试路 1 号", "slot_total": 10, "battery_ready": 6},
        headers=headers,
    )
    assert created.status_code == 201, created.text
    sid = created.json()["id"]
    assert created.json()["name"] == "西站测试换电站"

    updated = client.put(f"/api/stations/{sid}", json={"status": "maintenance"}, headers=headers)
    assert updated.status_code == 200
    assert updated.json()["status"] == "maintenance"

    deleted = client.delete(f"/api/stations/{sid}", headers=headers)
    assert deleted.status_code == 204
    assert client.get(f"/api/stations/{sid}", headers=headers).status_code == 404


def test_vehicle_unique_plate():
    headers = _auth_headers()
    plate = f"测{uuid.uuid4().hex[:6]}"
    first = client.post("/api/vehicles", json={"plate": plate, "model": "测试车型"}, headers=headers)
    assert first.status_code == 201, first.text
    dup = client.post("/api/vehicles", json={"plate": plate}, headers=headers)
    assert dup.status_code == 409


def test_swap_flow_updates_state():
    headers = _auth_headers()
    # 取一个有满电电池的运营站
    stations = client.get("/api/stations", headers=headers).json()
    station = next(s for s in stations if s["battery_ready"] > 0)
    plate = f"沪EV{uuid.uuid4().hex[:4]}"
    vehicle = client.post(
        "/api/vehicles", json={"plate": plate, "model": "换电测试车", "current_soc": 10.0}, headers=headers
    ).json()

    before_ready = station["battery_ready"]
    swap = client.post(
        "/api/swaps",
        json={"vehicle_id": vehicle["id"], "station_id": station["id"], "soc_before": 10.0, "soc_after": 100.0},
        headers=headers,
    )
    assert swap.status_code == 201, swap.text
    assert swap.json()["station_name"] == station["name"]

    # 车辆电量应更新、站点可用电池应减一
    v_after = client.get(f"/api/vehicles/{vehicle['id']}", headers=headers).json()
    assert v_after["current_soc"] == 100.0
    s_after = client.get(f"/api/stations/{station['id']}", headers=headers).json()
    assert s_after["battery_ready"] == before_ready - 1


def test_swap_invalid_soc():
    headers = _auth_headers()
    stations = client.get("/api/stations", headers=headers).json()
    station = next(s for s in stations if s["battery_ready"] > 0)
    vehicles = client.get("/api/vehicles", headers=headers).json()
    bad = client.post(
        "/api/swaps",
        json={"vehicle_id": vehicles[0]["id"], "station_id": station["id"], "soc_before": 90.0, "soc_after": 50.0},
        headers=headers,
    )
    assert bad.status_code == 422


def test_dashboard_stats():
    resp = client.get("/api/dashboard/stats", headers=_auth_headers())
    assert resp.status_code == 200
    data = resp.json()
    assert data["station_total"] >= 4
    assert data["vehicle_total"] >= 5
    assert "battery_ready_total" in data


# ---------- 认证链路加固 ----------

def _admin_user(db):
    return db.query(User).filter(User.username == "admin").first()


def test_login_with_corrupted_password_hash():
    # 磁盘损坏把哈希改成非 hex / 未知编码内容时，登录只能得到统一的 401，不得抛出 500
    db = SessionLocal()
    user = _admin_user(db)
    original_hash = user.password_hash
    try:
        for corrupted in (
            "not-hex-garbage!!",      # 无分隔符的非 hex 内容
            "abcd$not-hex!!",         # 哈希段不是合法 hex
            "not-hex!!$abcd",         # 盐段不是合法 hex
            "中文哈希$损坏内容",        # 未知编码内容
            "$",                      # 空盐空哈希
        ):
            user.password_hash = corrupted
            db.commit()
            resp = client.post("/api/auth/login", json={"username": "admin", "password": "admin123"})
            assert resp.status_code == 401, corrupted
            assert resp.json()["detail"] == "用户名或密码错误"
    finally:
        user.password_hash = original_hash
        db.commit()
        db.close()
    # 恢复后正常登录不受影响
    assert _login()


def test_invalid_tokens_uniformly_rejected():
    # 畸形 / 伪造 / 过期的令牌统一 401，且不泄露内部解析细节
    for bad in ("not-a-jwt", "aaa.bbb.ccc", "e30.e30.sig"):
        resp = client.get("/api/auth/me", headers={"Authorization": f"Bearer {bad}"})
        assert resp.status_code == 401, bad
        assert resp.json()["detail"] == "登录状态无效或已过期"

    future = datetime.now(timezone.utc) + timedelta(minutes=5)
    # 错误密钥签发
    forged = jwt.encode({"sub": "admin", "ver": 0, "exp": future}, "wrong-secret", algorithm="HS256")
    resp = client.get("/api/auth/me", headers={"Authorization": f"Bearer {forged}"})
    assert resp.status_code == 401
    # 正确密钥但缺少凭据版本（旧格式令牌）
    legacy = jwt.encode({"sub": "admin", "exp": future}, SECRET_KEY, algorithm=ALGORITHM)
    resp = client.get("/api/auth/me", headers={"Authorization": f"Bearer {legacy}"})
    assert resp.status_code == 401
    # 已过期令牌
    expired = jwt.encode(
        {"sub": "admin", "ver": 0, "exp": datetime.now(timezone.utc) - timedelta(minutes=1)},
        SECRET_KEY,
        algorithm=ALGORITHM,
    )
    resp = client.get("/api/auth/me", headers={"Authorization": f"Bearer {expired}"})
    assert resp.status_code == 401


def test_token_carries_credential_version():
    payload = jwt.decode(_login(), SECRET_KEY, algorithms=[ALGORITHM])
    assert payload["sub"] == "admin"
    assert isinstance(payload["ver"], int)


def test_password_change_invalidates_old_tokens():
    old_token = _login()
    old_headers = {"Authorization": f"Bearer {old_token}"}
    assert client.get("/api/auth/me", headers=old_headers).status_code == 200

    db = SessionLocal()
    user = _admin_user(db)
    original_hash, original_version = user.password_hash, user.token_version
    db.close()
    try:
        # 原密码错误时拒绝修改
        bad = client.post(
            "/api/auth/change-password",
            json={"old_password": "wrong", "new_password": "NewPassw0rd!"},
            headers=old_headers,
        )
        assert bad.status_code == 400
        # 新密码太弱时拒绝修改
        weak = client.post(
            "/api/auth/change-password",
            json={"old_password": "admin123", "new_password": "short"},
            headers=old_headers,
        )
        assert weak.status_code == 422

        resp = client.post(
            "/api/auth/change-password",
            json={"old_password": "admin123", "new_password": "NewPassw0rd!"},
            headers=old_headers,
        )
        assert resp.status_code == 200, resp.text
        # 旧令牌立即失效
        assert client.get("/api/auth/me", headers=old_headers).status_code == 401
        # 旧密码不能再登录
        assert client.post("/api/auth/login", json={"username": "admin", "password": "admin123"}).status_code == 401
        # 新凭据可正常登录，新令牌可访问当前用户接口
        new_token_resp = client.post("/api/auth/login", json={"username": "admin", "password": "NewPassw0rd!"})
        assert new_token_resp.status_code == 200
        new_headers = {"Authorization": f"Bearer {new_token_resp.json()['access_token']}"}
        me = client.get("/api/auth/me", headers=new_headers)
        assert me.status_code == 200
        assert me.json()["username"] == "admin"
    finally:
        # 恢复初始凭据与凭据版本，保证其他用例稳定
        db = SessionLocal()
        user = _admin_user(db)
        user.password_hash = original_hash
        user.token_version = original_version
        db.commit()
        db.close()


def test_startup_config_validation(monkeypatch):
    # 开发/测试环境：内置默认值允许启动，但必须给出告警提示运维
    monkeypatch.setattr(config, "APP_ENV", "development")
    monkeypatch.setattr(config, "SECRET_KEY", config.DEV_SECRET_KEY)
    monkeypatch.setattr(config, "DEFAULT_ADMIN_PASSWORD", config.DEV_ADMIN_PASSWORD)
    warnings = config.validate_startup_config()
    assert len(warnings) == 2

    # 生产环境：缺少强密钥（仍用内置开发密钥）→ 明确拒绝启动
    monkeypatch.setattr(config, "APP_ENV", "production")
    with pytest.raises(config.StartupConfigError):
        config.validate_startup_config()

    # 生产环境：强密钥但仍是默认管理员凭据 → 明确拒绝启动
    monkeypatch.setattr(config, "SECRET_KEY", "prod-secret-" + "x" * 40)
    with pytest.raises(config.StartupConfigError):
        config.validate_startup_config()

    # 生产环境：强密钥 + 强初始口令 → 通过且无告警
    monkeypatch.setattr(config, "DEFAULT_ADMIN_PASSWORD", "S3cure-Admin-Pass")
    assert config.validate_startup_config() == []
