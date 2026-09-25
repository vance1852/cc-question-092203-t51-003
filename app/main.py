"""应用入口。

新能源物流车换电站运营管理平台 —— 纯后端 API 服务。
"""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from .config import APP_ENV, validate_startup_config
from .routers import auth, dashboard, stations, swaps, vehicles
from .seed import init_db

logger = logging.getLogger("app.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logging.basicConfig(level=logging.INFO)
    # 启动配置安全检查：生产环境缺少强密钥或仍是默认凭据时抛错，明确拒绝启动
    warnings = validate_startup_config()
    for item in warnings:
        logger.warning("启动配置告警：%s", item)
    logger.info("启动配置检查完成（环境：%s）", APP_ENV)
    # 启动时初始化数据库（建表 + 种子数据）
    init_db()
    yield


app = FastAPI(
    title="换电站运营管理平台 API",
    description="新能源物流车换电站后台管理（纯后端）。",
    version="1.0.0",
    lifespan=lifespan,
)


@app.get("/api/health", tags=["系统"])
def health():
    return {"status": "ok", "service": "swap-station-admin"}


app.include_router(auth.router)
app.include_router(stations.router)
app.include_router(vehicles.router)
app.include_router(swaps.router)
app.include_router(dashboard.router)
