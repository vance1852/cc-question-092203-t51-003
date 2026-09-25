"""应用配置。

所有可调参数集中在这里，纯后端服务，使用本地 SQLite，离线可运行。

环境变量：
- APP_ENV：运行环境（development / test / production），默认 development
- APP_SECRET_KEY：JWT 签名密钥（生产环境必须设置为强随机值）
- APP_ADMIN_USERNAME / APP_ADMIN_PASSWORD：首次启动引导的管理员凭据
- APP_PORT：服务端口
"""
import logging
import os

logger = logging.getLogger(__name__)

# 数据库文件路径（SQLite，本地文件，开箱即用）
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "data.db")
DATABASE_URL = f"sqlite:///{DB_PATH}"

# 运行环境：development / test / production（生产环境启用严格启动检查）
APP_ENV = os.getenv("APP_ENV", "development").strip().lower()
_PRODUCTION_ENVS = {"production", "prod"}

# JWT 配置
_DEV_SECRET_KEY = "swap-station-admin-dev-secret-key-change-me"
SECRET_KEY = os.getenv("APP_SECRET_KEY", _DEV_SECRET_KEY)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 12  # 12 小时

# 内置管理员账号（首次启动自动初始化，可用环境变量覆盖）
_DEV_ADMIN_PASSWORD = "admin123"
DEFAULT_ADMIN_USERNAME = os.getenv("APP_ADMIN_USERNAME", "admin")
DEFAULT_ADMIN_PASSWORD = os.getenv("APP_ADMIN_PASSWORD", _DEV_ADMIN_PASSWORD)

# 服务端口（使用非常见端口）
APP_PORT = int(os.getenv("APP_PORT", "7634"))

# 生产环境安全基线
_MIN_SECRET_LENGTH = 32
_MIN_ADMIN_PASSWORD_LENGTH = 12
_WEAK_SECRETS = {_DEV_SECRET_KEY, "secret", "changeme", "change-me", "jwt-secret"}
_WEAK_ADMIN_PASSWORDS = {_DEV_ADMIN_PASSWORD, "admin", "password", "123456", "admin1234"}


class ConfigError(RuntimeError):
    """启动配置不满足安全要求时抛出，应用应拒绝启动。"""


def validate_config() -> None:
    """启动前校验配置。

    生产环境缺少强签名密钥或仍使用默认/弱管理员口令时抛出 ConfigError，
    明确拒绝启动；开发与测试环境允许使用内置默认值，仅记录告警日志，
    保证显式选择的环境可以稳定运行。
    """
    problems = []
    if not SECRET_KEY or SECRET_KEY in _WEAK_SECRETS or len(SECRET_KEY) < _MIN_SECRET_LENGTH:
        problems.append(
            f"APP_SECRET_KEY 未设置或强度不足"
            f"（需至少 {_MIN_SECRET_LENGTH} 个字符的随机值，且不得使用内置默认值）"
        )
    if (
        not DEFAULT_ADMIN_PASSWORD
        or DEFAULT_ADMIN_PASSWORD in _WEAK_ADMIN_PASSWORDS
        or len(DEFAULT_ADMIN_PASSWORD) < _MIN_ADMIN_PASSWORD_LENGTH
    ):
        problems.append(
            f"APP_ADMIN_PASSWORD 未设置或仍为弱口令"
            f"（需至少 {_MIN_ADMIN_PASSWORD_LENGTH} 个字符，且不得使用默认口令）"
        )

    if APP_ENV not in _PRODUCTION_ENVS:
        if problems:
            logger.warning(
                "当前 APP_ENV=%s 正在使用内置开发配置（%s）；仅限本地开发/测试，禁止用于生产部署。",
                APP_ENV,
                "；".join(problems),
            )
        return

    if problems:
        raise ConfigError("生产环境配置不安全，拒绝启动：\n- " + "\n- ".join(problems))
