"""应用配置。

所有可调参数集中在这里，纯后端服务，使用本地 SQLite，离线可运行。

环境变量：
- APP_ENV：运行环境，development（默认）/ test / production
- APP_SECRET_KEY：JWT 签名密钥；生产环境必须显式配置为强随机值
- APP_ADMIN_USERNAME：首次引导的管理员用户名（默认 admin）
- APP_ADMIN_PASSWORD：首次引导的管理员初始密码；生产环境必须显式配置为非默认强口令
"""
import os

# 数据库文件路径（SQLite，本地文件，开箱即用）
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "data.db")
DATABASE_URL = f"sqlite:///{DB_PATH}"

# 运行环境
APP_ENV = os.getenv("APP_ENV", "development").strip().lower() or "development"

# 内置开发回退值：仅允许在开发/测试环境使用，生产环境见 validate_startup_config
DEV_SECRET_KEY = "swap-station-admin-dev-secret-key-change-me"
DEV_ADMIN_PASSWORD = "admin123"

# JWT 配置
SECRET_KEY = os.getenv("APP_SECRET_KEY") or DEV_SECRET_KEY
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 12  # 12 小时

# 首次引导的管理员账号（仅在数据库中尚无该用户时创建）
DEFAULT_ADMIN_USERNAME = os.getenv("APP_ADMIN_USERNAME", "admin")
DEFAULT_ADMIN_PASSWORD = os.getenv("APP_ADMIN_PASSWORD") or DEV_ADMIN_PASSWORD

# 服务端口（使用非常见端口）
APP_PORT = 7634

# 密钥/口令强度基线
_MIN_SECRET_KEY_LENGTH = 32
_MIN_ADMIN_PASSWORD_LENGTH = 8


class StartupConfigError(RuntimeError):
    """启动配置不满足安全基线，服务必须拒绝启动。"""


def is_production() -> bool:
    """当前是否生产环境。"""
    return APP_ENV in ("production", "prod")


def validate_startup_config() -> list[str]:
    """校验启动配置的安全基线。

    返回告警信息列表（开发/测试环境使用内置默认值时给出提示，便于运维
    判断实例是否安全启动）；生产环境下任一基线不达标即抛出
    StartupConfigError，让进程明确拒绝启动。
    """
    problems = []
    if SECRET_KEY == DEV_SECRET_KEY:
        problems.append("APP_SECRET_KEY 未配置，当前使用内置开发密钥，所有部署共享同一签名密钥")
    elif len(SECRET_KEY) < _MIN_SECRET_KEY_LENGTH:
        problems.append(f"APP_SECRET_KEY 长度不足 {_MIN_SECRET_KEY_LENGTH} 字符，签名密钥强度不够")
    if DEFAULT_ADMIN_PASSWORD == DEV_ADMIN_PASSWORD:
        problems.append("APP_ADMIN_PASSWORD 未配置，初始管理员密码仍为内置默认凭据")
    elif len(DEFAULT_ADMIN_PASSWORD) < _MIN_ADMIN_PASSWORD_LENGTH:
        problems.append(f"APP_ADMIN_PASSWORD 长度不足 {_MIN_ADMIN_PASSWORD_LENGTH} 位，初始口令强度不够")

    if problems and is_production():
        raise StartupConfigError("生产环境启动配置检查未通过：" + "；".join(problems))
    return problems
