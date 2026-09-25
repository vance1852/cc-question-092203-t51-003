# 换电站运营管理平台（纯后端）

新能源物流车换电站后台管理的纯后端 API 服务，提供站点、车辆和换电记录的统一管理能力。

## 技术栈

- FastAPI + Uvicorn
- SQLAlchemy + SQLite（本地文件，开箱即用）
- PyJWT（JWT 鉴权）
- 密码哈希用标准库 `hashlib.pbkdf2_hmac`，无额外依赖

所有数据本地、离线可运行，不依赖任何外部服务。

## 运行

```bash
pip install -r requirements.txt
python run.py
```

服务启动在 `http://127.0.0.1:7634`，首次启动自动建表并灌入种子数据。
交互式文档：`http://127.0.0.1:7634/docs`。

## 环境变量与启动检查

| 变量 | 说明 | 默认值 |
| --- | --- | --- |
| `APP_ENV` | 运行环境：`development` / `test` / `production` | `development` |
| `APP_SECRET_KEY` | JWT 签名密钥（生产必须 ≥32 字符的强随机值） | 内置开发密钥 |
| `APP_ADMIN_USERNAME` | 首次引导的管理员用户名 | `admin` |
| `APP_ADMIN_PASSWORD` | 首次引导的管理员初始密码（生产必须为非默认强口令） | `admin123` |

启动时执行配置安全检查：

- **生产环境**（`APP_ENV=production`）：缺少强签名密钥、或初始管理员密码仍是内置
  默认值时，进程**明确拒绝启动**并输出原因。
- **开发/测试环境**：允许使用内置默认值稳定运行，但启动日志会逐条给出告警，
  便于运维判断实例是否安全启动。

初始密码仅在数据库中尚无管理员时生效（首次引导）；已存在的账号不受其影响。

## 内置账号（仅开发/测试）

首次启动自动创建唯一管理员（本平台只有 admin 一个角色）：

- 用户名：`admin`
- 密码：`admin123`（生产环境必须通过 `APP_ADMIN_PASSWORD` 显式覆盖，否则拒绝启动）

## 已实现的基础功能

- 登录签发 JWT、获取当前用户、修改密码（`/api/auth/login`、`/api/auth/me`、`/api/auth/change-password`）
- 换电站增删改查（`/api/stations`）
- 车辆增删改查（`/api/vehicles`）
- 换电记录查询与登记（`/api/swaps`，会联动更新车辆电量与站点可用电池）
- 仪表盘统计（`/api/dashboard/stats`）
- 健康检查（`/api/health`）

除 `login` 与 `health` 外，所有接口均需携带 `Authorization: Bearer <token>`。

## 认证安全说明

- 令牌携带持久化的凭据版本（`token_version`）：修改密码后版本 +1，
  此前签发的所有令牌立即失效，需用新密码重新登录。
- 存储的密码哈希损坏（非 hex、未知编码等）或令牌畸形/伪造/过期时，
  一律返回统一的 401，不向调用方泄露内部解析细节。

## 测试

```bash
pip install -r requirements.txt
pytest -q
```

## 编码说明

源码与数据均为 UTF-8；FastAPI 响应为 UTF-8 JSON，中文不转义、不乱码。
Windows 控制台若为 GBK，仅影响终端打印观感，不影响接口返回。
