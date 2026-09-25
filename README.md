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

## 环境变量

| 变量 | 说明 | 默认值 |
| --- | --- | --- |
| `APP_ENV` | 运行环境：`development` / `test` / `production` | `development` |
| `APP_SECRET_KEY` | JWT 签名密钥 | 内置开发密钥（仅限本地） |
| `APP_ADMIN_USERNAME` | 首次引导的管理员用户名 | `admin` |
| `APP_ADMIN_PASSWORD` | 首次引导的管理员密码 | `admin123`（仅限本地） |
| `APP_PORT` | 服务端口 | `7634` |

可参考 `.env.example`。

### 启动安全检查

- **生产环境**（`APP_ENV=production`）：启动前强制校验配置，`APP_SECRET_KEY`
  未设置为至少 32 字符的强随机值、或 `APP_ADMIN_PASSWORD` 仍为默认/弱口令
  （少于 12 字符）时，服务会打印具体原因并**拒绝启动**。
- **开发与测试环境**：允许使用内置默认值稳定运行，但会记录告警日志，
  提示该配置禁止用于生产部署。

## 内置账号

首次启动自动创建唯一管理员（本平台只有 admin 一个角色），凭据取自
`APP_ADMIN_USERNAME` / `APP_ADMIN_PASSWORD`：

- 用户名：`admin`（默认）
- 密码：`admin123`（默认，仅限开发/测试）

登录后可通过 `POST /api/auth/password` 修改密码；修改成功后用户凭据版本号
递增并持久化，此前签发的所有 JWT 立即失效（重启后仍然有效），需用新密码重新登录。

## 已实现的基础功能

- 登录签发 JWT、修改密码、获取当前用户（`/api/auth/login`、`/api/auth/password`、`/api/auth/me`）
- 换电站增删改查（`/api/stations`）
- 车辆增删改查（`/api/vehicles`）
- 换电记录查询与登记（`/api/swaps`，会联动更新车辆电量与站点可用电池）
- 仪表盘统计（`/api/dashboard/stats`）
- 健康检查（`/api/health`）

除 `login` 与 `health` 外，所有接口均需携带 `Authorization: Bearer <token>`。
认证失败（密码错误、哈希数据损坏、令牌伪造/过期/版本失效等）一律返回统一的
401 响应，不向调用方泄露内部细节。

## 测试

```bash
pip install -r requirements.txt
pytest -q
```

## 编码说明

源码与数据均为 UTF-8；FastAPI 响应为 UTF-8 JSON，中文不转义、不乱码。
Windows 控制台若为 GBK，仅影响终端打印观感，不影响接口返回。
