# 舞萌 DX 赛事管理系统

基于 Flask 的 maimai DX 线下赛事管理 Web 应用，提供选曲、计分、投票、抽奖等一站式赛事管理功能。

## 功能概览

- **选曲系统** — 管理员发布课题，选手选曲 / Ban 曲
- **计分系统** — 多赛事多轮次成绩录入、名单导入、选手改名
- **投票系统** — 支持单选 / 多选投票
- **抽奖系统** — 奖池管理、参与者名单、随机抽选
- **用户管理** — 邀请码注册、管理员 / 普通用户角色
- **公告系统** — 管理员发布公告
- **数据重置** — 一键清空各类数据

## 技术栈

| 层级 | 技术 |
|------|------|
| 后端 | Python 3 / Flask / Flask-Login / SQLAlchemy |
| 数据库 | SQLite |
| 前端 | Bootstrap 5 / Jinja2 模板 |
| 反向代理 | Caddy（可选） |

## 快速开始

### 1. 安装依赖

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux / macOS
source .venv/bin/activate

pip install flask flask-login flask-sqlalchemy markupsafe werkzeug requests
```

### 2. 配置环境变量

```bash
# 必须：设置 Flask 密钥（生产环境请使用随机长字符串）
export SECRET_KEY="your-secret-key-here"

# 可选：自定义数据库路径（默认 sqlite:///app.db）
export DATABASE_URL="sqlite:///app.db"
```

Windows PowerShell：

```powershell
$env:SECRET_KEY = "your-secret-key-here"
```

### 3. 初始化数据库

```bash
python init_db.py
```

这将创建数据库并插入：
- 默认管理员账号：`admin` / `test`
- 默认邀请码：`test`
- 歌曲数据（从 `songs.csv` 导入）

> **注意**：部署后请立即修改管理员密码和邀请码。

### 4. 获取歌曲数据（可选）

如需更新歌曲库，运行：

```bash
python songs.py
```

将从 diving-fish API 拉取最新曲目数据并写入 `songs.csv`。

> **歌曲数据来源**：[https://maimai.diving-fish.com/](https://maimai.diving-fish.com/)，包括现行国服曲库。如需日服曲库，可尝试从日服官网爬取。

### 5. 获取歌曲封面及图片资源

歌曲封面图片（`static/mai/cover/`）未包含在仓库中，请按以下步骤获取：

1. 前往 [Diving-Fish/mai-bot](https://github.com/Diving-Fish/mai-bot)
2. 按照该项目 README 的 **第二步** 下载歌曲封面资源
3. 将封面图片放入 `static/mai/cover/` 目录

> `static/mai/pic/` 中仅提交了程序运行所需的图片（Rank 图标、难度框等），完整资源同样来源于 [Diving-Fish/mai-bot](https://github.com/Diving-Fish/mai-bot)。

### 6. 启动应用

```bash
python app.py
```

默认监听 `http://127.0.0.1:5000`。

## 项目结构

```
├── app.py              # Flask 主应用（路由 & 业务逻辑）
├── models.py           # SQLAlchemy 数据模型
├── init_db.py          # 数据库初始化脚本
├── songs.py            # 歌曲数据抓取工具
├── songs.csv           # 歌曲数据源
├── Caddyfile           # Caddy 反向代理配置（可选）
├── static/
│   ├── app.css         # 全局样式
│   ├── app.js          # 全局 JS（CSRF 注入等）
│   └── mai/            # maimai 封面 & 资源图片
│       ├── cover/      # 歌曲封面
│       ├── pic/
│       ├── plate/
│       └── rating/
└── templates/
    ├── base.html       # 基础布局模板
    ├── dashboard.html  # 仪表盘
    ├── login.html      # 登录
    ├── register.html   # 注册
    ├── select_song.html # 选曲界面
    ├── score.html      # 计分界面
    ├── vote.html       # 投票界面
    ├── lottery.html    # 抽奖界面
    └── admin/          # 管理员页面
        ├── settings.html
        ├── assignments.html
        ├── users.html
        └── ...
```

## 部署建议

- 生产环境务必通过环境变量设置 `SECRET_KEY`
- 使用 Caddy / Nginx 作为反向代理并启用 HTTPS
- 定期备份 `instance/app.db` 数据库文件

## 许可

MIT
