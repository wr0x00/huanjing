"""全局配置：环境变量优先，MVP 全部可离线运行"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)


def _load_dotenv():
    env_file = BASE_DIR / ".env"
    if not env_file.exists():
        return
    for line in env_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip())


_load_dotenv()

# ---- 存储：按职责分库 ----
# HP_DB_PATH 仍可用，指向旧单库（honeypot.db），仅作为一次性迁移来源；
# HP_DB_DIR 指定分库所在目录；未指定时沿用 HP_DB_PATH 所在目录（测试隔离依然有效）
LEGACY_DB_PATH = os.getenv("HP_DB_PATH", str(DATA_DIR / "honeypot.db"))
DB_DIR = Path(os.getenv("HP_DB_DIR") or Path(LEGACY_DB_PATH).parent)
DB_DIR.mkdir(parents=True, exist_ok=True)

DB_PATHS = {
    "site": str(DB_DIR / "hp_site.db"),      # 站点信息：靶站 / 克隆 / SiteGraph 节点
    "log": str(DB_DIR / "hp_log.db"),        # 运行日志：事件 / 完整报文 / 生长账本
    "session": str(DB_DIR / "hp_session.db"),  # 会话画像：评分 / 状态 / WebRTC 溯源 IP
    "config": str(DB_DIR / "hp_config.db"),  # 配置：陷阱 / 模型源 / 全局设置
    "asset": str(DB_DIR / "hp_asset.db"),    # 资产：Canary Token
}
# 兼容旧引用（已不再作为主库使用）
DB_PATH = LEGACY_DB_PATH
TRAPS_FILE = BASE_DIR / "config" / "traps.yaml"
CONSOLE_DIR = BASE_DIR / "console" / "static"

PERSONA = os.getenv("HP_PERSONA", "默认仿冒模板")
# 蜜点正文与动态页统一使用的品牌标识：默认与站点人设同源，
# 避免出现与站点身份自相矛盾的残留品牌（拟真前提）。
BRAND = os.getenv("HP_BRAND", PERSONA)
# 英文标识：库名 / 内部域名 / 部署路径统一用它，保证全套蜜点口径一致
BRAND_SLUG = os.getenv("HP_BRAND_SLUG", "saas")
BRAND_DOMAIN = os.getenv("HP_BRAND_DOMAIN", f"{BRAND_SLUG}.example")

# 假登录弱口令库：只有命中列表的凭据才放行（MFA → 后台），
# 其余一律失败并置 401 —— 避免"任意凭据均可登录"这种一眼假的蜜罐特征。
WEAK_CREDENTIALS = [
    ("admin", "987987"),
]

# ---- 入口端口：靶站（攻击者视角，生产换域名+反代）与管理端分离 ----
SITE_PORT = int(os.getenv("HP_SITE_PORT", "8888"))
CONSOLE_PORT = int(os.getenv("HP_CONSOLE_PORT", "9000"))
SITE_HOST = os.getenv("HP_SITE_HOST", "0.0.0.0")
CONSOLE_HOST = os.getenv("HP_CONSOLE_HOST", "127.0.0.1")
# Canary 回连统一指向管理端基础设施（与靶站域名隔离，防关联识破）
CALLBACK_BASE = os.getenv("HP_CALLBACK_BASE", f"http://127.0.0.1:{CONSOLE_PORT}")
GROWTH_HOURLY_QUOTA = int(os.getenv("HP_GROWTH_QUOTA", "20"))
WEBRTC_ATTRIBUTION = os.getenv("HP_WEBRTC_ATTRIBUTION", "false").lower() in ("1", "true", "yes")

# ---- 混合模型网关：本地 + 云端，全部走 OpenAI 兼容协议 ----
LLM_PROVIDERS = {
    "local": {
        "base_url": os.getenv("HP_LOCAL_LLM_URL", "http://127.0.0.1:8000/v1"),
        "model": os.getenv("HP_LOCAL_LLM_MODEL", "Qwen2.5-14B-Instruct"),
        "key": os.getenv("HP_LOCAL_LLM_KEY", "EMPTY"),
    },
    "deepseek": {
        "base_url": "https://api.deepseek.com/v1",
        "model": "deepseek-chat",
        "key": os.getenv("DEEPSEEK_API_KEY", ""),
    },
    "openai": {
        "base_url": "https://api.openai.com/v1",
        "model": os.getenv("HP_OPENAI_MODEL", "gpt-4o-mini"),
        "key": os.getenv("OPENAI_API_KEY", ""),
    },
}

# 任务级路由：answer=高频交互应答 / blueprint=生长蓝图 / report=态势报告
LLM_ROUTING = {
    "answer": ["local", "deepseek", "openai"],
    "blueprint": ["deepseek", "openai", "local"],
    "report": ["deepseek", "openai"],
}

# 投入评分阈值（对应设计文档 L0-L4 阶梯）
SCORE_L2, SCORE_L3 = 10.0, 25.0
