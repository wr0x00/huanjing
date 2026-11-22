"""自主 Agent 行为检测引擎

设计原则（对齐《面向自主 Agent 检测的蜜罐设计与检测手法汇总》）：
  1. 行为序列优先于单个指纹：单条 UA/Header 命中只作线索，不足以定性。
  2. 多信号关联后再提高置信度：分数由「稳定键证据」累加，阈值分层给出结论。
  3. 蜜罐只提供受控诱饵：识别与判定都在被动观测侧完成，不主动试探攻击者。
  4. 「可能是 Agent」与「确认恶意行为」分开表达：agent_label 只描述编排/行为特征，
     恶意性由会话状态与凭据捕获另行判定，避免把自动化客户端一律当作攻击者。
  5. 阈值由本地基线确定：窗口参数走 settings（可按部署环境调整），不硬套外部数字。
  6. 低权重 IOC 有效期有限：字符串线索（如 x-id-token）仅作 enrichment，永不单独定罪。

所有证据以「稳定键」写入 store.AGENT_SIGNAL_REGISTRY，保证历史回放幂等：
同一份证据反复命中不会重复计分，说明文案可随时调整而不影响已落库结论。
"""
import hashlib
import json
import os
import re
import time
from collections import defaultdict

from . import events, store

# ---- 低权重字符串 IOC（公开材料的默认特征；命中仅作线索） ----
UA_IOCS = [
    ("artex-enrich", "ua_ioc_match"),
    ("artex/1.0", "ua_ioc_match"),
    ("scopeweaver", "ua_ioc_match"),
    ("cyberstrikeai", "ua_ioc_match"),
    ("hexstrike", "ua_ioc_match"),
]
# 任务化 UA：LLM Agent 常把 worker 任务名写进 UA（每个 worker 一个专属 UA）
TASK_UA_MARKS = (
    "recon", "probe", "poc", "pentest", "scanner", "exploit",
    "enum", "brute", "audit", "verify", "crawl", "fuzz", "test",
)
HEADER_IOCS = ("x-id-token",)  # 未验证候选：仅作低置信度 enrichment

RECON_MARKS = ("robots.txt", "sitemap.xml", ".git", ".env", "backup", "swagger",
               "actuator", "phpinfo", ".svn", "docker-compose", "jenkins",
               "/pma", "admin_old")
DENY_STATUS = (401, 403, 404, 429)

# 聚合窗口：行为统计按一分钟窗口滚动计算
WINDOW = 60
# 同源并行判定窗口
PARALLEL_WINDOW = 600

# 本地基线默认值（可经 settings["agent_baseline"] 或环境变量覆盖）
DEFAULT_BASELINE = {
    "rpm": 25,             # 一分钟窗口请求数上限（超过视为突发扫描）
    "path_diversity": 15,  # 一分钟窗口内不同路径数上限（超过视为枚举爬取）
    "deny_spray": 4,       # 一分钟内被拒目标数上限（超过视为广撒扫描）
}
DEFAULT_ALLOWLIST = {"ips": [], "ua": []}

_baseline_cache: dict = {"ts": 0.0, "value": dict(DEFAULT_BASELINE)}
_allow_cache: dict = {"ts": 0.0, "value": dict(DEFAULT_ALLOWLIST)}


def _settings_json(key: str, default):
    """读取 settings 表中的 JSON 配置（失败回落到默认值）"""
    try:
        raw = store.get_setting(key)
        if not raw:
            return default
        val = json.loads(raw)
        return val if isinstance(val, dict) else default
    except Exception:
        return default


def baseline() -> dict:
    """本地基线阈值：settings 优先，其次环境变量，最后默认值"""
    now = time.time()
    if now - _baseline_cache["ts"] < 30:
        return _baseline_cache["value"]
    val = dict(DEFAULT_BASELINE)
    val.update({k: int(v) for k, v in
                _settings_json("agent_baseline", {}).items()
                if k in val and str(v).isdigit()})
    env_rpm = os.getenv("HP_AGENT_BASELINE_RPM")
    if env_rpm and env_rpm.isdigit():
        val["rpm"] = int(env_rpm)
    _baseline_cache.update({"ts": now, "value": val})
    return val


def allowlist() -> dict:
    """授权白名单：授权扫描器 / CI / 监控来源不计入 Agent 判定"""
    now = time.time()
    if now - _allow_cache["ts"] < 30:
        return _allow_cache["value"]
    val = dict(DEFAULT_ALLOWLIST)
    raw = _settings_json("agent_allowlist", {})
    val["ips"] = [str(x).strip() for x in (raw.get("ips") or []) if str(x).strip()]
    val["ua"] = [str(x).strip().lower() for x in (raw.get("ua") or []) if str(x).strip()]
    env_ips = os.getenv("HP_AGENT_ALLOW_IPS", "")
    env_ua = os.getenv("HP_AGENT_ALLOW_UA", "")
    if env_ips:
        val["ips"] += [x.strip() for x in env_ips.split(",") if x.strip()]
    if env_ua:
        val["ua"] += [x.strip().lower() for x in env_ua.split(",") if x.strip()]
    _allow_cache.update({"ts": now, "value": val})
    return val


def is_allowed(ip: str, ua: str) -> bool:
    """命中白名单则不参与 Agent 判定（不当作攻击者）"""
    al = allowlist()
    if ip and ip in al["ips"]:
        return True
    ua_low = (ua or "").lower()
    return any(mark and mark in ua_low for mark in al["ua"])


# ---------------- 客户端工具族 ----------------
def client_family(ua: str, headers) -> str:
    """UA + Header 一致性 → 客户端工具族"""
    ua_low = (ua or "").lower()
    h = {k.lower() for k in (headers or {})}
    browser_hints = (any(k.startswith(("sec-ch-", "sec-fetch-")) for k in h)
                     or "accept-language" in h)
    if "curl/" in ua_low:
        return "curl"
    if any(m in ua_low for m in ("python-urllib", "python-requests", "aiohttp", "httpx")):
        return "python"
    if ua_low.startswith("wget") or "wget/" in ua_low:
        return "wget"
    if "go-http-client" in ua_low:
        return "go"
    if "java/" in ua_low or "okhttp" in ua_low:
        return "java"
    if "mozilla" in ua_low:
        return "browser" if browser_hints else "fake_browser"
    return "no_ua" if not ua_low else "other"


FAMILY_LABELS = {
    "curl": "curl", "python": "Python HTTP 库", "wget": "wget", "go": "Go HTTP",
    "java": "Java HTTP", "browser": "真实浏览器", "fake_browser": "伪装浏览器UA",
    "no_ua": "空UA", "other": "其他客户端",
}


def family_label(fam: str) -> str:
    return FAMILY_LABELS.get(fam, fam)


def family_from_ua(ua: str) -> str:
    """无 header 上下文时的 UA-only 兜底（历史会话展示用）"""
    ua_low = (ua or "").lower()
    for mark, fam in (("curl/", "curl"), ("python-urllib", "python"),
                      ("python-requests", "python"), ("aiohttp", "python"),
                      ("httpx", "python"), ("wget/", "wget"),
                      ("go-http-client", "go"), ("okhttp", "java"), ("java/", "java")):
        if mark in ua_low:
            return fam
    if "mozilla" in ua_low:
        return "browser"
    return "no_ua" if not ua_low else "other"


# ---------------- 会话/来源行为状态（内存态，可从历史流量重建） ----------------
_state: dict[str, dict] = {}
_ip_families: dict[str, dict[str, float]] = defaultdict(dict)
_ip_sids: dict[str, dict[str, float]] = defaultdict(dict)
_ip_uas: dict[str, dict[str, float]] = defaultdict(dict)
_ident_sids: dict[str, dict[str, float]] = defaultdict(dict)
_ident_families: dict[str, dict[str, float]] = defaultdict(dict)
_last_sweep = 0.0


def _state_of(sid: str) -> dict:
    return _state.setdefault(sid, {
        "last_ts": 0.0, "burst_n": 0, "burst_cycles": 0,
        "families": {}, "denies": {}, "stages": set(),
        "paths": set(), "surfaces": set(), "window": [],
        "allowed": False})


def _sweep(now: float):
    """清理 2h 不活跃的状态，防内存无限增长（每 5 分钟一次）"""
    global _last_sweep
    if now - _last_sweep < 300:
        return
    _last_sweep = now
    for sid in [s for s, st in _state.items() if now - st["last_ts"] > 7200]:
        _state.pop(sid, None)
    cutoff = now - 7200
    for m in (_ip_families, _ip_sids, _ip_uas, _ident_sids, _ident_families):
        for ip in list(m):
            m[ip] = {k: t for k, t in m[ip].items() if t > cutoff}
            if not m[ip]:
                m.pop(ip, None)


def _norm_target(path: str) -> str:
    return re.sub(r"/+", "/", (path or "").lower()).strip("/")


def _basename(path: str) -> str:
    return _norm_target(path).rsplit("/", 1)[-1]


def _surface(path: str) -> str:
    p = _norm_target(path)
    if p.startswith("admin"):
        return "admin后台"
    if p.startswith("api"):
        return "API接口"
    if any(m in p for m in (".sql", ".gz", "backup", "dump")):
        return "备份文件"
    if ".git" in p:
        return "版本库"
    if "swagger" in p or "openapi" in p:
        return "接口文档"
    return "Web页面"


def _stage(method: str, path: str, body: str) -> str:
    p = _norm_target(path)
    if any(m in p for m in RECON_MARKS):
        return "recon"
    if method == "POST" and ("login" in p or any(
            k in (body or "").lower() for k in ("password=", "pass=", "username=", "&p=", "u="))):
        return "cred"
    if p.startswith("admin") and method == "GET":
        return "postauth"
    return ""


def _identity(headers) -> str:
    """身份维度：Authorization / API Key / 会话 Cookie 的指纹（不落原文）"""
    h = {}
    for k, v in (headers or {}).items():
        h.setdefault(str(k).lower(), v)
    for key in ("authorization", "x-api-key", "x-auth-token",
                "proxy-authorization", "cookie"):
        val = h.get(key)
        if val:
            digest = hashlib.sha1(str(val).encode("utf-8", "replace")).hexdigest()[:12]
            return f"{key}:{digest}"
    return ""


def _record(sid: str, signal: str, quiet: bool = False):
    """记录稳定键证据（权重由 store 注册表决定，回放幂等）"""
    before = store.session_snapshot(sid).get("agent_label", "未判定")
    profile = store.record_agent_signal(sid, signal)
    if quiet:
        return
    if profile["agent_label"] != before:
        events.broadcast("profile.agent_signal", "-", sid,
                         f"Agent 研判升级：{profile['agent_label']}（{profile['agent_score']}）· "
                         f"{store.signal_desc(signal)}",
                         {**profile, "signal": signal})


def observe(sid: str, ip: str, method: str, path: str,
            ua: str, headers, body: str = "", status: int = 0,
            ts: float = None, quiet: bool = False):
    """热路径观测：每请求一次，纯内存运算 + 信号落会话缓存

    ts/quiet 供历史回放使用：ts 传入真实时间戳以还原节奏，quiet 抑制事件广播。
    """
    now = ts if ts else time.time()
    _sweep(now)
    st = _state_of(sid)

    # 白名单来源：授权扫描器/CI/监控，不参与 Agent 判定
    if not st["allowed"] and is_allowed(ip, ua):
        st["allowed"] = True
        store.mark_session_allowed(sid)
        return

    fam = client_family(ua, headers)
    st["families"].setdefault(fam, now)
    if ip:
        _ip_families[ip][fam] = now
        _ip_sids[ip][sid] = now
        _ip_uas[ip][ua or ""] = now
    ident = _identity(headers)
    if ident:
        _ident_sids[ident][sid] = now
        _ident_families[ident][fam] = now

    # 1) 客户端指纹信号（低权重，单独不定罪）
    if fam == "fake_browser":
        _record(sid, "ua_fake_browser", quiet)
    elif fam in ("curl", "python", "wget", "go", "java"):
        _record(sid, "tool_non_browser", quiet)
    ua_low = (ua or "").lower()
    for mark, sig in UA_IOCS:
        if mark in ua_low:
            _record(sid, sig, quiet)
    # 任务化 UA：每个 worker 自带任务名后缀（Agent 编排的典型痕迹）
    ua_tail = ua_low.split(")", 1)[-1].strip()
    if any(mark in ua_tail for mark in TASK_UA_MARKS):
        _record(sid, "ua_task_mark", quiet)
    hlow = {k.lower() for k in (headers or {})}
    for key in HEADER_IOCS:
        if key in hlow:
            _record(sid, "header_id_token", quiet)

    # 2) 同源多工具族 / 多身份并行（编排型 Agent 特征）
    recent_fams = {f: t for f, t in _ip_families.get(ip, {}).items() if now - t < PARALLEL_WINDOW}
    if len(recent_fams) >= 3:
        _record(sid, "multi_family_parallel", quiet)
    elif len(recent_fams) >= 2 and len(_ip_sids.get(ip, {})) >= 3:
        _record(sid, "multi_session_parallel", quiet)
    # 2b) 同源多会话且 UA 互不相同（每 worker 一个专属 UA：编排式 Agent 强特征）
    if ip:
        uas = {u: t for u, t in _ip_uas.get(ip, {}).items() if t and now - t < PARALLEL_WINDOW}
        uas.pop("", None)
        if len(uas) >= 4 and len(_ip_sids.get(ip, {})) >= 4:
            _record(sid, "multi_ua_per_worker", quiet)
    # 2c) 同一身份（令牌/凭据）跨多会话多工具族并行
    if ident:
        ids = {s2: t for s2, t in _ident_sids.get(ident, {}).items() if now - t < PARALLEL_WINDOW}
        if len(ids) >= 3 and len(_ident_families.get(ident, {})) >= 2:
            _record(sid, "multi_identity_parallel", quiet)

    # 3) 突发-静默节奏（批请求 → 静默推理 → 换方向）
    prev = st["last_ts"]
    st["last_ts"] = now
    if prev and now - prev > 60:
        if st["burst_n"] >= 3:
            st["burst_cycles"] += 1
            if st["burst_cycles"] >= 2:
                _record(sid, "burst_silence", quiet)
        st["burst_n"] = 0
    st["burst_n"] += 1

    # 4) 被拒后同目标变体重试（连续变体 > 单个变体）
    norm = _norm_target(path)
    base = _basename(path)
    if status in DENY_STATUS and base:
        st["denies"][base] = (norm, now)
        if len(st["denies"]) > 50:  # 只留最近 50 个被拒目标
            st["denies"] = dict(list(st["denies"].items())[-50:])
    elif base:
        hit = st["denies"].get(base)
        if hit and hit[0] != norm:
            _record(sid, "deny_variant_retry", quiet)
            st["denies"].pop(base, None)

    # 5) 阶段序列与攻击面切换
    stage = _stage(method, path, body)
    if stage:
        st["stages"].add(stage)
        if stage == "cred" and "recon" in st["stages"]:
            _record(sid, "chain_recon_cred", quiet)
        if stage == "postauth" and "cred" in st["stages"]:
            _record(sid, "chain_postauth", quiet)
    st["surfaces"].add(_surface(path))
    if len(st["surfaces"]) >= 3:
        _record(sid, "multi_surface", quiet)
    st["paths"].add(norm)
    if len(st["paths"]) >= 20:
        _record(sid, "path_diversity", quiet)

    # 6) 一分钟窗口聚合（阈值取本地基线）
    win = st["window"]
    win.append((now, norm, status))
    while win and now - win[0][0] > WINDOW:
        win.pop(0)
    base_l = baseline()
    if len(win) >= base_l["rpm"]:
        _record(sid, "burst_rate", quiet)
    if len({p for _, p, _ in win}) >= base_l["path_diversity"]:
        _record(sid, "window_path_diversity", quiet)
    denied = {p for _, p, s in win if s in DENY_STATUS}
    if len(denied) >= base_l["deny_spray"]:
        _record(sid, "deny_target_spray", quiet)


def session_families(sid: str, ua: str = "") -> str:
    """会话工具族标签（实时状态优先，历史会话 UA 兜底）"""
    st = _state.get(sid)
    if st and st["families"]:
        return " / ".join(family_label(f) for f in sorted(
            st["families"], key=lambda f: -st["families"][f]))
    return family_label(family_from_ua(ua))


def identity_guess(signals) -> str:
    """身份推断：多信号关联后给出推测（措辞留余地，不锁死断言）"""
    names = set(signals or [])
    orchestrated = ("multi_ua_per_worker" in names
                    or ("multi_family_parallel" in names and "ua_task_mark" in names)
                    or ("multi_session_parallel" in names and "multi_family_parallel" in names))
    if names & {"semantic_followthrough", "semantic_task_read"}:
        return "LLM 自主渗透 Agent（读懂语义诱饵并按要求跟进）"
    if orchestrated or "multi_identity_parallel" in names:
        return "编排型自主攻击 Agent（Planner/Worker 多会话并发、每 worker 专属 UA，疑似 ARTEX 类框架）"
    if names & {"chain_postauth", "chain_recon_cred"}:
        return "结果驱动的自主攻击 Agent"
    if "ua_task_mark" in names:
        return "LLM Agent 驱动的自动化客户端（UA 自带任务标识）"
    if names & {"burst_silence", "deny_variant_retry", "burst_rate",
                "deny_target_spray", "window_path_diversity"}:
        return "自动化攻击脚本（疑为 Agent 驱动）"
    if "ua_fake_browser" in names:
        return "UA 伪装的自动化客户端"
    return ""


def replay_history(limit: int = 4000) -> int:
    """历史流量回放：从 packets 表重放最近流量，重建行为状态与 Agent 信号

    目的：进程重启后内存态清零，历史会话（尤其是重启前已发生的 Agent 攻击）
    仍可被研判，而不是只有重启后的新流量才有结论。
    """
    try:
        packets = store.list_packets(limit=limit, light=False)
    except Exception:
        return 0
    if not packets:
        return 0
    rows = sorted(packets, key=lambda p: p.get("id") or 0)
    sess_map = {s["id"]: s for s in store.list_sessions(limit=1000)}
    touched = set()
    done = 0
    for p in rows:
        sid = p.get("session_id") or ""
        if not sid:
            continue
        s = sess_map.get(sid)
        if not s:
            continue
        if sid not in touched:
            # 先清空该会话既有证据（保留陷阱侧语义证据），再按流量重建
            _reset_behavior_signals(sid)
            touched.add(sid)
        headers = {}
        try:
            raw = p.get("req_headers")
            if isinstance(raw, (bytes, bytearray)):
                import zlib as _zlib
                for wb in (15, -15):
                    try:
                        raw = _zlib.decompress(bytes(raw), wb)
                        break
                    except Exception:
                        continue
            if isinstance(raw, (bytes, bytearray)):
                raw = raw.decode("utf-8", "replace")
            if isinstance(raw, str) and raw:
                import json as _json
                headers = _json.loads(raw)
        except Exception:
            headers = {}
        ua = next((v for k, v in (headers or {}).items()
                   if k.lower() == "user-agent"), s.get("ua") or "")
        try:
            ts = time.mktime(time.strptime((p.get("ts") or "")[:19], "%Y-%m-%d %H:%M:%S"))
        except Exception:
            ts = None
        observe(sid, s.get("ip") or "", p.get("method") or "GET",
                p.get("path") or "/", ua, headers, p.get("req_body") or "",
                int(p.get("status") or 0), ts=ts, quiet=True)
        done += 1
    return done


def _reset_behavior_signals(sid: str):
    """清空行为侧证据（保留陷阱语义证据），供历史回放幂等重建"""
    s = store.session_snapshot(sid)
    keep = [x for x in s.get("agent_signals", [])
            if x in ("client_marker", "semantic_task_read",
                     "result_api_probe", "semantic_followthrough")]
    s["agent_signals"] = keep
    s["agent_score"] = sum(store.AGENT_SIGNAL_REGISTRY.get(k, (0, ""))[0] for k in keep)
    s["agent_label"] = store.agent_label_for(s["agent_score"])
    store._sess_dirty.add(sid)
