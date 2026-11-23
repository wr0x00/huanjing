"""拟真引擎：蜜罐核心请求处理管线（陷阱优先 → SiteGraph 缓存 → 生长 → 泛化 404）
handle(request, path, clone_id) —— clone_id 由靶站入口按站点绑定解析后传入"""
import hashlib
import json
import os.path
from urllib.parse import unquote_plus

import httpx
from starlette.responses import Response

from . import agentdetect, classifier, config, events, growth, llm_gateway, store, traps, watermark
from .redaction import redact_headers, redact_payload, redact_query

# 静态资源扩展名：这类路径不参与生长（防止把 JS/CSS "长"成 HTML 导致页面黑屏）
ASSET_EXTS = {".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
              ".woff", ".woff2", ".ttf", ".eot", ".map", ".webp", ".mp4", ".mp3"}


def is_asset(path: str) -> bool:
    p = "/" + path.lstrip("/")
    return (os.path.splitext(p)[1].lower() in ASSET_EXTS
            or p.startswith("/@") or p.startswith("/_mirror/"))

_login_attempts: dict[str, int] = {}  # MVP 内存版；生产换 Redis
_mfa_state: dict[str, str] = {}  # sid -> pending（待验证）/ passed（已通过）

# WebRTC 真实 IP 静默采集脚本（注入 L2+ 会话的 HTML；仅同源上报，不引外部资源防识破）
WEBRTC_SNIPPET = (
    '<script>(function(){if(!window.RTCPeerConnection)return;try{'
    'var pc=new RTCPeerConnection({iceServers:[{urls:"stun:stun.l.google.com:19302"}]});'
    'pc.createDataChannel("");'
    'pc.onicecandidate=function(e){if(!e.candidate)return;var c=e.candidate.candidate;'
    'if(c.indexOf("typ srflx")>-1||c.indexOf("typ host")>-1){'
    'navigator.sendBeacon("/api/webrtc-leak",JSON.stringify({candidate:c}))}};'
    'pc.createOffer().then(function(o){return pc.setLocalDescription(o)})}catch(_){}})();'
    '</script>')


def login_attempts(sid: str) -> int:
    return _login_attempts.get(sid, 0)


def record_attempt(sid: str):
    _login_attempts[sid] = _login_attempts.get(sid, 0) + 1


def mfa_pending(sid: str) -> bool:
    """弱口令已命中、等待短信二次验证"""
    return _mfa_state.get(sid) == "pending"


def mfa_passed(sid: str) -> bool:
    """二次验证已通过，可进入假后台"""
    return _mfa_state.get(sid) == "passed"


def mark_mfa_pending(sid: str):
    _mfa_state[sid] = "pending"


def mark_mfa_passed(sid: str):
    _mfa_state[sid] = "passed"


def norm_path(path: str) -> str:
    p = "/" + (path or "").strip("/")
    return p if p != "/" else "/index"


def ensure_session(request) -> str:
    ip = request.client.host if request.client else "unknown"
    ua = request.headers.get("user-agent", "")
    sid = hashlib.sha1(f"{ip}|{ua}".encode()).hexdigest()[:12]
    store.get_or_create_session(sid, ip, ua)
    store.add_score(sid, 1)
    return sid


# ---------------- 种子站点（首次启动自动部署） ----------------
SEED_INDEX = f"""<!DOCTYPE html><html lang="zh"><head><meta charset="utf-8">
<title>{config.PERSONA}</title>
<style>body{{font-family:sans-serif;max-width:860px;margin:40px auto;padding:0 16px}}
nav a{{margin-right:16px}}header{{border-bottom:2px solid #2456c4;padding-bottom:8px}}</style>
</head><body>
<header><h1>{config.PERSONA}</h1><p>企业综合业务平台 · 让生意更简单</p></header>
<nav><a href="/">首页</a><a href="/login">客户登录</a><a href="/search">商品搜索</a>
<a href="/about">关于我们</a></nav>
<h2>产品能力</h2>
<ul><li>全渠道订单聚合</li><li>智能库存同步</li><li>会员营销自动化</li></ul>
<footer>© 2023 {config.PERSONA} · 浙ICP备XXXXXXXX号</footer>
<!-- TODO: 上线前删除测试数据 /backup_2023.sql.gz -->
<!-- 老后台迁移遗留入口: /admin_old/ -->
</body></html>"""

SEED_LOGIN = f"""<!DOCTYPE html><html lang="zh"><head><meta charset="utf-8">
<title>登录 - {config.PERSONA}</title></head><body>
<h2>客户登录</h2>
<form method="post" action="/admin/login">
<input name="username" placeholder="用户名"><br>
<input name="password" type="password" placeholder="密码"><br>
<button>登录</button></form>
<p style="color:#888">忘记密码请联系管理员</p>
<!-- test account: admin / 987987 (仅内网) -->
</body></html>"""


def seed_site():
    store.add_clone("seed", "internal://seed", config.PERSONA, "DEPLOYED")
    store.add_node("seed", "/index", SEED_INDEX, "seed", title="首页")
    store.add_node("seed", "/login", SEED_LOGIN, "seed", title="登录")


def sync_seed():
    """默认仿冒模板以代码内种子为准：人设不一致（老库升级）时同步人设与首页/登录页"""
    seed = {c["id"]: c for c in store.list_clones()}.get("seed")
    if not seed or seed.get("persona") == config.PERSONA:
        return
    store.add_clone("seed", "internal://seed", config.PERSONA, seed.get("status") or "DEPLOYED")
    store.add_node("seed", "/index", SEED_INDEX, "seed", title="首页")
    store.add_node("seed", "/login", SEED_LOGIN, "seed", title="登录")


def init_runtime():
    """两个入口共用的启动初始化（幂等）"""
    store.init_db()
    traps.load_builtin()
    llm_gateway.seed_from_env()
    if not store.list_clones():
        seed_site()
    else:
        sync_seed()
    if not store.list_sites():
        # 首次启动：默认靶站（独立入口端口）挂载种子蜜罐
        store.add_site("默认靶站", config.SITE_PORT, "seed", domain="")
        events.broadcast("site.created", "seed", "-",
                         f"默认靶站已创建并挂载 seed（端口 {config.SITE_PORT}）")
    # 历史流量回放：重建 Agent 行为状态（重启后历史会话仍可被研判）
    try:
        replayed = agentdetect.replay_history()
        if replayed:
            events.broadcast("profile.replay", "-", "-",
                             f"Agent 行为检测：已回放 {replayed} 条历史流量，"
                             f"重建行为链与研判状态")
    except Exception:
        pass


# ---------------- 主管线 ----------------
def _serve_node(node: dict, sid: str) -> Response:
    content = node["content"]
    ctype = node.get("content_type", "text/html")
    if isinstance(content, (bytes, bytearray)) or not ctype.startswith("text/html"):
        # 代理缓存的二进制/非 HTML 资源：原样返回，不注入水印
        return Response(content, media_type=ctype)
    content = content + watermark.session_marker(sid)
    score = store.session_snapshot(sid)["score"]
    if score >= config.SCORE_L2:
        url, tid = watermark.canary_url(sid, f"node:{node['path']}", config.CALLBACK_BASE)
        store.add_token(tid, sid, f"node:{node['path']}")
        content += f'<img src="{url}" width="1" height="1" style="display:none">'
        # L2+（已深度投入）会话：注入 WebRTC 采集脚本，静默收集真实出口 IP
        if config.WEBRTC_ATTRIBUTION:
            content += WEBRTC_SNIPPET
    return Response(content, media_type=node.get("content_type", "text/html"))


def _plain404() -> Response:
    return Response("<!DOCTYPE html><html><body><h1>404 Not Found</h1><hr>nginx</body></html>",
                    status_code=404, media_type="text/html")


_PROXY_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")

# 进程级共享回源客户端：复用连接池/TLS 会话（旧版每请求新建 client，多一次握手）
_http: httpx.AsyncClient | None = None


def _origin_client() -> httpx.AsyncClient:
    global _http
    if _http is None or _http.is_closed:
        _http = httpx.AsyncClient(follow_redirects=True, timeout=15,
                                  headers={"User-Agent": _PROXY_UA})
    return _http


async def _proxy_asset(clone_id: str, path: str) -> Response:
    """静态资源反向代理回源站（克隆页拟真的关键：JS/CSS/图片原样可用）。
    首次成功后缓存进 SiteGraph，后续走本地缓存。失败返回 404，绝不生长成 HTML。"""
    np = norm_path(path)
    # /_mirror/ 是克隆期镜像的跨域资产，源站上不存在该路径。
    # miss 时用 born_from 记录的真实 URL 自愈补抓；仍失败给正确 MIME 的空占位
    #（绝不能返回 HTML，否则浏览器把 HTML 当脚本解析 → SyntaxError → 页面黑屏）
    if np.startswith("/_mirror/"):
        node = store.get_node(clone_id, np) or {}
        src = node.get("born_from") or ""
        if src.startswith(("http://", "https://")) and node.get("generated_by") == "mirror_placeholder":
            try:
                client = _origin_client()
                r = await client.get(src)
                if r.status_code == 200 and r.content:
                    ctype = r.headers.get("content-type", "application/octet-stream")
                    store.add_node(clone_id, np, r.content, "mirror",
                                   content_type=ctype.split(";")[0].strip())
                    return Response(r.content, media_type=ctype)
            except Exception:
                pass
        ext = os.path.splitext(np)[1].lower()
        if ext == ".js":
            return Response("/* asset placeholder */", media_type="application/javascript")
        if ext == ".css":
            return Response("/* asset placeholder */", media_type="text/css")
        return Response(b"", status_code=404, media_type="application/octet-stream")

    clone = store.get_clone(clone_id)
    base = (clone or {}).get("source_url") or ""
    if not base.startswith(("http://", "https://")):
        return _plain404()
    origin = "/".join(base.split("/")[:3])
    url = f"{origin}/{path.lstrip('/')}"
    try:
        client = _origin_client()
        r = await client.get(url, headers={"Referer": base})
        if r.status_code != 200 or not r.content:
            return Response(r.content, status_code=r.status_code,
                            media_type=r.headers.get("content-type", "text/plain"))
        ctype = r.headers.get("content-type", "application/octet-stream")
        store.add_node(clone_id, norm_path(path), r.content, "proxy",
                       content_type=ctype.split(";")[0].strip())
        return Response(r.content, media_type=ctype)
    except Exception:
        return _plain404()


MAX_PACKET_BODY = 256 * 1024  # 单条报文 body 存库上限（超出截断，防撑爆）


def _clip(text: str) -> str:
    if len(text) > MAX_PACKET_BODY:
        return text[:MAX_PACKET_BODY] + f"\n<!-- ...截断，原始长度 {len(text)} 字节... -->"
    return text


def _record_packet(site, port, clone_id, sid, method, path, query,
                   req_headers, body, resp: Response):
    try:
        store.add_packet(
            site["id"] if site else "", port, clone_id, sid,
            method, "/" + path, redact_query(query),
            json.dumps(redact_headers(req_headers), ensure_ascii=False),
            _clip(redact_payload(body, req_headers.get("content-type", ""))),
            resp.status_code,
            json.dumps(redact_headers(dict(resp.headers)), ensure_ascii=False),
            _clip(redact_payload(
                resp.body.decode("utf-8", "replace") if isinstance(resp.body, (bytes, bytearray))
                else str(resp.body or ""), resp.headers.get("content-type", ""))))
    except Exception:
        pass  # 存档失败不影响拟真服务


async def handle(request, path: str, clone_id: str, site=None) -> Response:
    method = request.method
    sid = ensure_session(request)
    try:
        body = (await request.body()).decode("utf-8", "ignore")
    except Exception:
        body = ""
    query = unquote_plus(str(request.url.query))
    ua = request.headers.get("user-agent", "")
    req_headers = dict(request.headers)
    port = request.scope.get("server", (None, None))[1] if request.scope.get("server") else None

    intent = classifier.classify(ua, path)
    profile = store.session_snapshot(sid)
    agent_profile = {key: profile.get(key) for key in
                     ("agent_score", "agent_label", "agent_signals")}
    intent["agent_profile"] = agent_profile
    if agent_profile["agent_label"] == "强 Agent 行为链" and intent["level"] == "noise":
        intent["level"] = "probe"
        intent["tool"] = "agent_behavior_chain"
    store.touch_session_tool(sid, intent["tool"])  # 纯缓存；旧版这里多查改 2 次 DB
    if intent["level"] == "noise":
        events.broadcast("request.noise", clone_id, sid,
                         f"扫描器请求 {method} /{path}（{intent['tool']}）")

    async def route() -> Response:
        # 1) 陷阱优先（payload 常被 URL 编码，用解码后的 query+body 匹配）
        trap = traps.match_first(path, method, query, unquote_plus(body), req_headers)
        if trap:
            content, media, status = await traps.respond(trap, sid, body, query)
            return Response(content, media_type=media, status_code=status)

        # 2) SiteGraph 命中（缓存应答，热路径）
        node = store.get_node(clone_id, norm_path(path))
        if node:
            return _serve_node(node, sid)

        # 3) 静态资源：代理回源站，不参与生长（防止 JS/CSS 被长成 HTML 导致页面黑屏）
        if is_asset(path):
            return await _proxy_asset(clone_id, path)

        # 4) 生长决策：noise 不生长，probe/human 按配额生长
        events.broadcast("request.miss", clone_id, sid, f"未命中 {method} /{path}（{intent['level']}）")
        if intent["level"] == "noise":
            return _plain404()
        store.add_score(sid, 2, state="PROBING")
        grown = await growth.grow(clone_id, sid, norm_path(path), intent)
        if grown:
            return Response(grown["content"], media_type="text/html")
        return _plain404()

    resp = await route()
    # 完整收发数据包存档（弱口令尝试可见、可按站点/日期/小时导出）
    _record_packet(site, port, clone_id, sid, method, path, query,
                   req_headers, body, resp)
    # 自主 Agent 行为检测：行为序列 + 工具族指纹（内存态，异常不影响拟真服务）
    try:
        agentdetect.observe(sid, request.client.host if request.client else "",
                            method, "/" + path, ua, req_headers, body,
                            resp.status_code)
    except Exception:
        pass
    return resp
