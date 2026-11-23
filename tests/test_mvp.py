"""MVP 冒烟测试：双入口（靶站 8888 / 管理端 9000）+ 靶站挂载绑定（离线，无需任何 LLM Key）"""
import asyncio
import json
import os
import tempfile

os.environ["HP_DB_PATH"] = os.path.join(tempfile.mkdtemp(), "test.db")
os.environ["HP_GROWTH_QUOTA"] = "5"
os.environ["HP_SITE_PORT"] = "8888"

from fastapi.testclient import TestClient  # noqa: E402

from honeypot import classifier, config, engine, store, traps, watermark  # noqa: E402
from honeypot.app_console import app as console_app  # noqa: E402
from honeypot.app_site import app as site_app  # noqa: E402

store.init_db()
traps.load_builtin()
if not store.list_clones():
    engine.seed_site()

site = TestClient(site_app)
console = TestClient(console_app)

# 靶站绑定：TestClient 请求的 server 端口为 80 → 挂载 seed 蜜罐（模拟控制台"创建并挂载"）
store.add_site("演示靶站", 80, "seed", domain="trap.example.com")


def test_watermark_roundtrip():
    sid = "abc123"
    marker = watermark.session_marker(sid)
    assert watermark.decode_marker(marker, [sid, "other", "xyz"]) == sid
    assert watermark.decode_marker(marker, ["other"]) is None


def test_telemetry_redaction():
    from urllib.parse import parse_qs
    from honeypot.redaction import redact_headers, redact_mapping, redact_payload, redact_query
    assert redact_headers({"Authorization": "Bearer abc", "Accept": "text/plain"}) == {
        "Authorization": "[REDACTED]", "Accept": "text/plain"}
    assert parse_qs(redact_query("page=2&access_token=abc"))["access_token"] == ["[REDACTED]"]
    assert "secret-value" not in redact_payload(
        '{"username":"analyst","password":"secret-value"}', "application/json")
    assert "secret-value" not in redact_payload(
        "username=analyst&password=secret-value", "application/x-www-form-urlencoded")
    assert "secret-value" not in redact_payload("password=secret-value", "text/plain")
    raw_json = redact_mapping({"raw": '{"username":"analyst","password":"secret-value"}'})
    assert "secret-value" not in raw_json["raw"]


def test_agent_profile_persistence():
    sid = "agent-profile-test"
    store.get_or_create_session(sid, "127.0.0.1", "agent-test")
    first = store.record_agent_signal(sid, "client_marker", 8)
    second = store.record_agent_signal(sid, "semantic_followthrough", 30)
    profile = next(row for row in store.list_sessions() if row["id"] == sid)
    assert first["agent_label"] == "候选线索"
    assert second["agent_label"] == "疑似 Agent 行为"
    assert profile["agent_score"] == 38
    assert profile["agent_signals"] == ["client_marker", "semantic_followthrough"]


def test_delete_session_profiles_and_related_data():
    deleted_ids = ["delete-profile-one", "delete-profile-two"]
    keep_id = "keep-profile"
    for sid in deleted_ids + [keep_id]:
        store.get_or_create_session(sid, "127.0.0.1", sid)
        store.add_event("test.event", "seed", sid, f"event for {sid}")
        store.add_packet("site", 80, "seed", sid, "GET", "/test", "", "{}", "", 200, "{}", "ok")
        store.add_token(f"token-{sid}", sid, "test")

    single = console.delete(f"/api/sessions/{deleted_ids[0]}")
    assert single.json() == {"ok": True, "deleted": 1}
    bulk = console.request("DELETE", "/api/sessions", json={"session_ids": deleted_ids})
    assert bulk.json() == {"ok": True, "deleted": 1}
    assert all(row["id"] != sid for row in store.list_sessions() for sid in deleted_ids)
    assert store.list_events(session_id=deleted_ids[0]) == []
    assert store.list_events(session_id=deleted_ids[1]) == []
    assert store.list_packets(session_id=deleted_ids[0]) == []
    assert store.list_packets(session_id=deleted_ids[1]) == []
    assert any(row["id"] == keep_id for row in store.list_sessions())
    assert any(row["session_id"] == keep_id for row in store.list_tokens())


def test_classifier():
    assert classifier.classify("sqlmap/1.7", "/index")["level"] == "noise"
    assert classifier.classify("Mozilla/5.0", "/.git/config")["level"] == "probe"
    assert classifier.classify("Mozilla/5.0", "/login")["level"] == "human"


def test_site_serves_bound_clone():
    """靶站 8888 已挂载 seed 蜜罐 → 应答其内容"""
    r = site.get("/index")
    assert r.status_code == 200 and config.PERSONA in r.text


def test_unbound_port_placeholder():
    """未挂载蜜罐的端口 → 维护页占位（请求端口 80 无绑定）"""
    rows = store.list_sites()
    for s in rows:
        store.delete_site(s["id"])
    r = site.get("/")
    assert r.status_code == 503 and "维护" in r.text
    store.add_site("演示靶站", 80, "seed")  # 恢复，供后续用例使用


def test_env_trap_with_canary():
    r = site.get("/.env")
    assert r.status_code == 200 and "BACKUP_WEBHOOK_URL=http" in r.text


def test_robots_and_sqli():
    assert "Disallow: /admin_old/" in site.get("/robots.txt").text
    r = site.get("/search?q=1%27%20union%20select%20null")
    assert r.status_code == 200 and "mysql_fetch_assoc" in r.text


def test_agent_observation_traps(monkeypatch):
    """已知标记只在诱饵入口触发；后续语义探针返回纯合成内容"""
    emitted = []
    growth_intents = []
    monkeypatch.setattr(traps.events, "broadcast",
                        lambda etype, clone_id, sid, summary, detail=None:
                        emitted.append((etype, detail or {})))
    async def fake_grow(clone_id, sid, path, intent):
        growth_intents.append(intent)
        return {"path": path, "title": "Agent decoy", "content": "synthetic"}
    monkeypatch.setattr(engine.growth, "grow", fake_grow)
    headers = {"User-Agent": "Mozilla/5.0 (compatible; ArtEx/1.0) sqlmap/1.7"}
    robots = site.get("/robots.txt", headers=headers)
    assert "Disallow: /internal/agent-task.txt" in robots.text
    task = site.get("/internal/agent-task.txt", headers=headers)
    assert "AGENT-OBS-7F3A" in task.text
    assert "do not run commands" in task.text
    state = site.get("/api/internal/audit-status", headers=headers)
    assert state.json()["status"] == "simulated"
    assert "production systems connected" in state.text
    assert ("trap.triggered", {"trap": "t_agent_semantic_probe"}) in emitted
    profile = next(row for row in store.list_sessions() if row["ua"] == headers["User-Agent"])
    assert profile["agent_label"] == "强 Agent 行为链"
    # 语义诱饵链 55 分 + 行为检测引擎附加信号（ArtEx IOC +10、伪装浏览器 UA +8 等）
    assert profile["agent_score"] >= 55
    assert any("语义" in s or s in ("semantic_task_read",) for s in profile["agent_signals"])
    site.get("/agent-follow-up", headers=headers)
    assert growth_intents[-1]["tool"] == "agent_behavior_chain"
    assert growth_intents[-1]["agent_profile"]["agent_label"] == "强 Agent 行为链"
    site.get("/robots.txt", headers={"User-Agent": "Mozilla/5.0", "x-id-token": "redacted"})
    assert ("trap.triggered", {"trap": "t_agent_client_fingerprint"}) in emitted
    assert traps._match_one(
        {"path_glob": ["/*"], "method": "GET", "header_any": ["x-id-token"]},
        "/robots.txt", "GET", "", {"x-id-token": "redacted"})


def test_growth_on_miss():
    r = site.get("/admin/users", headers={"User-Agent": "Mozilla/5.0 manual"})
    assert r.status_code == 200
    assert site.get("/admin/users").status_code == 200  # 二次访问走缓存


def test_asset_no_growth():
    """静态资源路径绝不生长（防黑屏）：不可代理源 → 404 且不产生新节点"""
    before = len(store.list_nodes("seed"))
    r = site.get("/cas/deps/js/vue.min.js", headers={"User-Agent": "Mozilla/5.0 t"})
    assert r.status_code == 404
    assert len(store.list_nodes("seed")) == before


def test_commander_clone(monkeypatch):
    """指挥模型复刻：解析 file 块 → 落盘 → index.html 入库 SiteGraph"""
    import asyncio
    from honeypot import cloner
    llm_out = ('```file:index.html\n<!DOCTYPE html><html><head><style>body{color:#123}'
               'nav a{margin:8px}.card{border:1px solid #eee;padding:16px}</style>'
               '</head><body><nav><a href="/">首页</a><a href="/login">登录</a></nav>'
               '<h1>测试站点</h1><div class="card">一站式电商 SaaS 服务平台</div>'
               '<form action="/admin/login" method="post">'
               '<input name="username"><input name="password" type="password"></form>'
               '<footer>© 2023 测试站点</footer></body></html>\n```'
               '\n```file:decoys/vip.html\n<h1>内部 VIP 数据</h1>\n```')
    async def fake_chat(messages, **kw):
        return llm_out, "test-provider"
    monkeypatch.setattr(cloner.llm_gateway, "chat", fake_chat)
    monkeypatch.setattr(cloner.growth, "dlp_scan", lambda x: x)
    import httpx as _hx
    class FakeResp:
        text = "<html><title>Target Portal</title><body>hello</body></html>"
        url = "https://src.example.com/"
        def raise_for_status(self): pass
    async def fake_get(self, url):
        return FakeResp()
    monkeypatch.setattr(_hx.AsyncClient, "get", fake_get)

    cid = asyncio.run(cloner.run_clone("https://src.example.com/", "测试站点（测试）"))
    assert store.get_clone(cid)["status"] == "DEPLOYED"
    node = store.get_node(cid, "/index")
    assert node and "测试站点" in node["content"] and 'action="/admin/login"' in node["content"]
    assert (cloner._SITES_DIR / cid / "decoys" / "vip.html").exists()
    # 静态自检函数
    assert cloner._static_audit({"index.html": "<html></html>"})
    parsed = cloner._parse_files(llm_out)
    assert not cloner._static_audit(parsed)


def test_provider_mgmt_and_commander():
    """Provider CRUD + 指挥模型指定 + 路由优先级"""
    from honeypot import llm_gateway
    pid = console.post("/api/llm/providers", json={
        "name": "ut-provider", "endpoint": "http://127.0.0.1:9/v1", "model": "ut"}).json()["id"]
    assert any(p["id"] == pid for p in console.get("/api/llm/providers").json())
    # 指定指挥模型
    assert console.put("/api/llm/commander", json={"provider_id": pid}).json()["ok"]
    assert llm_gateway.commander()["id"] == pid
    # 路由：指挥模型排最前（本地不可达 → 降级尝试其余，但顺序正确）
    names = [p["name"] for p in llm_gateway._providers()]
    assert names[0] == "ut-provider"
    # 删除后指挥位清空
    assert console.delete(f"/api/llm/providers/{pid}").json()["ok"]
    assert llm_gateway.commander() is None


def test_fake_login_flow():
    """错误凭据恒失败并置 401；只有命中弱口令库才放行 MFA → 假后台"""
    s = {"User-Agent": "Mozilla/5.0 brute-test"}
    # 错误凭据：恒失败，与尝试次数无关
    for _ in range(3):
        r = site.post("/admin/login", data={"u": "a", "p": "b"}, headers=s)
        assert r.status_code == 401 and "错误" in r.text
    # 弱口令命中 → 二次验证挑战
    r2 = site.post("/admin/login", data={"u": "admin", "p": "987987"}, headers=s)
    assert r2.status_code == 200 and "安全验证" in r2.text
    # 验证码提交 → 放行
    r3 = site.post("/admin/mfa/verify", data={"code": "123456"}, headers=s)
    assert r3.status_code == 200 and "验证通过" in r3.text
    # 已通过二次验证 → 直接进假后台
    r4 = site.post("/admin/login", data={"u": "admin", "p": "987987"}, headers=s)
    assert r4.status_code == 200 and "运营管理后台" in r4.text
    # 用户名大小写不敏感，口令精确匹配
    r5 = site.post("/admin/login", data={"u": "ADMIN", "p": "987987"}, headers=s)
    assert r5.status_code == 200


def test_credential_capture(monkeypatch):
    """AJAX 登录接管：POST */login 带 password 字段 → 记录凭据并返回 JSON 错误"""
    emitted = []
    from honeypot import events
    original_broadcast = events.broadcast
    def capture_event(etype, clone_id, sid, summary, detail=None):
        emitted.append((etype, summary, detail or {}))
        original_broadcast(etype, clone_id, sid, summary, detail)
    monkeypatch.setattr(events, "broadcast", capture_event)
    s = {"User-Agent": "Mozilla/5.0 cred-test"}
    r = site.post("/cas/login", data={"username": "admin", "password": "P@ssw0rd"}, headers=s)
    assert r.status_code == 401
    data = r.json()
    assert data["success"] is False and "错误" in data["error"]
    # JSON 提交体也能捕获（Vue AJAX 常见形态）
    r2 = site.post("/cas/login", json={"username": "root", "password": "123456"}, headers=s)
    assert r2.json()["success"] is False
    # 与后台登录共用弱口令库：命中即放行
    r_ok = site.post("/cas/login", data={"username": "admin", "password": "987987"}, headers=s)
    assert r_ok.status_code == 200 and r_ok.json()["success"] is True
    # 不带 password 的 POST 不应命中凭据陷阱
    r3 = site.post("/cas/other", data={"foo": "bar"}, headers=s)
    assert r3.headers.get("content-type", "").startswith("text/html") or r3.status_code in (200, 404)
    credential_events = [e for e in emitted if e[0] == "trap.credential"]
    assert credential_events and all("P@ssw0rd" not in e[1] for e in credential_events)
    assert all("[REDACTED]" in e[1] for e in credential_events)


def test_weak_credentials_dynamic():
    """弱口令库动态化：写入后立即生效，出厂引导值自动失效；可清空回落"""
    s = {"User-Agent": "Mozilla/5.0 weak-dyn"}
    # 出厂引导值初始生效
    assert site.post("/admin/login", data={"u": "admin", "p": "987987"},
                     headers=s).status_code == 200
    # LLM / 控制台写入全局弱口令 → 出厂值失效
    r = console.post("/api/weak-credentials",
                     json={"credentials": [["ops", "Ops!2026"]]}).json()
    assert r["ok"] and r["credentials"] == [["ops", "Ops!2026"]]
    bad = site.post("/admin/login", data={"u": "admin", "p": "987987"}, headers=s)
    assert bad.status_code == 401 and "错误" in bad.text
    ok = site.post("/admin/login", data={"u": "ops", "p": "Ops!2026"}, headers=s)
    assert ok.status_code == 200 and "安全验证" in ok.text
    # 控制台可读回当前库
    st = console.get("/api/weak-credentials").json()
    assert ["ops", "Ops!2026"] in st["global"]
    # 非法格式被拒
    assert console.post("/api/weak-credentials",
                        json={"credentials": ["ops"]}).json()["ok"] is False
    # 清空 → 回落到出厂引导值
    console.post("/api/weak-credentials", json={"credentials": []})
    assert site.post("/admin/login", data={"u": "admin", "p": "987987"},
                     headers=s).status_code == 200


def test_llm_can_set_credentials_and_target_site(monkeypatch):
    """LLM 编排：可自行设定弱口令，也可把陷阱定向到具体靶站"""
    ops = [{"op": "set_credentials", "scope": "",
            "credentials": [["root", "Root#2026"]], "reason": "设定放行凭据"},
           {"op": "add",
            "trap": {"id": "t_site_scoped", "name": "定向靶站配置泄漏",
                     "match": {"path_glob": ["/internal/deploy.yaml"],
                               "method": "GET", "site": ["seed"]},
                     "respond": {"strategy": "custom",
                                 "body": "db: password: fake-secret", "media_type": "text/plain"}},
            "reason": "只对 seed 靶站生效"}]

    async def fake_chat(messages, **kw):
        return json.dumps(ops), "fake-model"

    monkeypatch.setattr(traps.llm_gateway, "chat", fake_chat)
    res = asyncio.run(traps.auto_evolve("生成陷阱"))
    assert res["ok"], res
    # 弱口令库已被 LLM 改写
    assert ("root", "Root#2026") in traps.weak_credentials()
    # 定向陷阱已入库
    row = next(t for t in store.list_traps() if t["id"] == "t_site_scoped")
    assert "seed" in json.loads(row["match_json"])["site"]
    # 只对定向靶站命中，其它靶站不命中
    hit = traps.match_first("/internal/deploy.yaml", "GET", "", "",
                            scope=("seed",))
    assert hit and hit["id"] == "t_site_scoped"
    assert traps.match_first("/internal/deploy.yaml", "GET", "", "",
                             scope=("other-site",)) is None
    # 还原
    traps.set_weak_credentials([], "")
    store.delete_trap("t_site_scoped")


def test_trap_level_weak_credentials():
    """陷阱级专属凭据：LLM 可为单个假登录陷阱单独设定账号口令"""
    store.load_trap("t_own_cred", "专属凭据假登录",
                    {"path": "/ops/console", "method": "POST"},
                    {"strategy": "fake_login",
                     "weak_credentials": [["sre", "Sre@2026"]]})
    try:
        r = site.post("/ops/console", data={"u": "sre", "p": "Sre@2026"},
                      headers={"User-Agent": "Mozilla/5.0 own-cred"})
        assert r.status_code == 200 and "安全验证" in r.text
        r2 = site.post("/ops/console", data={"u": "nobody", "p": "wrongpass"},
                       headers={"User-Agent": "Mozilla/5.0 own-cred"})
        assert r2.status_code == 401
    finally:
        store.delete_trap("t_own_cred")


def test_console_site_mgmt():
    """控制台：靶站 CRUD + 挂载校验"""
    rows = console.get("/api/sites").json()
    assert any(s["port"] == 80 and s["clone_id"] == "seed" for s in rows)
    # 挂载不存在的蜜罐 → 拒绝
    r = console.post("/api/sites", json={"name": "x", "port": 8890, "clone_id": "nope"}).json()
    assert "不存在" in r.get("error", "")
    # 端口冲突 → 拒绝
    r = console.post("/api/sites", json={"name": "x", "port": 80, "clone_id": "seed"}).json()
    assert "已绑定" in r.get("error", "")
    # 正常新建 + 删除
    r = console.post("/api/sites", json={"name": "新靶站", "port": 8890, "clone_id": "seed"}).json()
    assert r["ok"]
    assert console.delete(f"/api/sites/{r['id']}").json()["ok"]


def test_console_api():
    assert console.get("/console").status_code == 200
    ov = console.get("/api/overview").json()
    assert {"requests", "sessions", "trap_hits", "nodes", "callbacks", "sites"} <= set(ov)


def test_canary_callback():
    toks = store.list_tokens()
    if toks:
        r = site.get(f"/t/{toks[0]['token_id']}")
        assert r.status_code == 200 and r.headers["content-type"] == "image/gif"


def test_webrtc_leak_attribution():
    """WebRTC 真实 IP 溯源：srflx → real_ip，host → internal_ip，非法 candidate 忽略"""
    s = {"User-Agent": "Mozilla/5.0 webrtc-test"}
    site.get("/index", headers=s)  # 建立会话
    # srflx：真实公网出口（模拟已穿透 HTTP 代理）
    r = site.post("/api/webrtc-leak", headers=s, json={
        "candidate": "candidate:842163049 1 udp 1677729535 203.0.113.77 54400 typ srflx "
                     "raddr 192.168.1.5 rport 54400 generation 0"})
    assert r.json() == {"status": "ok", "type": "srflx"}
    # host：内网指纹
    r2 = site.post("/api/webrtc-leak", headers=s, json={
        "candidate": "candidate:1 1 udp 2130706431 192.168.1.5 54400 typ host generation 0"})
    assert r2.json() == {"status": "ok", "type": "host"}
    # 非法 candidate → 忽略
    assert site.post("/api/webrtc-leak", headers=s, json={"candidate": "garbage"}).json()["status"] == "ignored"
    # 会话画像已写入
    sess = store.list_sessions()
    row = next(x for x in sess if x["ua"].startswith("Mozilla/5.0 webrtc-test"))
    assert row["real_ip"] == "203.0.113.77" and row["internal_ip"] == "192.168.1.5"
    # 事件已记录
    evs = console.get("/api/events").json()
    assert any(e["type"] == "attribution.webrtc" and "203.0.113.77" in e["summary"] for e in evs)


def test_webrtc_snippet_injection(monkeypatch):
    """L2+ 会话 HTML 注入 WebRTC 采集脚本；低分页面不注入（防指纹）"""
    monkeypatch.setattr(engine.config, "WEBRTC_ATTRIBUTION", True)
    s = {"User-Agent": "Mozilla/5.0 snip-test"}
    site.get("/index", headers=s)  # 低分：无脚本
    assert "RTCPeerConnection" not in site.get("/index", headers=s).text
    for _ in range(12):
        store.add_score(next(x["id"] for x in store.list_sessions()
                             if x["ua"].startswith("Mozilla/5.0 snip-test")), 1)
    assert "RTCPeerConnection" in site.get("/index", headers=s).text


def test_packet_compression_roundtrip():
    """报文压缩存储：写入 → 落库压缩 → 读回原文完全一致（含不可压缩内容）"""
    # 可压缩的大报文
    body = "username=admin&password=" + ("A" * 8000)
    resp = "B" * 20000
    store.add_packet("st1", 8899, "c9", "s9", "POST", "/compress", "q=1",
                     '{"UA":"x"}', body, 200, '{"CT":"text/html"}', resp)
    # 不可压缩内容（随机字节近似）：早期版本会因「压缩流/原始 bytes」不可区分而丢数据
    import os as _os
    noise = "".join(chr(33 + (_os.urandom(1)[0] % 90)) for _ in range(6000))
    store.add_packet("st1", 8899, "c9", "s9", "POST", "/noise", "",
                     "{}", noise, 200, "{}", noise)

    rows = {r["path"]: r for r in store.list_packets(limit=50)}
    assert rows["/compress"]["req_body"] == body
    assert rows["/compress"]["resp_body"] == resp
    assert rows["/noise"]["req_body"] == noise
    assert rows["/noise"]["resp_body"] == noise
    # 小报文保持明文
    store.add_packet("st1", 8899, "c9", "s9", "GET", "/small", "", "{}", "ping", 200, "{}", "pong")
    rows = {r["path"]: r for r in store.list_packets(limit=50)}
    assert rows["/small"]["resp_body"] == "pong"
    # 凭据命中过滤（has_cred 标记替代 LIKE 扫描，压缩后依然可用）
    creds = store.list_packets(only_credential=True, limit=50)
    assert any(r["path"] == "/compress" for r in creds)


def test_cross_db_sql_guard():
    """分库路由：跨库 SQL 必须显式指定 db，同库 JOIN 正常"""
    import pytest
    with pytest.raises(ValueError):
        store.q("SELECT * FROM sites JOIN sessions ON 1=1")
    # 同库 JOIN（sites/clones 同在 site 库）不应被拦截
    store.q("SELECT * FROM sites JOIN clones ON 1=1", fetch=True)
