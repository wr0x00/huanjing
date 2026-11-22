"""管理控制台入口（默认 9000）：控制台静态页 + 全部管理 API + SSE + Canary 回连"""
import asyncio
import json

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles

from . import agentdetect, cloner, clone_runner, config, engine, events, instances, livelog, llm_chat, llm_gateway, store
from .common_routes import router as common_router

app = FastAPI(title="AI Honeypot Console", docs_url=None, redoc_url=None)
app.include_router(common_router)


@app.on_event("startup")
def startup():
    engine.init_runtime()


# ---------------- SSE ----------------
@app.get("/sse/stream")
async def sse_stream():
    q = events.subscribe()

    async def gen():
        try:
            while True:
                try:
                    data = await asyncio.wait_for(q.get(), timeout=15)
                    yield f"data: {data}\n\n"
                except asyncio.TimeoutError:
                    yield ": ping\n\n"
        finally:
            events.unsubscribe(q)

    return StreamingResponse(gen(), media_type="text/event-stream")


# ---------------- 管理端 API ----------------
@app.get("/api/overview")
async def api_overview():
    return store.overview()


@app.get("/api/events")
async def api_events(limit: int = 100, type: str | None = None):
    return store.list_events(limit=limit, etype=type)


@app.get("/api/sessions")
async def api_sessions():
    rows = store.list_sessions()
    for r in rows:
        sigs = r.get("agent_signals") or []
        r["agent_guess"] = agentdetect.identity_guess(sigs)
        r["families"] = agentdetect.session_families(r["id"], r.get("ua") or "")
        r["agent_evidence"] = [store.signal_desc(x) for x in sigs]
    return rows


@app.delete("/api/sessions")
async def api_delete_sessions(request: Request):
    body = await request.json()
    ids = body.get("session_ids")
    if not isinstance(ids, list):
        return {"error": "session_ids 必须是数组"}
    deleted = store.delete_sessions(ids)
    return {"ok": True, "deleted": deleted}


@app.delete("/api/sessions/{session_id}")
async def api_delete_session(session_id: str):
    deleted = store.delete_sessions([session_id])
    return {"ok": deleted == 1, "deleted": deleted}


@app.get("/api/clones")
async def api_clones():
    return store.list_clones()


@app.post("/api/clones")
async def api_create_clone(request: Request):
    body = await request.json()
    source_url, persona = body.get("source_url", ""), body.get("persona") or config.PERSONA
    if not source_url.startswith(("http://", "https://")):
        return {"error": "source_url 必须以 http(s):// 开头"}
    clone_id = await clone_runner.start(source_url, persona)
    return {"ok": True, "clone_id": clone_id, "note": "任务已后台启动，监控窗口实时可见 LLM 产出"}


@app.post("/api/clones/{clone_id}/pause")
async def api_pause_clone(clone_id: str):
    """暂停克隆任务：后台协程立即取消（LLM 调用断开），状态清理为已暂停"""
    return clone_runner.pause(clone_id)


@app.post("/api/clones/{clone_id}/command")
async def api_clone_command(clone_id: str, request: Request):
    """对话框指令：即时 LLM 回应（流式直播）；任务运行中同时注入下一阶段提示词"""
    body = await request.json()
    text = str(body.get("text") or "").strip()
    if not text:
        return {"error": "消息不能为空"}
    if len(text) > 2000:
        return {"error": "消息过长（≤2000 字）"}
    return clone_runner.command(clone_id, text)


@app.delete("/api/clones/{clone_id}")
async def api_delete_clone(clone_id: str):
    if not store.get_clone(clone_id):
        return {"error": "蜜罐不存在"}
    if clone_id == "seed":
        return {"error": "出厂种子蜜罐不允许删除"}
    store.delete_clone(clone_id)
    events.broadcast("clone.deleted", clone_id, "-", f"蜜罐 {clone_id} 已删除")
    return {"ok": True}


# ---- 完整数据包日志：查询 / 弱口令 / 导出（按站点+日期+小时） ----
@app.get("/api/logs")
async def api_logs(session_id: str | None = None, limit: int = 300):
    evs = store.list_events(limit=limit, session_id=session_id)
    out = []
    for e in evs:
        item = dict(e)
        try:
            item["detail"] = json.loads(e["detail"]) if e["detail"] else None
        except Exception:
            item["detail"] = e["detail"]
        out.append(item)
    return out


@app.get("/api/packets")
async def api_packets(session_id: str | None = None, site_id: str | None = None,
                      start: str | None = None, end: str | None = None, limit: int = 300):
    # light=True：列表不取四个正文字段（300 条从 ~60ms 降到 ~1ms）；导出走 /api/logs/export 全文
    return store.list_packets(site_id=site_id, session_id=session_id,
                              start=start, end=end, limit=limit, light=True)


@app.get("/api/packets/credentials")
async def api_credentials(session_id: str | None = None, site_id: str | None = None):
    """攻击者尝试过的弱口令（从完整请求体解析 username/password 字段）"""
    from urllib.parse import parse_qsl
    rows = store.list_packets(site_id=site_id, session_id=session_id,
                              only_credential=True, limit=200)
    out = []
    for p in rows:
        fields = dict(parse_qsl(p["req_body"] or "", keep_blank_values=True))
        if not any(("password" in k.lower() or "passwd" in k.lower() or "pwd" in k.lower())
                   for k in fields):
            continue  # 请求体含 password 字样但解析不出键值对（JSON/AJAX 场景原样展示）
        out.append({"ts": p["ts"], "session_id": p["session_id"], "port": p["port"],
                    "path": p["path"],
                    "username": next((v for k, v in fields.items()
                                      if "user" in k.lower() or "name" in k.lower() or "email" in k.lower()), ""),
                    "password": next((v for k, v in fields.items()
                                      if "password" in k.lower() or "passwd" in k.lower() or "pwd" in k.lower()), ""),
                    "raw": p["req_body"][:500]})
    return out


@app.get("/api/logs/export")
async def api_logs_export(session_id: str | None = None, site_id: str | None = None,
                          start: str | None = None, end: str | None = None,
                          fmt: str = "json"):
    """导出攻击活动日志（流式输出，支持大数据量），仅支持 JSON / CSV：
    - site_id 有值：导出完整收发数据包（结构化 + 可复现 raw）
    - 否则：导出事件流水"""
    import csv as _csv
    import datetime
    import io as _io
    from urllib.parse import quote

    from starlette.responses import StreamingResponse

    if site_id:
        site = next((s for s in store.list_sites() if s["id"] == site_id), {})
        sname = site.get("name", site_id) or site_id
        total = store.count_packets(site_id=site_id, session_id=session_id, start=start, end=end)
        kw = dict(site_id=site_id, session_id=session_id, start=start, end=end)

        def _loads(s):
            try:
                return json.loads(s or "{}")
            except Exception:
                return {}

        def _raw(p):
            """完整原始报文：可直接粘进 BurpSuite Repeater 复现"""
            rh, sh = _loads(p["req_headers"]), _loads(p["resp_headers"])
            line = f"{p['method']} {p['path']}" + (f"?{p['query']}" if p["query"] else "") + " HTTP/1.1\r\n"
            line += "\r\n".join(f"{k}: {v}" for k, v in rh.items())
            if p["req_body"]:
                line += "\r\n\r\n" + p["req_body"]
            rline = f"HTTP/1.1 {p['status']}\r\n" + "\r\n".join(f"{k}: {v}" for k, v in sh.items())
            if p["resp_body"]:
                rline += "\r\n\r\n" + p["resp_body"]
            return line, rline

        if fmt != "csv":
            # 默认 JSON：结构化 + 可复现 raw，输出 2 空格缩进（人力可读）
            meta = {"site": sname, "port": site.get("port", "-"), "total": total,
                    "start": start, "end": end,
                    "exported": datetime.datetime.now().isoformat(timespec="seconds")}

            def gen():
                yield ('{\n  "meta": '
                       + json.dumps(meta, ensure_ascii=False, indent=2).replace("\n", "\n  ")
                       + ',\n  "packets": [')
                first = True
                for p in store.iter_packets(**kw):
                    req, resp = _raw(p)
                    obj = {"id": p["id"], "ts": p["ts"], "site_id": p["site_id"], "port": p["port"],
                           "clone_id": p["clone_id"], "session_id": p["session_id"],
                           "method": p["method"], "path": p["path"], "query": p["query"],
                           "request": {"headers": _loads(p["req_headers"]), "body": p["req_body"], "raw": req},
                           "response": {"status": p["status"], "headers": _loads(p["resp_headers"]),
                                        "body": p["resp_body"], "raw": resp}}
                    yield ("" if first else ",") + "\n    " + json.dumps(
                        obj, ensure_ascii=False, indent=2).replace("\n", "\n    ")
                    first = False
                yield "\n  ]\n}\n"
            name = f"packets_{sname}_{(start or 'earliest').replace(':', '')}_{(end or 'latest').replace(':', '')}.json"
            return StreamingResponse(gen(), media_type="application/json; charset=utf-8",
                                     headers={"Content-Disposition": f"attachment; filename*=UTF-8''{quote(name)}"})

        if fmt == "csv":
            def gen():
                buf = _io.StringIO()
                w = _csv.writer(buf)
                w.writerow(["id", "ts", "port", "session_id", "clone_id", "method", "path",
                            "query", "status", "req_headers", "req_body", "resp_headers", "resp_body", "req_raw"])
                yield "\ufeff" + buf.getvalue()
                buf.seek(0); buf.truncate()
                for p in store.iter_packets(**kw):
                    req, _ = _raw(p)
                    w.writerow([p["id"], p["ts"], p["port"], p["session_id"], p["clone_id"],
                                p["method"], p["path"], p["query"], p["status"],
                                p["req_headers"], p["req_body"], p["resp_headers"], p["resp_body"], req])
                    yield buf.getvalue()
                    buf.seek(0); buf.truncate()
            name = f"packets_{sname}_{(start or 'earliest').replace(':', '')}_{(end or 'latest').replace(':', '')}.csv"
            return StreamingResponse(gen(), media_type="text/csv; charset=utf-8",
                                 headers={"Content-Disposition": f"attachment; filename*=UTF-8''{quote(name)}"})

    # 事件流水导出（JSON / CSV）
    evs = store.list_events(limit=1000, session_id=session_id)
    evs_out = [{"ts": e["ts"], "type": e["type"], "session_id": e["session_id"],
                "clone_id": e["clone_id"], "summary": e["summary"], "detail": e["detail"]}
               for e in reversed(evs)]
    if fmt == "csv":
        def gen():
            buf = _io.StringIO()
            w = _csv.writer(buf)
            w.writerow(["ts", "type", "session_id", "clone_id", "summary", "detail"])
            yield "\ufeff" + buf.getvalue()
            buf.seek(0); buf.truncate()
            for e in evs_out:
                w.writerow([e["ts"], e["type"], e["session_id"], e["clone_id"],
                            e["summary"], e["detail"] or ""])
                yield buf.getvalue()
                buf.seek(0); buf.truncate()
        name = f"honeypot_logs_{session_id or 'all'}.csv"
        return StreamingResponse(gen(), media_type="text/csv; charset=utf-8",
                                 headers={"Content-Disposition": f"attachment; filename*=UTF-8''{quote(name)}"})
    body = json.dumps({"exported": datetime.datetime.now().isoformat(timespec="seconds"),
                       "session_id": session_id, "total": len(evs_out), "events": evs_out},
                      ensure_ascii=False, indent=2)
    name = f"honeypot_logs_{session_id or 'all'}.json"
    return Response(body, media_type="application/json; charset=utf-8",
                    headers={"Content-Disposition": f"attachment; filename*=UTF-8''{quote(name)}"})


# ---- 设置（日志保留天数等） ----
@app.get("/api/settings")
async def api_get_settings():
    return {"log_retention_days": int(store.get_setting("log_retention_days", 7) or 7)}


@app.put("/api/settings")
async def api_put_settings(request: Request):
    body = await request.json()
    if "log_retention_days" in body:
        days = max(1, int(body["log_retention_days"]))
        store.set_setting("log_retention_days", days)
        events.broadcast("settings.updated", "-", "-", f"日志保留天数设为 {days} 天")
    return await api_get_settings()


@app.on_event("startup")
def start_retention_cleaner():
    """按设置定期清理过期数据包日志，并回收日志库磁盘空间"""
    import threading, time as _t
    def loop():
        while True:
            try:
                days = int(store.get_setting("log_retention_days", 7) or 7)
                store.delete_old_packets(days)
                store.vacuum_logs()   # DELETE 只标记空闲页，VACUUM 才把文件压回实际大小
            except Exception:
                pass
            _t.sleep(600)
    threading.Thread(target=loop, daemon=True).start()


@app.get("/api/storage")
async def api_storage():
    """分库存储自检：各库体积与表行数"""
    return store.db_stats()


@app.get("/api/charts")
async def api_charts():
    """大屏图表数据：24h 趋势 / 事件分布 / 陷阱 TOP / 体积占比 / 评分分布 / 高频路径"""
    return store.chart_stats()


# ---- 靶站管理：配置靶站（域名/端口）并挂载蜜罐 ----
@app.get("/api/sites")
async def api_sites():
    clones = {c["id"]: c for c in store.list_clones()}
    out = []
    for s in store.list_sites():
        c = clones.get(s["clone_id"], {})
        out.append({**s, "clone_status": c.get("status", "?"),
                    "clone_source": c.get("source_url", "?")})
    return out


@app.post("/api/sites")
async def api_add_site(request: Request):
    body = await request.json()
    name = (body.get("name") or "").strip()
    port = body.get("port")
    clone_id = body.get("clone_id")
    if not name or not port or not clone_id:
        return {"error": "name / port / clone_id 必填"}
    if not store.get_clone(clone_id):
        return {"error": f"蜜罐 {clone_id} 不存在"}
    if store.get_site_by_port(int(port)):
        return {"error": f"端口 {port} 已绑定其他靶站（一个端口一个靶站实例）"}
    sid = store.add_site(name, int(port), clone_id,
                         body.get("domain") or "", bool(body.get("enabled", True)))
    return {"ok": True, "id": sid}


@app.put("/api/sites/{site_id}")
async def api_update_site(site_id: str, request: Request):
    body = await request.json()
    if "port" in body and body["port"]:
        existed = store.get_site_by_port(int(body["port"]))
        if existed and existed["id"] != site_id:
            return {"error": f"端口 {body['port']} 已被占用"}
    store.update_site(site_id, **body)
    return {"ok": True}


@app.delete("/api/sites/{site_id}")
async def api_delete_site(site_id: str):
    store.delete_site(site_id)
    return {"ok": True}


# ---- 靶站实例（模板复制 + 独立进程 + LLM 增删改查） ----
@app.get("/api/instances")
async def api_instances():
    return instances.list_instances()


@app.get("/api/instances/{site_id}/files")
async def api_instance_files(site_id: str):
    return instances.list_files(site_id)


@app.get("/api/instances/{site_id}/file")
async def api_instance_read(site_id: str, path: str):
    try:
        return {"ok": True, "path": path, "content": instances.read_file(site_id, path)}
    except FileNotFoundError:
        return {"error": f"文件不存在: {path}"}
    except PermissionError:
        return {"error": "路径越界"}


@app.put("/api/instances/{site_id}/file")
async def api_instance_write(site_id: str, request: Request):
    body = await request.json()
    rel, content = str(body.get("path") or ""), body.get("content")
    if not rel or content is None:
        return {"error": "path / content 必填"}
    try:
        r = instances.write_file(site_id, rel, str(content), dlp=not body.get("no_dlp"))
    except (PermissionError, FileNotFoundError) as e:
        return {"error": str(e)}
    return r


@app.delete("/api/instances/{site_id}/file")
async def api_instance_delete(site_id: str, path: str):
    try:
        return instances.delete_file(site_id, path)
    except FileNotFoundError:
        return {"error": f"文件不存在: {path}"}
    except PermissionError:
        return {"error": "路径越界"}


def _get_site(site_id: str) -> dict | None:
    return next((s for s in store.list_sites() if s["id"] == site_id), None)


@app.post("/api/instances/{site_id}/restart")
async def api_instance_restart(site_id: str):
    site = _get_site(site_id)
    if not site:
        return {"error": "靶站不存在"}
    pid = instances.restart(site_id, int(site["port"]))
    return {"ok": True, "pid": pid, "status": instances.status(site_id)}


@app.post("/api/instances/{site_id}/evolve")
async def api_instance_evolve(site_id: str, request: Request):
    """LLM 依据实时攻击态势对靶站实例文件增删改查，应用后自动重启实例"""
    body = await request.json()
    site = _get_site(site_id)
    if not site:
        return {"error": "靶站不存在"}
    r = await instances.evolve(site_id, int(site["port"]), str(body.get("instruction") or ""))
    return r


@app.post("/api/instances/{site_id}/command")
async def api_site_command(site_id: str, request: Request):
    """靶站 LLM 对话框：自由指挥真实运行的靶站（功能增减等），回复实时直播"""
    body = await request.json()
    text = str(body.get("text") or "").strip()
    if not text:
        return {"error": "消息不能为空"}
    if len(text) > 2000:
        return {"error": "消息过长（≤2000 字）"}
    site = _get_site(site_id)
    port = int(site["port"]) if site else 0
    return instances.site_command(site_id, port, text)


@app.get("/api/sitegraph/{clone_id}")
async def api_sitegraph(clone_id: str):
    return {"clone": store.get_clone(clone_id), "nodes": store.list_nodes(clone_id),
            "ledger": store.list_ledger(clone_id)}


@app.get("/api/sitegraph/{clone_id}/node")
async def api_sitegraph_node(clone_id: str, path: str):
    """按需读取单个节点源码（文件树点开预览用）"""
    n = store.get_node(clone_id, path)
    if not n:
        return {"error": "节点不存在"}
    return {"path": n["path"], "title": n.get("title", ""),
            "generated_by": n.get("generated_by", ""), "born_from": n.get("born_from", ""),
            "content_type": n.get("content_type", "text/html"),
            "value_score": n.get("value_score", 0), "created_at": n.get("created_at", ""),
            "content": n.get("content") or ""}


@app.get("/api/traps")
async def api_traps():
    """陷阱列表（全局生效）+ 实际命中过的靶站，供列表展示命中分布"""
    from . import traps as traps_mod
    rows = store.list_traps()
    mounts = traps_mod.derive_site_mounts()
    return [{**r, "sites": mounts.get(r["id"], [])} for r in rows]


@app.get("/api/live/logs")
async def api_live_logs(after: int = 0, limit: int = 200):
    """实时日志（大文本框数据源）：各靶站的 HTTP 访问 + 实例凭据记录增量拉取。

    after=0 表示首屏：回补最近 limit 条；之后前端带上次 cursor 轮询增量。
    引擎模式靶站走 packets 表，实例模式靶站走实例日志文件（livelog 尾读）。
    """
    sites_list = store.list_sites()
    sites = {s["id"]: s for s in sites_list}
    sessions = {s["id"]: s for s in store.list_sessions(limit=1000)}
    lines: list[dict] = []
    cursor = int(after or 0)
    if not after:
        cursor = max(0, store.packets_latest_id() - int(limit))
    for p in store.packets_after(cursor, int(limit)):
        info = sites.get(p.get("site_id") or "") or {}
        name = info.get("name") or (f"端口{p['port']}" if p.get("port") else "未知靶站")
        label = f"{name}(:{p['port']})" if p.get("port") else name
        sess = sessions.get(p.get("session_id") or "") or {}
        # IP 优先 WebRTC 溯源结果（srflx 真实出口），其次 HTTP 层来源 IP
        real_ip = str(sess.get("real_ip") or "").strip()
        http_ip = str(sess.get("ip") or "").strip()
        lines.append({"ts": p.get("ts"), "site": label, "method": p.get("method"),
                      "path": p.get("path") or "", "status": p.get("status"),
                      "kind": "cred" if p.get("has_cred") else "http",
                      "ip": real_ip or http_ip, "ip_src": "webrtc" if real_ip else ("http" if http_ip else ""),
                      "internal_ip": str(sess.get("internal_ip") or ""),
                      "tool": str(sess.get("tool") or ""),
                      "sid": str(p.get("session_id") or "")[:8], "text": ""})
        cursor = max(cursor, int(p["id"]))
    lines += livelog.tail_instances(sites_list)
    return {"lines": lines, "cursor": cursor}


@app.get("/api/traps/templates")
async def api_trap_templates():
    """内置静态正文模板清单（strategy=static 时可选 file）"""
    from . import traps as traps_mod
    return [{"key": k, "size": len(v)} for k, v in traps_mod.STATIC_BODIES.items()]


@app.put("/api/traps/{tid}")
async def api_toggle_trap(tid: str, request: Request):
    body = await request.json()
    store.toggle_trap(tid, bool(body.get("enabled")))
    return {"ok": True}


@app.post("/api/traps")
async def api_create_trap(request: Request):
    """新增/覆盖一条陷阱（人工或前端表单）"""
    from . import traps as traps_mod
    body = await request.json()
    trap, err = traps_mod._sanitize(body.get("trap") or body)
    if not trap:
        return {"error": err}
    store.load_trap(trap["id"], trap["name"], trap["match"], trap["respond"], trap["enabled"])
    if trap["id"] not in traps_mod.builtin_ids():
        traps_mod.mark_custom(trap["id"], True)
    else:
        # 出厂陷阱被重新添加：撤销之前的删除标记，否则重启后 load_builtin 会再次清掉
        state = traps_mod._load_state()
        if trap["id"] in set(state.get("removed") or []):
            state["removed"] = [t for t in state.get("removed") or [] if t != trap["id"]]
            traps_mod._save_state(state)
    events.broadcast("trap.created", trap["id"], "-", f"新增陷阱 {trap['id']} · {trap['name']}")
    return {"ok": True, "trap": trap}


@app.delete("/api/traps/{tid}")
async def api_delete_trap(tid: str):
    """删除陷阱（出厂陷阱删除会持久化，重启不会被 load_builtin 复活）"""
    from . import traps as traps_mod
    if not store.get_trap(tid):
        return {"error": "陷阱不存在"}
    state = traps_mod._load_state()
    removed = set(state.get("removed") or [])
    overrides = dict(state.get("overrides") or {})
    if tid in traps_mod.builtin_ids():
        removed.add(tid)
        overrides.pop(tid, None)
        state["removed"] = sorted(removed)
        state["overrides"] = overrides
        traps_mod._save_state(state)
    else:
        traps_mod.mark_custom(tid, False)
    store.delete_trap(tid)  # 立刻从库与内存缓存移除，避免删除后仍被命中
    events.broadcast("trap.deleted", tid, "-", f"陷阱 {tid} 已删除")
    return {"ok": True}


@app.post("/api/traps/auto")
async def api_traps_auto(request: Request):
    """LLM 依据实时攻击态势自动增删改陷阱"""
    from . import traps as traps_mod
    body = await request.json()
    instruction = str(body.get("instruction") or "")
    res = await traps_mod.auto_evolve(instruction)
    return res


@app.post("/api/traps/{tid}/dryrun")
async def api_trap_dryrun(tid: str, request: Request):
    body = await request.json()
    trap = store.get_trap(tid)
    if not trap:
        return {"error": "陷阱不存在"}
    from .traps import _match_one
    hit = _match_one(json.loads(trap["match_json"]),
                     body.get("path", "").lstrip("/"), body.get("method", "GET"),
                     body.get("payload", ""))
    return {"trap": trap["id"], "would_match": hit,
            "strategy": json.loads(trap["respond_json"]).get("strategy")}


# ---- 模型管理：Provider CRUD + 指挥模型指定 + 连通性测试 ----
@app.get("/api/llm/providers")
async def api_providers():
    return llm_gateway.provider_status()


@app.post("/api/llm/providers")
async def api_add_provider(request: Request):
    body = await request.json()
    name = (body.get("name") or "").strip()
    endpoint = (body.get("endpoint") or "").strip()
    model = (body.get("model") or "").strip()
    if not name or not endpoint or not model:
        return {"error": "name / endpoint / model 必填"}
    pid = store.add_provider(name, endpoint, model, body.get("key") or "",
                            temperature=float(body.get("temperature") or 0.7))
    return {"ok": True, "id": pid}


@app.put("/api/llm/providers/{pid}")
async def api_update_provider(pid: str, request: Request):
    if not store.get_provider(pid):
        return {"error": "Provider 不存在"}
    store.update_provider(pid, **{k: v for k, v in (await request.json()).items()
                                  if k in ("name", "endpoint", "model", "key", "enabled",
                                           "temperature")})
    return {"ok": True}


@app.delete("/api/llm/providers/{pid}")
async def api_delete_provider(pid: str):
    store.delete_provider(pid)
    if store.get_setting("commander_provider_id") == pid:
        store.set_setting("commander_provider_id", "")
    return {"ok": True}


@app.put("/api/llm/commander")
async def api_set_commander(request: Request):
    body = await request.json()
    pid = body.get("provider_id") or ""
    if pid and not store.get_provider(pid):
        return {"error": "Provider 不存在"}
    store.set_setting("commander_provider_id", pid)
    name = store.get_provider(pid)["name"] if pid else "（未指定，按添加顺序降级）"
    events.broadcast("commander.changed", "-", "-",
                     f"指挥模型已切换为：{name}" if pid else "已清空指挥模型指定")
    return {"ok": True}


@app.post("/api/llm/providers/{pid}/test")
async def api_test_provider(pid: str):
    return await llm_gateway.test_provider(pid)


@app.post("/api/llm/providers/test-all")
async def api_test_all_providers():
    return await llm_gateway.test_all()


# ---- 直接对话（fuckai 同款）：会话 CRUD + 非流式 + SSE 流式 ----
@app.get("/api/llm/chat/sessions")
async def api_chat_sessions():
    return {"sessions": [llm_chat.session_brief(s) for s in store.list_chat_sessions()]}


@app.post("/api/llm/chat/sessions")
async def api_chat_session_create(request: Request):
    body = await request.json()
    s = store.create_chat_session(
        title=body.get("title") or "新对话",
        provider_id=body.get("provider_id") or "",
        model=body.get("model") or "",
        temperature=float(body.get("temperature") or 0.7),
        system_prompt=body.get("system_prompt") or "",
        history_mode=body.get("history_mode") or "compress",
        context_rounds=int(body.get("context_rounds") or 6),
        history_chars=int(body.get("history_chars") or 300),
        max_tokens=int(body.get("max_tokens") or 0))
    return {"ok": True, "session": llm_chat.session_brief(s)}


@app.get("/api/llm/chat/sessions/{sid}")
async def api_chat_session_get(sid: str):
    s = store.get_chat_session(sid)
    if not s:
        return {"error": "会话不存在"}
    return {"ok": True, "session": llm_chat.session_brief(s), "messages": s.get("messages") or []}


@app.put("/api/llm/chat/sessions/{sid}")
async def api_chat_session_update(sid: str, request: Request):
    if not store.get_chat_session(sid):
        return {"error": "会话不存在"}
    body = await request.json()
    store.update_chat_session(sid, **body)
    return {"ok": True}


@app.delete("/api/llm/chat/sessions/{sid}")
async def api_chat_session_delete(sid: str):
    store.delete_chat_session(sid)
    return {"ok": True}


@app.post("/api/llm/chat")
async def api_llm_chat(request: Request):
    return await llm_chat.chat(await request.json())


@app.post("/api/llm/chat/stream")
async def api_llm_chat_stream(request: Request):
    return llm_chat.stream_chat(await request.json())


@app.post("/api/reports/generate")
async def api_report():
    evs = store.list_events(limit=200)
    ov = store.overview()
    digest = "\n".join(f"- [{e['type']}] {e['ts']} {e['summary']}" for e in evs[:60])
    content, _ = await llm_gateway.chat(
        [{"role": "system", "content": "你是企业安全态势报告撰写员，输出 Markdown 中文报告。"},
         {"role": "user", "content":
             f"统计概览：{ov}\n近期事件：\n{digest}\n"
             "请输出态势报告：趋势判断、重点攻击者行为、陷阱效果、生长摘要、建议。"}],
        task="report", max_tokens=32000, timeout=150)
    if not content:
        content = (f"# 态势报告（离线生成）\n\n概览：{ov}\n\n## 近期事件\n{digest}\n\n"
                   "> 配置指挥模型后可自动撰写分析结论。")
    return {"report": content}


@app.post("/api/profile/{sid}/analyze")
async def api_profile_analyze(sid: str):
    """指挥模型研判攻击者画像：动机/工具/熟练度/下一步诱导建议"""
    sess = store.get_or_create_session(sid, "", "")
    evs = store.list_events(limit=300, session_id=sid)
    mine = [e for e in evs if e["session_id"] == sid]
    digest = "\n".join(f"- [{e['type']}] {e['ts']} {e['summary']}" for e in mine[:60]) or "（暂无行为事件）"
    # 凭据捕获记录：攻击者提交过的账号密码（trap.credential 事件 detail）
    creds = []
    for e in mine:
        if e["type"] == "trap.credential" and e["detail"]:
            try:
                creds.append(json.loads(e["detail"]).get("credentials", {}))
            except Exception:
                pass
    cred_block = json.dumps(creds, ensure_ascii=False) if creds else "（未捕获到凭据提交）"
    out, used = await llm_gateway.chat(
        [{"role": "system", "content":
            "你是攻击者画像研判引擎，基于服务器日志分析攻击者活动。区分人工、通用工具和疑似自主 Agent；"
            "Agent 标签只是行为证据，不得据此断言模型身份。只输出 JSON："
            '{"动机":"...","技术水平":"脚本小子/中级/高级","工具研判":"...","威胁等级":"低/中/高",'
            '"凭据研判":"对提交凭据的分析：是否常用密码/字典特征/真实意图",'
            '"行为时间线":["..."],"下一步诱导建议":["..."],"处置建议":["..."]}'},
         {"role": "user", "content":
            f"会话信息：IP={sess['ip']} UA={sess['ua']} 工具特征={sess['tool']} "
            f"投入评分={sess['score']} 阶段={sess['state']}\n"
            f"客户端工具族={agentdetect.session_families(sid, sess.get('ua') or '')} "
            f"身份推断={agentdetect.identity_guess(sess.get('agent_signals'))}\n"
            f"Agent 行为画像：标签={sess.get('agent_label', '未判定')} "
            f"分数={sess.get('agent_score', 0)} 证据={json.dumps(sess.get('agent_signals', []), ensure_ascii=False)}\n"
            f"服务器活动日志：\n{digest}\n"
            f"攻击者提交过的账号密码记录：{cred_block}\n"
            "请研判该攻击者画像，重点分析其提交的凭据特征与真实意图。"}],
        task="report", json_mode=True, max_tokens=32000, timeout=150)
    if not out:
        return {"error": "指挥模型不可用，无法研判"}
    import re
    import json as _j
    try:
        profile = _j.loads(re.sub(r"^```(json)?|```$", "", out.strip(), flags=re.M).strip())
    except Exception:
        profile = {"raw": out}
    store.add_event("profile.analyzed", "-", sid, f"AI 画像研判完成（via {used}）", profile)
    return {"profile": profile}


@app.post("/api/morph/{clone_id}")
async def api_morph(clone_id: str, request: Request):
    body = await request.json()
    return await cloner.morph(clone_id, body.get("instruction") or "")


@app.post("/api/morph/{clone_id}/chat")
async def api_morph_chat(clone_id: str, request: Request):
    """指挥靶站变形（对话式）：回复经 SSE morph.llm 流式下发"""
    body = await request.json()
    return await cloner.morph_chat(clone_id, body.get("instruction") or "",
                                   body.get("history") or [])


# ---------------- 控制台静态页 ----------------
app.mount("/static", StaticFiles(directory=str(config.CONSOLE_DIR)), name="static")


@app.get("/console")
@app.get("/")
async def console():
    return FileResponse(str(config.CONSOLE_DIR / "index.html"),
                        headers={"Cache-Control": "no-cache"})
