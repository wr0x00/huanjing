"""直接对话模块（fuckai 同款）：会话持久化 + 上下文优化 + 多模态 + SSE 真流式。

与 fuckai 的差异：
  * 会话落 ai-honeypot 的 SQLite（config 库），不写 JSON 文件
  * 模型配置直接复用「模型网关」的 Provider（不再单独维护 config.yaml 模型列表）
  * 流式基于 llm_gateway.ChatClient.chat_stream（httpx 异步逐行读 SSE）
"""
import base64
import json
import time

from fastapi.responses import StreamingResponse

from . import llm_gateway, store

# SSE 响应头：Connection: close 让响应结束即关连接，
# 避免 keep-alive 空闲连接被服务端超时关闭时 Chrome 把该请求标成 net::ERR_ABORTED
_SSE_HEADERS = {"Cache-Control": "no-cache", "X-Accel-Buffering": "no",
                 "Connection": "close"}


# --------------------------------------------------------------------------- #
# 上下文拼装（fuckai 同款语义）
# --------------------------------------------------------------------------- #
def _clip(text: str, limit: int) -> str:
    text = (text or "").strip()
    if limit > 0 and len(text) > limit:
        return text[:limit] + "…"
    return text


def compose_messages(messages: list[dict], system_prompt: str = "",
                     history_mode: str = "compress", context_rounds: int = 6,
                     history_chars: int = 300) -> list[dict]:
    """按上下文优化策略拼装最终发送给模型的 messages。"""
    hist = [
        {"role": m.get("role"), "content": m.get("content") or ""}
        for m in (messages or [])
        if m.get("role") in ("user", "assistant") and (m.get("content") or "").strip()
    ]
    mode = history_mode or "compress"
    rounds = max(0, int(context_rounds))
    older: list[dict] = []
    if mode == "drop":
        hist = hist[-1:]
    elif mode == "compress":
        keep = max(2, rounds * 2)
        if len(hist) > keep:
            older, hist = hist[:-keep], hist[-keep:]

    sys_chunks: list[str] = []
    if (system_prompt or "").strip():
        sys_chunks.append(system_prompt.strip())
    if older:
        lines = [
            f"{'用户' if m['role'] == 'user' else '助手'}：{_clip(m['content'], history_chars)}"
            for m in older
        ]
        sys_chunks.append("【历史对话摘要（早期轮次已压缩）】\n" + "\n".join(lines))

    out: list[dict] = []
    if sys_chunks:
        out.append({"role": "system", "content": "\n\n".join(sys_chunks)})
    out.extend(hist)
    return out


def build_content_parts(text: str, attachments: list[dict]) -> list[dict]:
    """把用户输入 + 附件组装成 OpenAI 多模态 content parts。"""
    parts: list[dict] = []
    if text:
        parts.append({"type": "text", "text": text})
    for a in attachments or []:
        name = a.get("name") or "file"
        mime = (a.get("mime") or "").lower()
        data = a.get("data") or ""
        datauri = a.get("url") or (f"data:{mime};base64,{data}" if data else "")
        if not data:
            continue
        if mime.startswith("image/"):
            parts.append({"type": "image_url", "image_url": {"url": datauri}})
        elif mime.startswith("video/"):
            parts.append({"type": "video_url", "video_url": {"url": datauri}})
        elif mime == "application/pdf":
            parts.append({"type": "file", "file": {"filename": name, "file_data": datauri}})
        elif mime.startswith("audio/"):
            fmt = name.rsplit(".", 1)[-1].lower() or "wav"
            parts.append({"type": "input_audio", "input_audio": {"data": data, "format": fmt}})
        else:
            txt = ""
            try:
                raw = base64.b64decode(data)
                try:
                    txt = raw.decode("utf-8")
                except UnicodeDecodeError:
                    txt = ""
            except Exception:
                txt = ""
            if txt and len(txt) < 100000:
                parts.append({"type": "text", "text": f"【附件文件 {name}】\n{txt}"})
            else:
                parts.append({"type": "text",
                              "text": f"【附件文件 {name}（{mime or '未知类型'}）无法内联解析，请描述其内容】"})
    return parts or [{"type": "text", "text": ""}]


def sent_preview(composed: list[dict]) -> list[dict]:
    """前端「本次实际发送」展示：把多模态二进制替换为占位符。"""
    out = []
    for m in composed:
        content = m.get("content")
        if isinstance(content, list):
            slim = []
            for p in content:
                p = dict(p)
                if p.get("type") == "text":
                    continue
                slim.append({"type": p.get("type"), "data": "[base64 数据已省略]"})
            texts = [p.get("text", "") for p in content if p.get("type") == "text"]
            out.append({"role": m.get("role"), "content": "\n".join(texts), "parts": slim})
        else:
            out.append(m)
    return out


# --------------------------------------------------------------------------- #
# Provider 解析
# --------------------------------------------------------------------------- #
def resolve_provider(provider_id: str = "", base_url: str = "", model: str = "",
                     temperature: float | None = None) -> dict:
    """优先用 provider_id 从模型网关取配置；否则用传入的 base_url/model（自建连接）。"""
    if provider_id:
        p = store.get_provider(provider_id)
        if p:
            return {
                "id": p["id"], "name": p["name"], "base_url": p["endpoint"],
                "api_key": p["key"] or "", "model": p["model"],
                "temperature": float(p.get("temperature") or 0.7),
                "temperature_override": temperature,
            }
    return {
        "id": "", "name": "自定义连接", "base_url": base_url or "",
        "api_key": "", "model": model or "",
        "temperature": 0.7 if temperature is None else float(temperature),
        "temperature_override": temperature,
    }


def _client(info: dict, max_tokens: int | None, timeout: int = 180):
    temp = info.get("temperature_override")
    if temp is None:
        temp = info.get("temperature", 0.7)
    return llm_gateway.ChatClient(
        info["base_url"], info["api_key"], info["model"],
        temperature=float(temp), timeout=timeout, max_tokens=max_tokens)


def _max_tokens_of(raw) -> int | None:
    """0 / 空 = 不限制（fuckai 语义：省略 max_tokens 字段）。"""
    try:
        v = int(raw or 0)
    except (TypeError, ValueError):
        return None
    return v if v > 0 else None


# --------------------------------------------------------------------------- #
# 会话
# --------------------------------------------------------------------------- #
def session_brief(s: dict) -> dict:
    return {
        "id": s.get("id", ""),
        "title": s.get("title", ""),
        "provider_id": s.get("provider_id", ""),
        "model": s.get("model", ""),
        "temperature": s.get("temperature", 0.7),
        "system_prompt": s.get("system_prompt", ""),
        "history_mode": s.get("history_mode", "compress"),
        "context_rounds": s.get("context_rounds", 6),
        "history_chars": s.get("history_chars", 300),
        "max_tokens": s.get("max_tokens", 0),
        "created_at": s.get("created_at", ""),
        "updated_at": s.get("updated_at", ""),
        "msg_count": s.get("msg_count", len(s.get("messages") or [])),
    }


def _pick(body: dict, session: dict, key: str, default=None):
    """请求体优先，其次会话默认值。"""
    v = body.get(key)
    if v is None:
        return session.get(key, default)
    return v


def prepare(body: dict) -> tuple[dict | None, dict | None, list[dict], str, str, list[dict]]:
    """统一解析 Provider / 会话 / 最终 messages。

    返回 (info, session, composed, text, session_id, attachments)；
    info 为 None 表示配置缺失，composed 为空表示参数非法。
    """
    session_id = body.get("session_id") or ""
    session = store.get_chat_session(session_id) if session_id else None
    # 无会话时，允许「直接给 messages + provider」的脚本式调用（含编辑重发 raw_messages）
    standalone = session is None and bool(body.get("messages"))
    if session is None and not standalone:
        return None, None, [], "", session_id, []

    provider_id = body.get("provider_id") or (session or {}).get("provider_id") or ""
    info = resolve_provider(
        provider_id,
        body.get("base_url") or "",
        body.get("model") or (session or {}).get("model") or "",
        body.get("temperature") if body.get("temperature") is not None
        else (session or {}).get("temperature"))
    if not info["base_url"] or not info["model"]:
        return None, session, [], "", session_id, []

    text = (body.get("content") or "").strip()
    raw_messages = bool(body.get("raw_messages"))
    attachments = body.get("attachments") or []

    if raw_messages:
        # 编辑重发：前端给的 messages 即最终发送内容，不落盘、不混入原会话
        composed = [{"role": m.get("role") or "user", "content": m.get("content") or ""}
                    for m in (body.get("messages") or []) if (m.get("content") or "").strip()]
    elif body.get("messages"):
        composed = [{"role": m.get("role") or "user", "content": m.get("content") or ""}
                    for m in body["messages"] if (m.get("content") or "").strip()]
    else:
        hist = [{"role": m["role"], "content": m.get("content") or ""}
                for m in ((session or {}).get("messages") or [])
                if m.get("role") in ("user", "assistant") and (m.get("content") or "").strip()]
        if text:
            hist.append({"role": "user", "content": text})
        composed = compose_messages(
            hist,
            system_prompt=_pick(body, session or {}, "system_prompt", ""),
            history_mode=_pick(body, session or {}, "history_mode", "compress"),
            context_rounds=_pick(body, session or {}, "context_rounds", 6),
            history_chars=_pick(body, session or {}, "history_chars", 300))
        if attachments:
            for m in reversed(composed):
                if m.get("role") == "user":
                    m["content"] = build_content_parts(text, attachments)
                    break
    return info, session, composed, text, session_id, attachments


# --------------------------------------------------------------------------- #
# 流式对话
# --------------------------------------------------------------------------- #
def stream_chat(body: dict):
    """SSE 直连对话：逐段下发 delta / reasoning / done / error。"""
    info, session, composed, text, session_id, attachments = prepare(body)
    if info is None:
        err = "会话不存在，请先新建会话" if session is None and not body.get("messages") \
            else "模型缺少 Endpoint 或模型名"
        return StreamingResponse(
            iter([_sse({"type": "error", "error": err})]),
            media_type="text/event-stream",
            headers=_SSE_HEADERS)
    if not composed:
        return StreamingResponse(
            iter([_sse({"type": "error", "error": "消息内容为空"})]),
            media_type="text/event-stream",
            headers=_SSE_HEADERS)

    raw_messages = bool(body.get("raw_messages"))

    # 用户消息立即落盘（即使后续失败也保留历史）
    if not raw_messages and text and session_id:
        store.add_chat_message(session_id, "user", text, attachments=[
            {"name": a.get("name", ""), "mime": a.get("mime", ""),
             "size": a.get("size", 0)} for a in attachments])
        if session and (session.get("title") or "新对话") == "新对话":
            store.update_chat_session(session_id, title=_clip(text, 20))

    max_tokens = _max_tokens_of(_pick(body, session or {}, "max_tokens", 0))
    client = _client(info, max_tokens)

    async def gen():
        t0 = time.perf_counter()
        acc: list[str] = []
        think_acc: list[str] = []
        yield _sse({"type": "meta", "model": client.model, "provider": info["name"]})
        try:
            async for kind, delta in client.chat_stream(composed):
                if kind == "reasoning":
                    think_acc.append(delta)
                    yield _sse({"type": "reasoning", "text": delta})
                elif kind == "content":
                    acc.append(delta)
                    yield _sse({"type": "delta", "text": delta})
            reply = "".join(acc)
            if not raw_messages and session_id:
                store.add_chat_message(session_id, "assistant", reply,
                                       thinking="".join(think_acc))
            yield _sse({"type": "done", "reply": reply,
                        "elapsed_ms": int((time.perf_counter() - t0) * 1000),
                        "sent": sent_preview(composed)})
        except Exception as e:  # noqa: BLE001
            yield _sse({"type": "error", "error": str(e)})

    return StreamingResponse(
        gen(), media_type="text/event-stream",
        headers=_SSE_HEADERS)


def _sse(obj: dict) -> str:
    return f"data: {json.dumps(obj, ensure_ascii=False)}\n\n"


# --------------------------------------------------------------------------- #
# 非流式对话
# --------------------------------------------------------------------------- #
async def chat(body: dict) -> dict:
    """一次性返回整段回复（供脚本/无浏览器场景调用）。"""
    info, session, composed, text, session_id, attachments = prepare(body)
    if info is None:
        return {"ok": False, "error": "会话不存在，请先新建会话" if session is None
                and not body.get("messages") else "模型缺少 Endpoint 或模型名"}
    if not composed:
        return {"ok": False, "error": "消息内容为空"}

    raw_messages = bool(body.get("raw_messages"))
    if not raw_messages and text and session_id:
        store.add_chat_message(session_id, "user", text, attachments=[
            {"name": a.get("name", ""), "mime": a.get("mime", ""),
             "size": a.get("size", 0)} for a in attachments])

    max_tokens = _max_tokens_of(_pick(body, session or {}, "max_tokens", 0))
    client = _client(info, max_tokens)
    t0 = time.perf_counter()
    try:
        reply = await client.chat(composed)
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e), "sent": sent_preview(composed)}
    if not raw_messages and session_id:
        store.add_chat_message(session_id, "assistant", reply)
    return {"ok": True, "reply": reply,
            "elapsed_ms": int((time.perf_counter() - t0) * 1000),
            "sent": sent_preview(composed)}
