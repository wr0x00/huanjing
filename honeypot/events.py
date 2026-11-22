"""SSE 事件广播：所有实时事件（生长/陷阱/会话）经此推送到控制台

broadcast：落库 + 推队列（阶段级事件，量少）
publish  ：仅推队列不落库（高频实时流，如 LLM 逐段回复），带长度/时间微聚合防刷屏
"""
import asyncio
import json
import time as _time

_SUBSCRIBERS: set[asyncio.Queue] = set()
_PUB_BUF: dict[str, list[str]] = {}
_PUB_TS: dict[str, float] = {}


def subscribe() -> asyncio.Queue:
    q: asyncio.Queue = asyncio.Queue(maxsize=500)
    _SUBSCRIBERS.add(q)
    return q


def unsubscribe(q: asyncio.Queue):
    _SUBSCRIBERS.discard(q)


def _push(etype: str, clone_id: str, summary: str, detail=None):
    payload = json.dumps({
        "ts": _time.strftime("%H:%M:%S"), "type": etype, "clone_id": clone_id,
        "session_id": "", "summary": summary,
        "detail": detail or {},
    }, ensure_ascii=False)
    for q in list(_SUBSCRIBERS):
        try:
            q.put_nowait(payload)
        except asyncio.QueueFull:
            pass


def broadcast(etype: str, clone_id: str, session_id: str, summary: str, detail=None):
    from . import store
    store.add_event(etype, clone_id, session_id, summary, detail)
    payload = json.dumps({
        "ts": _time.strftime("%H:%M:%S"), "type": etype, "clone_id": clone_id,
        "session_id": session_id, "summary": summary,
        "detail": detail or {},
    }, ensure_ascii=False)
    for q in list(_SUBSCRIBERS):
        try:
            q.put_nowait(payload)
        except asyncio.QueueFull:
            pass


def publish(etype: str, clone_id: str, text: str,
            flush_len: int = 90, flush_secs: float = 0.8):
    """高频实时片段：仅入 SSE 队列不落库；攒满 flush_len 字符或距上次推送超 flush_secs 才推一条"""
    key = f"{etype}:{clone_id}"
    buf = _PUB_BUF.setdefault(key, [])
    buf.append(text)
    joined = "".join(buf)
    now = _time.time()
    if len(joined) >= flush_len or now - _PUB_TS.get(key, 0.0) >= flush_secs:
        _PUB_TS[key] = now
        buf.clear()
        if joined.strip():
            _push(etype, clone_id, joined)


def publish_flush(etype: str, clone_id: str):
    """任务/阶段结束时把残余缓冲一次性推出"""
    buf = _PUB_BUF.pop(f"{etype}:{clone_id}", None)
    if buf:
        joined = "".join(buf)
        if joined.strip():
            _push(etype, clone_id, joined)
