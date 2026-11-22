"""两个入口共用的路由：Canary Token 回连 + WebRTC 真实 IP 采集
（管理端基础设施，与靶站域名隔离）"""
import hashlib
import json
import re

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from . import events, store

GIF = bytes.fromhex(
    "47494638396101000100800000000000ffffff21f90401000000002c00000000"
    "0100010002020401003b")

router = APIRouter()

# ICE candidate 格式：candidate:<foundation> <comp> <transport> <prio> <addr> <port> typ <type>
_CAND_RE = re.compile(
    r"candidate:\S+\s+\d+\s+(?:udp|tcp)\s+\d+\s+"
    r"(\d{1,3}(?:\.\d{1,3}){3})\s+\d+\s+typ\s+(srflx|host|relay)")


def _session_from_request(request: Request) -> str:
    """与 engine.ensure_session 同口径：ip|ua 哈希 → 会话 ID"""
    ip = request.client.host if request.client else "unknown"
    ua = request.headers.get("user-agent", "")
    sid = hashlib.sha1(f"{ip}|{ua}".encode()).hexdigest()[:12]
    store.get_or_create_session(sid, ip, ua)
    return sid


@router.get("/t/{token_id}")
@router.post("/t/{token_id}")
async def canary_hit(token_id: str, request: Request):
    meta = {"ip": request.client.host if request.client else "?",
            "ua": request.headers.get("user-agent", "")[:200],
            "referer": request.headers.get("referer", "")[:200]}
    store.record_callback(token_id, meta)
    if meta["ip"]:
        events.broadcast("attribution.callback", "-", "-",
                         f"Canary Token 回连：{token_id} 出口={meta['ip']}", meta)
    return Response(GIF, media_type="image/gif")


@router.post("/api/webrtc-leak")
async def webrtc_leak(request: Request):
    """接收靶站前端静默上报的 ICE candidate。
    srflx = STUN 服务器看到的真实公网出口（UDP 不走 HTTP 代理，可穿透代理溯源）；
    host  = 攻击者本机内网地址（推断内网拓扑）。"""
    try:
        data = json.loads((await request.body()).decode("utf-8", "ignore") or "{}")
    except Exception:
        data = {}
    cand = str(data.get("candidate", ""))[:500]
    m = _CAND_RE.search(cand)
    if not m:
        return JSONResponse({"status": "ignored"})
    ip, typ = m.group(1), m.group(2)
    sid = _session_from_request(request)
    if typ == "host":
        store.set_webrtc_ip(sid, internal_ip=ip)
        events.broadcast("attribution.webrtc", "-", sid,
                         f"WebRTC 内网指纹：{ip}（host 候选）")
        return JSONResponse({"status": "ok", "type": "host"})
    # srflx / relay：公网出口
    store.set_webrtc_ip(sid, real_ip=ip)
    if request.client and ip != request.client.host:
        # HTTP 层出口 ≠ WebRTC 出口 → 攻击者挂了代理，real_ip 即真实 IP
        events.broadcast("attribution.webrtc", "-", sid,
                         f"WebRTC 真实 IP 溯源：{ip}（代理出口 {request.client.host}，已穿透）")
    else:
        events.broadcast("attribution.webrtc", "-", sid,
                         f"WebRTC 出口 IP：{ip}（srflx 候选）")
    return JSONResponse({"status": "ok", "type": typ})
