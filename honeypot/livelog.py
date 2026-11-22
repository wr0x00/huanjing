"""实时日志：把各靶站实例的访问/凭据日志增量尾读成统一的行，供控制台大文本框上屏。

实例模式（模板自带 backend/app.py）的靶站是独立进程，请求不进主库 packets，
因此这里按文件偏移增量读取：
  - backend/instance.stdout.log  uvicorn 访问日志（"GET /path HTTP/1.1" 200）
  - backend/honeypot.log         凭据提交记录（JSON 行）
偏移量存进程内存，服务重启后从头读一次（首屏补齐最近记录）。
"""
import json
import re
from pathlib import Path

from . import config

_ACCESS_RE = re.compile(
    r'(?:(?P<ip>[\d.]+):\d+\s+-\s+)?["“](?P<m>[A-Z]+)\s+(?P<p>\S+)\s+HTTP/[\d.]+["”]\s+(?P<s>\d{3})')
_offsets: dict[str, int] = {}
_MAX_READ = 256 * 1024          # 单文件单轮最多读 256KB，避免瞬时撑爆
_FIRST_SCAN_TAIL = 64 * 1024    # 首次读文件只取尾部，避免历史日志全量刷屏

_instances_dir = config.DATA_DIR / "instances"


def _site_label(site_id: str, sites: dict) -> str:
    s = sites.get(site_id) or {}
    name = s.get("name") or site_id
    port = s.get("port")
    return f"{name}(:{port})" if port else name


def _read_new(fp: Path, first_tail: int = 0) -> list[str]:
    """按偏移读取新增内容；返回新增的完整行（不足一行的尾巴留到下次）"""
    try:
        size = fp.stat().st_size
    except OSError:
        return []
    key = str(fp)
    off = _offsets.get(key)
    if off is None:
        off = max(0, size - first_tail) if first_tail else 0
    if size <= off:
        _offsets[key] = size
        return []
    if size - off > _MAX_READ:
        off = size - _MAX_READ
    try:
        with fp.open("rb") as f:
            f.seek(off)
            data = f.read()
    except OSError:
        return []
    cut = data.rfind(b"\n")
    if cut < 0:
        return []          # 还没有完整行
    _offsets[key] = off + cut + 1
    return data[:cut + 1].decode("utf-8", "replace").splitlines()


def tail_instances(sites: list[dict]) -> list[dict]:
    """收集所有实例靶站的新增日志行，按时间排序返回"""
    order = {s["id"]: s for s in sites}
    out: list[dict] = []
    if not _instances_dir.exists():
        return out
    for d in sorted(_instances_dir.iterdir()):
        if not d.is_dir():
            continue
        sid = d.name
        label = _site_label(sid, order)
        be = d / "backend"
        # uvicorn 访问日志：攻击者踩了哪个页面
        for line in _read_new(be / "instance.stdout.log", _FIRST_SCAN_TAIL):
            m = _ACCESS_RE.search(line)
            if not m:
                continue
            out.append({"k": "http", "ts": "", "site": label,
                        "ip": m.group("ip") or "", "method": m.group("m"),
                        "path": m.group("p"), "status": m.group("s"), "text": ""})
        # 凭据提交记录
        for line in _read_new(be / "honeypot.log", _FIRST_SCAN_TAIL):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            cred = rec.get("credentials") or {}
            brief = " ".join(f"{k}={v}" for k, v in list(cred.items())[:4])
            out.append({"k": "cred", "ts": str(rec.get("ts") or "").replace(" ", "T"),
                        "site": label, "ip": rec.get("ip") or "", "method": "POST", "path": "",
                        "status": "", "text": f"凭据提交 {brief}" if brief else "凭据提交"})
    return out