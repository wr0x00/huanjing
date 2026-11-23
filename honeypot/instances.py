"""靶站实例管理器：仿冒模板（完整前后端）→ 挂载时复制独立实例 → 独立进程运行

数据隔离模型：
  仿冒模板  data/sites/<模板ID>/          （frontend/ + backend/ + site.json，只读母本）
  靶站实例  data/instances/<靶站ID>/      （挂载时从模板整体复制，独立进程、独立 honeypot.log，
                                          各靶站数据互不混淆）
  删除靶站  停进程保留实例目录（取证）；重新挂载同模板则全新复制

LLM 对全部靶站实例文件拥有增删改查权利（路径限制在实例目录内，文本写入过 DLP 扫描），
并根据实时攻击者态势（事件流 + 会话画像 + 实例 honeypot.log）对站点功能/路径做进化。
"""
import asyncio
import atexit
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

from . import config, events, growth, llm_gateway, store

BASE = config.DATA_DIR / "instances"
_PY = sys.executable
_procs: dict[str, subprocess.Popen] = {}
_scanned: set[str] = set()   # 已做过孤儿扫描的 site_id（进程生命周期内只扫一次，避免拖慢 sync）
_failcnt: dict[str, int] = {}   # 连续启动失败计数（进程秒死 = 代码坏了，避免 sync 每 2s 无限重启）
_failstamp: dict[str, tuple] = {}  # 失败时的代码指纹（app.py + 启动器 mtime）：被改 → 熔断自动清零
_lasterr: dict[str, str] = {}   # 最近一次启动失败原因（控制台可见，避免"已重启"的假象）

# --------------------------------------------------------------------------- #
# 实例启动器：由框架接管 uvicorn（强制 127.0.0.1 + 端口读 HP_SITE_PORT）
#   LLM 只负责业务代码，host/端口不再由 app.py 决定 —— 杜绝"绑到 10.0.0.1 起不来"
# --------------------------------------------------------------------------- #
_LAUNCHER_SRC = '''import importlib.util
import os
import sys
from pathlib import Path

target = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path.cwd()
app_py = target / "app.py"
if not app_py.exists() and (target / "backend" / "app.py").exists():
    target = target / "backend"
    app_py = target / "app.py"
os.chdir(target)
sys.path.insert(0, str(target))
if not app_py.exists():
    raise SystemExit("instance backend/app.py not found: %s" % app_py)
spec = importlib.util.spec_from_file_location("hp_site_app", app_py)
mod = importlib.util.module_from_spec(spec)
sys.modules["hp_site_app"] = mod
spec.loader.exec_module(mod)
app = getattr(mod, "app", None)
if app is None:
    raise SystemExit("app.py does not define an `app` object")
import uvicorn
host = os.environ.get("HP_SITE_HOST") or "127.0.0.1"
port = int(os.environ.get("HP_SITE_PORT") or "8899")
uvicorn.run(app, host=host, port=port, log_level="info")
'''


def _launcher_path() -> Path:
    """框架自有的启动器（放在实例目录之外，LLM 改不到）"""
    d = config.DATA_DIR / "runtime"
    d.mkdir(parents=True, exist_ok=True)
    p = d / "site_launcher.py"
    try:
        old = p.read_text(encoding="utf-8", errors="replace")
    except Exception:
        old = ""
    if old != _LAUNCHER_SRC:
        p.write_text(_LAUNCHER_SRC, encoding="utf-8")
    return p


def _port_listening(port: int, host: str = "127.0.0.1") -> bool:
    """端口是否真的在监听（进程活着 ≠ 端口可用）"""
    if not port:
        return False
    try:
        with socket.create_connection((host, int(port)), timeout=0.6):
            return True
    except Exception:
        return False


def _port_bindable(port: int, host: str = "127.0.0.1") -> bool:
    """端口能否被绑定（残留 TIME_WAIT / 旧监听未释放时为 False）"""
    if not port:
        return False
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, int(port)))
        return True
    except OSError:
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass


def _log_tail(site_id: str, n: int = 300) -> str:
    try:
        txt = (instance_dir(site_id) / "backend" / "instance.stdout.log").read_text(
            errors="replace")
        return txt.strip()[-n:]
    except Exception:
        return ""


def _kill_orphans(site_id: str):
    """上一代服务重启后 _procs 清空，遗留的实例子进程成为孤儿仍握着日志句柄，
    rmtree 会报 WinError 32；按实例目录路径匹配命令行强制清杀"""
    pat = str(instance_dir(site_id))
    ps = (f"Get-CimInstance Win32_Process | Where-Object {{$_.CommandLine -like '*{pat}*'}} | "
          f"ForEach-Object {{ Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }}")
    try:
        subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                       capture_output=True, timeout=15)
    except Exception:
        pass


def _proc_cmdlines(pids: set[str]) -> dict[str, str]:
    """查询一批 PID 的命令行（用于判断端口占用者是否属于本项目）"""
    ids = ",".join(sorted(str(int(p)) for p in pids if str(p).isdigit()))
    if not ids:
        return {}
    ps = (f"$ids = @({ids}); "
          "Get-CimInstance Win32_Process | Where-Object { $ids -contains $_.ProcessId } | "
          "ForEach-Object { \"$($_.ProcessId)|$($_.CommandLine)\" }")
    try:
        out = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                             capture_output=True, text=True, timeout=15).stdout
    except Exception:
        return {}
    res: dict[str, str] = {}
    for line in (out or "").splitlines():
        line = line.strip()
        if "|" in line:
            pid, _, cmd = line.partition("|")
            res[pid.strip()] = cmd
    return res


def _kill_port(port: int, site_id: str = "") -> list[str]:
    """按端口清理监听进程，但**只终止可确认属于本项目该实例的进程**。

    归属判定：命令行包含本实例工作区路径（data/instances/<site_id>）——
    框架启动器 argv 一定带实例路径，因此本项目的孤儿可被准确识别。
    无法确认归属的占用者一律不强杀（避免误杀无关程序），只广播冲突提示。
    返回未能清理的外部占用 PID 列表。
    """
    if not port:
        return []
    try:
        out = subprocess.run(["netstat", "-ano"], capture_output=True, text=True,
                             timeout=12).stdout
    except Exception:
        return []
    pids = set()
    for line in (out or "").splitlines():
        if f":{port} " in line and "LISTENING" in line.upper():
            parts = line.split()
            if parts and parts[-1].isdigit() and parts[-1] != "0":
                pids.add(parts[-1])
    if not pids:
        return []
    cmds = _proc_cmdlines(pids)
    pat = str(instance_dir(site_id)).lower() if site_id else ""
    mine, foreign = [], []
    for pid in pids:
        cmd = (cmds.get(pid) or "").lower()
        if pat and pat in cmd:
            mine.append(pid)
        else:
            foreign.append(pid)
    for pid in mine:
        subprocess.run(["taskkill", "/F", "/T", "/PID", pid],
                       capture_output=True, timeout=10)
    if mine:
        events.broadcast("instance.orphan_killed", site_id, "-",
                         f"强杀占用端口 {port} 的本项目孤儿监听进程 pid={','.join(mine)}")
    if foreign:
        events.broadcast("instance.port_conflict", site_id, "-",
                         f"端口 {port} 被其他程序占用（pid={','.join(foreign)}），"
                         f"非本项目进程，已跳过强制终止，请手动释放后重试")
    return foreign


def template_dir(template_id: str) -> Path:
    return config.DATA_DIR / "sites" / template_id


def instance_dir(site_id: str) -> Path:
    return BASE / site_id


def has_backend(template_id: str) -> bool:
    """该模板是否带可运行后端（决定靶站走实例模式还是拟真引擎模式）"""
    return (template_dir(template_id) / "backend" / "app.py").exists()


def _copy_missing(src: Path, dst: Path):
    """递归补齐 dst 中缺失的文件/目录（已存在的一律不动，保护 LLM 自生长成果）"""
    for item in src.iterdir():
        target = dst / item.name
        if item.is_dir():
            if not target.exists():
                shutil.copytree(item, target)
            else:
                _copy_missing(item, target)
        elif not target.exists():
            shutil.copy2(item, target)


def deploy(site_id: str, port: int, template_id: str, full_reset: bool = False) -> dict:
    """部署实例。实例是 LLM 自生长的活工作区：
    - full_reset=False（日常）：非破坏式——只补缺失的 backend/frontend，绝不覆盖 LLM 已改文件
    - full_reset=True（更换模板/端口）：全量重置为模板内容"""
    src = template_dir(template_id)
    if not (src / "backend" / "app.py").exists():
        return {"ok": False, "error": f"模板 {template_id} 缺少 backend/app.py"}
    dst = instance_dir(site_id)
    stop(site_id, kill_orphan=True)
    # 端口清理：只终止可确认属于本项目该实例的进程（外部占用者不强杀）
    _kill_port(port, site_id)
    if full_reset and dst.exists():
        # Windows 下句柄释放有延迟，rmtree 重试几次
        for _ in range(4):
            try:
                shutil.rmtree(dst)
                break
            except PermissionError:
                time.sleep(0.5)
        else:
            return {"ok": False, "error": f"实例目录被占用，无法刷新: {dst}"}
    # 非破坏式补齐：模板有而实例缺的文件才复制（递归），已有文件（含 LLM 修改）一律保留
    if not dst.exists():
        shutil.copytree(src, dst)
    else:
        _copy_missing(src, dst)
    events.broadcast("instance.deployed", site_id, "-", f"靶站实例已从模板 {template_id} 复制 → {dst}")
    return {"ok": True, "dir": str(dst)}


def _fail_start(site_id: str, msg: str):
    """记录启动失败：计数 + 错误原因 + 代码指纹（app.py 或启动器被改 → 熔断自动解除）"""
    _failcnt[site_id] = _failcnt.get(site_id, 0) + 1
    try:
        stamp = ((instance_dir(site_id) / "backend" / "app.py").stat().st_mtime,
                 _launcher_path().stat().st_mtime)
    except OSError:
        stamp = (0.0, 0.0)
    _failstamp[site_id] = stamp
    _lasterr[site_id] = (msg or "未知错误").strip()[:400]
    _procs.pop(site_id, None)
    events.broadcast("instance.crash", site_id, "-",
                     f"实例启动失败（{_failcnt[site_id]}/3）：{_lasterr[site_id][:200]}")


def _code_stamp(site_id: str) -> tuple:
    """当前代码指纹（app.py + 启动器 mtime）：与失败时指纹不同 → 允许重试"""
    try:
        return ((instance_dir(site_id) / "backend" / "app.py").stat().st_mtime,
                _launcher_path().stat().st_mtime)
    except OSError:
        return (0.0, 0.0)


def start(site_id: str, port: int) -> int | None:
    """在实例目录启动独立后端进程。
    uvicorn 由框架启动器接管：强制 127.0.0.1 + 端口读 HP_SITE_PORT（LLM 写错 host 也不会起不来）。
    连续 3 次秒死（语法错误等）后熔断；app.py 被 LLM 改动（mtime 变化）后自动清零重试"""
    be = instance_dir(site_id) / "backend"
    app_py = be / "app.py"
    if not app_py.exists():
        return None
    if _failcnt.get(site_id, 0) >= 3:
        if _code_stamp(site_id) != _failstamp.get(site_id):
            _failcnt.pop(site_id, None)      # 代码/启动器被改过 → 熔断解除，允许再试
            _failstamp.pop(site_id, None)
            _lasterr.pop(site_id, None)
        else:
            _lasterr[site_id] = "连续 3 次启动失败已熔断；修复 backend/app.py 后自动重试"
            return None
    stop(site_id, kill_orphan=True)
    # 上一代孤儿可能仍占着端口：只清理可确认属于本项目该实例的进程，
    # 外部程序占用只报告不强杀（避免误杀无关服务）
    foreign: list[str] = []
    if _port_listening(port) or not _port_bindable(port):
        foreign = _kill_port(port, site_id)
    # 等端口真正可绑定（Windows 上旧监听被杀后仍会短暂占用 → 直接起会 EADDRINUSE）
    for _ in range(40):
        if _port_bindable(port):
            break
        time.sleep(0.2)
    if not _port_bindable(port):
        if foreign:
            _lasterr[site_id] = (f"端口 {port} 被其他程序占用"
                                 f"（pid={','.join(foreign)}），非本项目进程未强制终止，请手动释放")
        else:
            _lasterr[site_id] = f"端口 {port} 被其他进程占用，无法启动"
        events.broadcast("instance.crash", site_id, "-",
                         f"实例启动失败：{_lasterr[site_id]}")
        return None
    logf = (be / "instance.stdout.log").open("ab")
    env = {**os.environ, "HP_SITE_PORT": str(port), "HP_SITE_HOST": "127.0.0.1"}
    # argv 传实例路径（启动器命令行含路径 → 孤儿可按路径清理）
    p = subprocess.Popen([_PY, "-u", str(_launcher_path()), str(be)],
                         cwd=str(be), env=env, stdout=logf, stderr=subprocess.STDOUT)
    _procs[site_id] = p
    # 体检：进程存活 + 端口真正监听才算起来
    def _check():
        time.sleep(2.0)
        if p.poll() is not None:
            _fail_start(site_id, f"进程秒死：{_log_tail(site_id)}")
            return
        for _ in range(20):
            if _port_listening(port):
                _failcnt.pop(site_id, None)
                _failstamp.pop(site_id, None)
                _lasterr.pop(site_id, None)
                events.broadcast("instance.listening", site_id, "-",
                                 f"实例已就绪：pid={p.pid} 监听 127.0.0.1:{port}")
                return
            if p.poll() is not None:
                _fail_start(site_id, f"进程秒死：{_log_tail(site_id)}")
                return
            time.sleep(0.4)
        try:
            p.kill()
        except Exception:
            pass
        _procs.pop(site_id, None)
        _fail_start(site_id, f"进程存活但端口 {port} 未监听：{_log_tail(site_id)}")
    try:
        asyncio.get_running_loop().create_task(asyncio.to_thread(_check))
    except RuntimeError:
        threading.Thread(target=_check, daemon=True).start()
    events.broadcast("instance.started", site_id, "-", f"实例进程已拉起 pid={p.pid}，端口 {port}")
    return p.pid


def stop(site_id: str, kill_orphan: bool = False):
    # 重启后首次接触该实例：先扫杀上一代遗留的孤儿进程（命令行含实例路径）
    if kill_orphan and site_id not in _scanned:
        _scanned.add(site_id)
        _kill_orphans(site_id)
    p = _procs.pop(site_id, None)
    if p is None:
        return
    try:
        p.terminate()
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()
    except Exception:
        pass
    events.broadcast("instance.stopped", site_id, "-", "实例进程已停止")


def is_running(site_id: str) -> bool:
    p = _procs.get(site_id)
    return bool(p and p.poll() is None)


def status(site_id: str) -> str:
    return "running" if is_running(site_id) else "stopped"


def health(site_id: str, port: int = 0) -> dict:
    """实例健康态：进程状态 + 端口是否监听 + 最近失败原因"""
    p = int(port or (_read_meta(site_id) or {}).get("port") or 0)
    return {"status": status(site_id),
            "listening": _port_listening(p) if p else False,
            "error": _lasterr.get(site_id, "")}


async def wait_ready(site_id: str, port: int, timeout: float = 15.0) -> dict:
    """等待实例端口真正监听；返回 {ok, pid, error}（失败时如实给出原因）"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if port and _port_listening(port):
            proc = _procs.get(site_id)
            return {"ok": True, "pid": proc.pid if proc else None, "error": ""}
        if not is_running(site_id):
            err = _lasterr.get(site_id, "") or _log_tail(site_id) or "实例进程已退出"
            return {"ok": False, "pid": None, "error": err[:300]}
        await asyncio.sleep(0.4)
    return {"ok": False, "pid": None,
            "error": _lasterr.get(site_id, "") or f"等待端口 {port} 监听超时"}


def sync(sites: list[dict]):
    """与 sites 表对齐（run.py 每 2s 调用）：
    启用且模板带后端 → 保证实例部署并运行；停用/删除/无后端 → 停进程"""
    want = {}
    for s in sites:
        if not s.get("enabled"):
            continue
        tid = s.get("clone_id") or ""
        if tid and has_backend(tid):
            want[s["id"]] = (int(s["port"]), tid)
    # 启动缺失 / 配置变化（端口或模板变了 → 重新部署复制）
    for sid, (port, tid) in want.items():
        dst = instance_dir(sid)
        need_deploy = not (dst / "backend" / "app.py").exists()
        meta = _read_meta(sid)
        # 换模板/换端口才全量重置；日常补齐走非破坏式（保护 LLM 自生长文件）
        changed = bool(meta and (meta.get("port") != port or meta.get("template_id") != tid))
        if need_deploy:
            r = deploy(sid, port, tid, full_reset=changed)
            if not r.get("ok"):
                continue
        _write_meta(sid, port, tid)
        if not is_running(sid):
            start(sid, port)
    # 停止多余
    for sid in list(_procs):
        if sid not in want:
            stop(sid)


def _meta_path(site_id: str) -> Path:
    return instance_dir(site_id) / "instance.json"


def _read_meta(site_id: str) -> dict | None:
    try:
        return json.loads(_meta_path(site_id).read_text(encoding="utf-8"))
    except Exception:
        return None


def _write_meta(site_id: str, port: int, template_id: str):
    _meta_path(site_id).write_text(json.dumps(
        {"site_id": site_id, "port": port, "template_id": template_id,
         "updated_at": time.strftime("%Y-%m-%d %H:%M:%S")}, ensure_ascii=False, indent=2),
        encoding="utf-8")


def list_instances() -> list[dict]:
    out = []
    clones = {c["id"]: c for c in store.list_clones()}
    for s in store.list_sites():
        sid = s["id"]
        if not (instance_dir(sid) / "backend" / "app.py").exists():
            continue
        meta = _read_meta(sid) or {}
        h = health(sid, int(s["port"]))
        out.append({"site_id": sid, "site_name": s["name"], "port": s["port"],
                    "template_id": s["clone_id"],
                    "persona": (clones.get(s["clone_id"]) or {}).get("persona", ""),
                    "status": h["status"], "listening": h["listening"],
                    "error": h["error"],
                    "dir": str(instance_dir(sid)),
                    "updated_at": meta.get("updated_at", "")})
    return out


# --------------------------------------------------------------------------- #
# 文件增删改查（LLM 与控制台共用；路径严格限制在实例目录内）
# --------------------------------------------------------------------------- #
_TEXT_EXTS = {".html", ".css", ".js", ".mjs", ".json", ".txt", ".log", ".py", ".md", ".yaml", ".yml"}


def _resolve(site_id: str, rel: str) -> Path:
    base = instance_dir(site_id).resolve()
    fp = (base / rel).resolve()
    if not str(fp).startswith(str(base)):
        raise PermissionError("路径越界")
    return fp


def list_files(site_id: str) -> list[dict]:
    base = instance_dir(site_id)
    if not base.exists():
        return []
    out = []
    for fp in sorted(base.rglob("*")):
        if fp.is_file():
            rel = fp.relative_to(base).as_posix()
            if rel.endswith("instance.stdout.log"):
                continue
            out.append({"path": rel, "size": fp.stat().st_size})
    return out


def read_file(site_id: str, rel: str) -> str:
    fp = _resolve(site_id, rel)
    if not fp.exists():
        raise FileNotFoundError(rel)
    return fp.read_text(encoding="utf-8", errors="replace")


def write_file(site_id: str, rel: str, content: str, dlp: bool = True) -> dict:
    fp = _resolve(site_id, rel)
    ext = fp.suffix.lower()
    if ext in _TEXT_EXTS:
        # 品牌归一：LLM 落盘时可能自带另一套公司名，实例内多套品牌并存等于自曝假站
        site = next((s for s in store.list_sites() if s["id"] == site_id), None)
        brand, slug, domain = growth.brand_of_clone((site or {}).get("clone_id") or "")
        content = growth.normalize_brand(content, brand, slug, domain)
        if dlp:
            content = growth.dlp_scan(content)
    if ext in (".html", ".htm"):
        # LLM 常把 JSON 写成 {&quot;...} 放进 <script>；script 是原始文本区不解码实体，
        # 会导致 JSON.parse 失败、卡片把 {&quot; 当文本显示。写盘前统一还原。
        content = growth.normalize_html(content)
    if ext == ".py":
        # LLM 重写 app.py 常把源站 IP 写进 uvicorn host → 本机绑不上、站点秒死；写盘即强制回环
        from . import cloner
        content = cloner.force_local_host(content)
    fp.parent.mkdir(parents=True, exist_ok=True)
    fp.write_text(content, encoding="utf-8")
    events.broadcast("instance.file.write", site_id, "-", f"文件写入 {rel}")
    return {"ok": True, "path": rel, "bytes": len(content.encode("utf-8"))}


def delete_file(site_id: str, rel: str) -> dict:
    fp = _resolve(site_id, rel)
    if not fp.exists():
        raise FileNotFoundError(rel)
    fp.unlink()
    events.broadcast("instance.file.delete", site_id, "-", f"文件删除 {rel}")
    return {"ok": True, "path": rel}


def restart(site_id: str, port: int) -> int | None:
    _failcnt.pop(site_id, None)   # 手动/进化重启 = 主动意图，清熔断计数
    _failstamp.pop(site_id, None)
    _lasterr.pop(site_id, None)
    return start(site_id, port)


# --------------------------------------------------------------------------- #
# LLM 态势进化：读取实时攻击态势 → LLM 输出文件操作 → 应用 → 重启实例
# --------------------------------------------------------------------------- #
_EVOLVE_PROMPT = """你是蜜罐靶站的「自生长引擎」。本项目的核心使命：LLM 根据实时攻击者形态自由生长站点——
新建 HTML/JS/CSS 文件，预判攻击者的下一步动作，提前把那个页面造出来，实现交互式蜜罐：
诱导攻击者不断深入、消耗其时间、收集更多溯源情报（凭据/工具特征/攻击意图）。

【自生长策略（核心）】
- 攻击者提交了登录表单 → 假装登录成功，立刻生长出一个逼真的假后台首页（含导航/统计/待办），
  假后台里再埋更深的功能页（用户管理/财务/日志…），层层递进让攻击者一直有下一步可点。
- 攻击者在探测某路径 → 提前生成该路径的诱饵页（含新的表单/入口继续收集情报）。
- 无人问津或已暴露伪装的路径 → 下线或改造成新诱饵。
- 每个新页面的表单提交必须写入 honeypot.log（收集攻击者输入的凭据/数据），并链向更深层的诱饵页。
- 页面风格延续站点人设，逼真度优先：真实企业的排版密度、文案语气、交互细节。

【你的权利】对下列文件拥有增删改查全部权利（路径相对实例根目录，只能操作 frontend/ 与 backend/ 内的文件）。

【文件清单】
{files}

【可读文件内容（节选）】
{contents}

【实时攻击态势】
{posture}

【人设】{persona}

【硬性要求】
1. 只输出一个 JSON 数组，不要解释文字、不要 markdown 围栏。
2. 每个元素是一种操作：
   {{"op": "write",  "path": "frontend/decoy-admin.html", "content": "完整文件内容"}}
   {{"op": "write",  "path": "backend/app.py", "content": "完整修改后的 app.py（改接口时务必给出全文件）"}}
   {{"op": "delete", "path": "frontend/old-page.html"}}
3. 至少 1 个操作，最多 6 个；新页面必须自包含（CSS/JS 内联），含登录入口 action=/admin/login。
4. 修改 backend/app.py 时：保持 FastAPI 结构、frontend 静态挂载、凭据写 honeypot.log 行为不变；
   新增接口按既有风格；uvicorn host 固定 127.0.0.1，端口读环境变量 HP_SITE_PORT。
5. 品牌延续「{persona}」，不得出现源站真实域名。
"""


def _posture(site_id: str, limit: int = 40) -> str:
    """实时攻击者态势：控制台事件流 + 会话画像 + 实例本地 honeypot.log + 实例启动日志"""
    lines = []
    if _lasterr.get(site_id):
        lines.append("【最近一次启动失败（请优先修复）】" + _lasterr[site_id][:400])
    try:
        evs = store.list_events(limit=limit)
        for e in evs:
            lines.append(f"[{e['ts']}] {e['type']} {e.get('detail') or ''}")
    except Exception:
        pass
    try:
        sess = store.list_sessions()[:10]
        for s in sess:
            lines.append(f"会话 {s.get('sid','')[:12]} 分={s.get('score',0)} "
                         f"状态={s.get('state','')} 工具={s.get('tool','')} 最近={s.get('last_seen','')}")
    except Exception:
        pass
    try:
        logp = instance_dir(site_id) / "backend" / "honeypot.log"
        if logp.exists():
            tail = logp.read_text(encoding="utf-8", errors="replace").strip().splitlines()[-30:]
            lines.append("实例凭据日志（最近30条）:\n" + "\n".join(tail))
        else:
            lines.append("实例凭据日志：暂无记录")
    except Exception:
        pass
    try:
        sp = instance_dir(site_id) / "backend" / "instance.stdout.log"
        if sp.exists():
            tail = sp.read_text(encoding="utf-8", errors="replace").strip().splitlines()[-25:]
            lines.append("实例启动/运行日志（最近25条）:\n" + "\n".join(tail))
    except Exception:
        pass
    return "\n".join(lines[:140]) or "暂无态势数据"


def _read_snapshot(site_id: str, max_chars: int = 24000) -> tuple[str, str]:
    """文件清单 + 关键文件内容节选"""
    files = list_files(site_id)
    names = "\n".join(f"- {f['path']} ({f['size']}B)" for f in files[:60])
    buf = []
    budget = max_chars
    priority = ["backend/app.py", "frontend/index.html"]
    for rel in priority + [f["path"] for f in files
                           if f["path"] not in priority and f["path"].endswith((".html", ".py"))]:
        try:
            c = read_file(site_id, rel)
        except Exception:
            continue
        piece = c[:min(8000, max(0, budget))]
        if not piece:
            break
        budget -= len(piece)
        buf.append(f"===== {rel} =====\n{piece}")
        if budget <= 0:
            break
    return names, "\n\n".join(buf)


def _parse_ops(text: str) -> list[dict]:
    """解析 LLM 的操作数组。LLM 回复常因 max_tokens 截断导致 JSON 未闭合，
    此时用括号配对逐个抠出完整对象（截断的最后一个对象自然丢弃）"""
    text = (text or "").strip().strip("`")
    if text.startswith("json"):
        text = text[4:]
    lo, hi = text.find("["), text.rfind("]")
    if lo >= 0 and hi > lo:
        try:
            arr = json.loads(text[lo:hi + 1])
            if isinstance(arr, list):
                return arr
        except Exception:
            pass
    # 容错：括号配对提取每个完整对象
    out: list[dict] = []
    depth, start, in_str, esc = 0, -1, False, False
    for i, ch in enumerate(text[lo if lo >= 0 else 0:], lo if lo >= 0 else 0):
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            if depth > 0:
                depth -= 1
                if depth == 0 and start >= 0:
                    try:
                        obj = json.loads(text[start:i + 1])
                        if isinstance(obj, dict):
                            out.append(obj)
                    except Exception:
                        pass
                    start = -1
    return out


def _apply_ops(site_id: str, ops: list[dict]) -> tuple[list[dict], list[dict]]:
    """应用 LLM 文件操作（write/delete），返回 (applied, skipped)"""
    applied, skipped = [], []
    for op in ops[:8]:
        kind, rel = str(op.get("op") or "").lower(), str(op.get("path") or "")
        if not rel or rel.startswith(("backend/instance", "site.json", "instance.json")):
            skipped.append({"op": kind, "path": rel, "why": "系统文件不可动"})
            continue
        try:
            if kind == "write":
                content = op.get("content")
                if content is None:
                    raise ValueError("缺少 content")
                r = write_file(site_id, rel, str(content))
                applied.append({"op": "write", "path": r["path"], "bytes": r["bytes"]})
            elif kind == "delete":
                r = delete_file(site_id, rel)
                applied.append({"op": "delete", "path": r["path"]})
            else:
                skipped.append({"op": kind, "path": rel, "why": "未知操作类型"})
        except Exception as e:
            skipped.append({"op": kind, "path": rel, "why": str(e)[:100]})
    return applied, skipped


async def evolve(site_id: str, port: int, instruction: str = "") -> dict:
    """LLM 依据实时态势对实例文件增删改查，应用后重启实例进程"""
    persona = ""
    try:
        meta = _read_meta(site_id) or {}
        clone = store.get_clone(meta.get("template_id", ""))
        persona = (clone or {}).get("persona", "")
    except Exception:
        pass
    files, contents = _read_snapshot(site_id)
    try:
        out, used = await asyncio.wait_for(llm_gateway.chat(
            [{"role": "system", "content": "你是靶站实时进化引擎，只输出 JSON 操作数组。"},
             {"role": "user", "content": _EVOLVE_PROMPT.replace("{files}", files).replace(
                 "{contents}", contents).replace("{posture}", _posture(site_id)).replace(
                 "{persona}", persona or "虚构企业").replace(
                 "{instruction}", instruction or "（自行研判攻击者下一步意图，生长最有诱导价值的诱饵页）")}],
            task="blueprint", max_tokens=24000, timeout=150), timeout=420)
    except asyncio.TimeoutError:
        return {"ok": False, "error": "LLM 进化总超时（420s），请稍后重试或精简指令"}
    ops = _parse_ops(out)
    if not ops:
        return {"ok": False, "error": f"LLM 未输出可解析操作（{used or '无可用模型'}）"}
    applied, skipped = _apply_ops(site_id, ops)
    pid = restart(site_id, port)
    r = await wait_ready(site_id, port)
    events.broadcast("instance.evolved", site_id, "-",
                     f"LLM 态势进化（{used}）：应用 {len(applied)} 个操作，" +
                     (f"实例已重启并监听 127.0.0.1:{port}（pid={pid}）" if r.get("ok")
                      else f"但重启失败：{r.get('error')}"))
    return {"ok": True, "used": used, "applied": applied, "skipped": skipped, "pid": pid,
            "listening": bool(r.get("ok")), "error": r.get("error", "")}


# --------------------------------------------------------------------------- #
# 靶站 LLM 对话框：用户自由指挥真实运行中的靶站（功能增减/页面调整/问答）
# 回复约定：正常文字流式直播；若要改文件，在回复末尾输出 <<<OPS>>>[...操作JSON...]
# --------------------------------------------------------------------------- #
_ASSIST_PROMPT = """你是靶站「{name}」（端口 {port}，{state}）的自生长助手，用户通过对话框自由指挥你修改这个真实运行的站点。

【你的工作方式（自生长引擎）】根据实时攻击者形态自由生长站点：新建 HTML/JS/CSS 文件，预判攻击者下一步要走的页面并提前生成——
攻击者提交登录就假装登录成功并生长假后台，假后台里再埋更深的功能页，层层递进，实现交互式蜜罐：
诱导攻击者不断深入、消耗时间、收集更多溯源情报。每个新页面的表单提交必须写入 honeypot.log 并链向更深层诱饵页。

【站点人设】{persona}
【文件清单】
{files}
【可读文件内容（节选）】
{contents}
【实时攻击态势】
{posture}

【回复规则】
1. 先用简洁的中文文字回应用户（说明你要做什么/回答问题），这段会实时显示给用户。
2. 若需要修改站点文件，在文字之后另起一行输出标记行 <<<OPS>>>，紧跟一个 JSON 操作数组（会解析执行并自动重启站点，执行结果会播报给用户）：
   <<<OPS>>>
   [{{"op": "write", "path": "frontend/decoy-admin.html", "content": "完整文件内容"}},
    {{"op": "delete", "path": "frontend/old.html"}}]
3. 纯问答则不输出 <<<OPS>>> 段。
4. 修改 backend/app.py 时给出完整文件：保持 FastAPI 结构、frontend 静态挂载、凭据写 honeypot.log 行为不变。
5. 运行方式由框架接管：启动器会 import 你的 app.py 并用 uvicorn 绑定 127.0.0.1:HP_SITE_PORT，
   你写在 app.py 末尾的 uvicorn.run(...) 不会执行；但仍建议写成 host="127.0.0.1"、端口读 HP_SITE_PORT。
   app.py 必须暴露名为 app 的 FastAPI 对象，导入期不得抛异常（否则站点起不来）。
6. 新页面自包含（CSS/JS 内联）；品牌延续人设，不得出现源站真实域名；最多 6 个操作。
7. 用户要求增减功能、改页面、改话术时优先动手实现，不要只给建议。
8. HTML 里嵌入 JSON 一律用原始字符（如 {"a": 1}），严禁出现 &quot; &amp; 等 HTML 实体；
   <script type="application/json"> 内必须是纯 JSON，否则浏览器解析失败、卡片会把实体当文本显示。"""


async def _assist(site_id: str, port: int, text: str):
    """后台执行：LLM 回复流式直播（思考 site.think / 正文 site.llm）；
    含 <<<OPS>>> 则应用操作并重启，重启结果如实播报（成功=端口已监听，失败=给出原因）"""
    from . import llm_gateway
    try:
        meta = _read_meta(site_id) or {}
        persona = ""
        try:
            persona = (store.get_clone(meta.get("template_id", "")) or {}).get("persona", "")
        except Exception:
            pass
        files, contents = _read_snapshot(site_id)
        prompt = _ASSIST_PROMPT.replace("{name}", str(meta.get("name") or site_id)).replace(
            "{port}", str(port)).replace(
            "{state}", "运行中" if is_running(site_id) else "未运行").replace(
            "{persona}", persona or "虚构企业").replace(
            "{files}", files).replace("{contents}", contents).replace(
            "{posture}", _posture(site_id))
        # 思考流与正文分流；正文出现 <<<OPS>>> 后不再上屏（操作段单独播报）
        st = {"tail": "", "cut": False, "ans": ""}

        def _on_chunk(t: str, kind: str):
            if kind == "reasoning":
                events.publish("site.think", site_id, t)
                return
            if st["cut"]:
                return
            combo = st["tail"] + t
            idx = combo.find("<<<OPS>>>")
            if idx >= 0:
                keep = combo[:idx]
                if len(keep) > len(st["tail"]):
                    events.publish("site.llm", site_id, keep[len(st["tail"]):])
                    st["ans"] += keep[len(st["tail"]):]
                st["cut"] = True
                return
            events.publish("site.llm", site_id, t)
            st["ans"] += t
            st["tail"] = combo[-16:]

        out, used = await llm_gateway.chat(
            [{"role": "system", "content": "你是靶站运维助手，按回复规则输出。"},
             {"role": "user", "content": f"用户消息：{text}\n\n站点上下文：\n{prompt}"}],
            task="answer", max_tokens=24000, timeout=150, on_chunk=_on_chunk)
        events.publish_flush("site.llm", site_id)
        events.publish_flush("site.think", site_id)
        # 原始回复落盘（排障用：可核对 LLM 是否按约定输出 <<<OPS>>>）
        try:
            (instance_dir(site_id) / "backend" / "assist_last.txt").write_text(
                f"【用户】{text}\n【LLM 原始回复】\n{out}", encoding="utf-8")
        except Exception:
            pass
        # 答复正文单独落库（只入库不推 SSE，避免与实时流重复气泡；刷新后据此回填对话历史）
        try:
            answer = (st["ans"] or out.split("<<<OPS>>>")[0]).strip()
            if answer:
                store.add_event("site.answer", site_id, "-", answer[:4000])
        except Exception:
            pass
        # 解析操作段
        ops = []
        marker = out.find("<<<OPS>>>")
        if marker >= 0:
            ops = _parse_ops(out[marker + len("<<<OPS>>>"):])
        if ops:
            applied, skipped = _apply_ops(site_id, ops)
            pid = restart(site_id, port)
            r = await wait_ready(site_id, port)
            head = f"已应用 {len(applied)} 个文件操作"
            if skipped:
                head += "，跳过 " + "；".join(
                    f"{s.get('op')} {s.get('path')}（{s.get('why')}）" for s in skipped[:3])
            if r.get("ok"):
                events.broadcast("site.applied", site_id, "-",
                                 f"{head}，站点已重启并监听 127.0.0.1:{port}（pid={pid}）")
            else:
                events.broadcast("site.applied", site_id, "-",
                                 f"{head}，但站点重启失败：{r.get('error')}；"
                                 f"已把启动日志喂回给你，请据此修复 backend/app.py")
                # 失败原因回灌给模型，让它能继续修
                try:
                    await llm_gateway.chat(
                        [{"role": "system", "content": "你是靶站运维助手，只输出可执行的修复说明与 JSON 操作数组。"},
                         {"role": "user", "content":
                             f"刚才的修改导致站点启动失败，请阅读下面的启动日志并继续修复"
                             f"（可直接输出 <<<OPS>>> 操作数组）：\n{r.get('error','')}\n\n"
                             f"当前 backend/app.py 开头：\n"
                             f"{read_file(site_id, 'backend/app.py')[:4000]}"}],
                        task="answer", max_tokens=24000, timeout=150)
                except Exception:
                    pass
        events.broadcast("site.done", site_id, "-", f"本轮对话完成（{used}）")
    except asyncio.CancelledError:
        raise
    except Exception as e:
        events.broadcast("site.reply", site_id, "-", f"助手异常：{str(e)[:160]}")
        events.broadcast("site.done", site_id, "-", "本轮对话结束")


def site_command(site_id: str, port: int, text: str) -> dict:
    """靶站对话框入口：广播用户消息 → 调度后台 LLM 助手"""
    if not instance_dir(site_id).exists():
        return {"error": "靶站实例不存在（该靶站可能未启用模板部署）"}
    events.broadcast("site.user", site_id, "-", text)
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(_assist(site_id, port, text))
    except RuntimeError:
        asyncio.run(_assist(site_id, port, text))
    return {"ok": True, "note": "助手正在处理，回复实时直播"}


atexit.register(lambda: [stop(sid) for sid in list(_procs)])
