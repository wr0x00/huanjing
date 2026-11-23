"""一键克隆器 v4 —— 真实下载前端 + LLM 分析接口 + LLM 生成后端

流水线（一个站点 = data/sites/<时间戳ID>/ 下的完整前后端）：
  1. Download —— 真实下载目标站 index.html + 同源静态资产（css/js/图片/字体）到 frontend/
                并把 HTML 里的同源绝对引用重写为本地相对路径
  2. Analyze —— 机械抽取表单 action / fetch / API 路径作为线索，指挥模型（LLM）分析出
                结构化接口清单 JSON [{method, path, request, response, desc}]
  3. Build   —— 指挥模型按接口清单生成可运行后端（FastAPI：挂载 frontend 静态目录 +
                逐个实现接口；登录类接口记录凭据、按人设返回拟真假数据）
  4. Audit   —— 静态自检（app.py 存在 / 接口路径齐备），问题回喂指挥模型修正一轮
  5. Deploy  —— DLP 兜底扫描全部文本文件，index.html 与文本资产入库 SiteGraph 对外服务
站点 ID 用时间命名（20261119_153045），全程无乱码。
"""
import asyncio
import datetime
import json
import os
import re
import time
from pathlib import Path
from urllib.parse import urljoin, urlsplit

import httpx

from . import config, events, growth, llm_gateway, store

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")
MAX_ASSET_FILES = 40          # 单站最多下载的同源资产数
MAX_ASSET_BYTES = 3_000_000   # 单个资产体积上限
MAX_ANALYZE_CHARS = 60_000    # 喂给 LLM 的前端材料截断
MAX_BUILD_TOKENS = 32000
FILE_BLOCK_RE = re.compile(r"```file:([^\n`]+)\n(.*?)```", re.S)

_SITES_DIR = config.DATA_DIR / "sites"

# 同源资产扩展名白名单
ASSET_EXTS = {".css", ".js", ".mjs", ".png", ".jpg", ".jpeg", ".gif", ".svg",
              ".ico", ".webp", ".woff", ".woff2", ".ttf", ".eot"}
_TEXT_CTYPE = {".css": "text/css", ".js": "application/javascript",
               ".mjs": "application/javascript", ".svg": "image/svg+xml"}


_REL_TAIL = re.compile(
    r"^(.*?\.(?:html?|css|js|mjs|json|txt|md|ya?ml|svg|png|jpe?g|gif|ico|woff2?))(?:\..*)?$", re.I)


def _clean_rel(rel: str) -> str:
    """净化 LLM 给出的文件路径：只保留第一段合法相对路径。

    LLM 偶尔把提示词的复述写进代码围栏标题，例如
    ```file:decoys/news-center.html. The prose before code block in Chinese, concise. ...```
    直接落盘会生成垃圾文件。这里截断到第一个空白，再把尾部说明文字裁掉。
    """
    raw = str(rel or "").strip().strip("`\"'").replace("\\", "/").lstrip("/")
    if not raw:
        return ""
    token = re.split(r"[\s,;:]", raw, maxsplit=1)[0]
    m = _REL_TAIL.match(token)
    if m:
        token = m.group(1)
    token = re.sub(r'[<>"|?*\x00-\x1f]', "", token)
    parts = [p for p in token.split("/") if p and p not in (".", "..")]
    return "/".join(parts)


def _parse_files(llm_out: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for path, content in FILE_BLOCK_RE.findall(llm_out):
        rel = _clean_rel(path)
        if rel:
            out[rel] = content
    return out


# --------------------------------------------------------------------------- #
# Step 1：真实下载前端
# --------------------------------------------------------------------------- #
async def _download_frontend(client: httpx.AsyncClient, base_url: str,
                             site_dir: Path) -> tuple[str, list[dict]]:
    """下载 index.html + 同源静态资产到 frontend/，返回（重写引用后的 HTML, 资产清单）"""
    r = await client.get(base_url)
    r.raise_for_status()
    html = r.text
    base = str(r.url)
    origin_host = urlsplit(base).netloc
    fr = site_dir / "frontend"
    fr.mkdir(parents=True, exist_ok=True)

    # 收集同源资产引用（跨域资产不下载：运行时引擎会自动反向代理回源站）
    refs: set[str] = set()
    for m in re.finditer(r"""(?:src|href)\s*=\s*["']([^"']+)["']""", html, re.I):
        u = (m.group(1) or "").strip()
        if not u or u.startswith(("#", "data:", "javascript:", "mailto:", "tel:")):
            continue
        absu = urljoin(base, u)
        p = urlsplit(absu)
        if p.netloc != origin_host or os.path.splitext(p.path)[1].lower() not in ASSET_EXTS:
            continue
        refs.add(absu)

    downloaded: list[dict] = []
    for absu in sorted(refs)[:MAX_ASSET_FILES]:
        path = urlsplit(absu).path.lstrip("/")
        if not path or ".." in path:
            continue
        try:
            ar = await client.get(absu)
            if ar.status_code != 200 or not ar.content:
                continue
            fp = fr / path
            fp.parent.mkdir(parents=True, exist_ok=True)
            fp.write_bytes(ar.content[:MAX_ASSET_BYTES])
            # HTML 里的同源绝对引用改写为本地相对路径
            html = html.replace(f'"{absu}"', f'"{path}"').replace(f"'{absu}'", f"'{path}'")
            downloaded.append({"url": absu, "path": path, "bytes": len(ar.content)})
        except Exception:
            continue  # 单个资产失败不影响整体
    (fr / "index.html").write_text(html, encoding="utf-8")
    return html, downloaded


# --------------------------------------------------------------------------- #
# Step 2：接口线索抽取 + LLM 分析
# --------------------------------------------------------------------------- #
_ACTION_RE = re.compile(r"""<form[^>]*action\s*=\s*["']([^"']+)["']""", re.I)
_CALL_RE = re.compile(
    r"""(?:fetch|axios(?:\.\w+)*|\$\.(?:get|post|ajax)|url)\s*\(\s*["'`]([^"'`]+)["'`]""", re.I)
_API_RE = re.compile(
    r"""["'`](/(?:api|v\d|admin|user|login|auth|register|search|upload|comment|order|act|do)[\w/\-.]*)["'`]""",
    re.I)


def _interface_hints(html: str) -> dict:
    """机械抽取前端里的接口线索，作为 LLM 分析的锚点"""
    inputs = re.findall(r"<input[^>]*>", html, re.I)
    forms = re.findall(r"<form[^>]*>.*?</form>", html, re.S | re.I)
    form_desc = []
    for f in forms[:8]:
        act = _ACTION_RE.search(f)
        fields = re.findall(r"""name\s*=\s*["']([^"']+)["']""", f, re.I)
        form_desc.append({"action": act.group(1) if act else "", "fields": fields[:12]})
    return {
        "forms": form_desc,
        "form_actions": list(dict.fromkeys(_ACTION_RE.findall(html)))[:15],
        "ajax_calls": list(dict.fromkeys(_CALL_RE.findall(html)))[:25],
        "api_paths": list(dict.fromkeys(_API_RE.findall(html)))[:25],
        "input_controls": len(inputs),
        "password_fields": sum(1 for i in inputs if "password" in i.lower()),
    }


_ANALYZE_PROMPT = """你是蜜罐部署系统的「接口分析引擎」。以下是目标站点的前端文件材料。请分析出该站点前端会调用的后端 HTTP 接口清单。

【硬性要求】
1. 只输出一个 JSON 数组，不要任何解释文字、不要 markdown 代码围栏。
2. 每个元素格式：
   {"method": "GET|POST", "path": "/api/xxx", "request": "参数说明（query 或 JSON 字段）",
    "response": "前端期望的响应内容说明", "desc": "接口用途"}
3. 依据：表单 action、fetch/ajax 调用、URL 中的 api 路径、页面功能推理。至少覆盖登录表单。
4. 若前端未显式调用任何接口，则按页面功能（登录/搜索/留言等）推断最合理的接口。
5. 最多 10 个接口，按重要性排序。

【接口线索（程序抽取）】
{hints}

【前端材料】
{material}
"""

_BUILD_PROMPT = """你是蜜罐部署系统的「后端生成引擎」。根据前端文件与接口清单，生成一个完整可运行的本地后端服务。

【硬性要求】
1. 输出一个或多个文件，每个文件用 ```file:<相对路径>``` 开头的代码块给出，例如：
```file:backend/app.py
...
```
2. 必须输出 backend/app.py（FastAPI + uvicorn 单文件）与 backend/requirements.txt。
3. app.py 行为：
   - 挂载静态目录：StaticFiles(directory=BASE_DIR/"frontend", html=True)，其中
     BASE_DIR = Path(__file__).resolve().parent.parent（即站点根目录，内含 frontend/）。
   - 逐个实现【接口清单】中的全部接口：返回符合前端期望的拟真响应。
   - 登录/注册/改密类接口：把提交的 username/password/验证码等凭据写入
     BASE_DIR/"backend"/"honeypot.log"（JSON 行，含时间戳、IP、表单字段），
     然后返回「登录成功」假响应（始终成功，诱导攻击者继续深入）。
   - 数据类接口：按「{persona}」人设返回虚构但格式逼真的 JSON 数据（订单/用户/文章等）。
   - 未在清单中的路径兜底返回 404 JSON。
   - 端口：uvicorn.run(app, host="127.0.0.1", port=int(os.getenv("HP_SITE_PORT", "8899")))。
4. 品牌拟真：响应中出现的公司名/产品名替换为虚构的「{persona}」体系，不得出现源站真实域名。
5. requirements.txt 只列必要依赖（fastapi、uvicorn）。
6. 只输出文件代码块，不要任何解释文字。

【接口清单】
{interfaces}

【前端材料（index.html 摘要）】
{material}
"""

_FIX_PROMPT = """你上一轮生成的后端自检未通过，请修正后重新输出完整文件（格式同前：```file:<路径>``` 代码块，只输出代码块）。

【自检问题】
{issues}

【上一轮输出】
{prev}
"""


def _offline_backend_files(interfaces: list[dict], persona: str) -> dict[str, str]:
    """指挥模型不可用时的离线兜底：按接口清单程序化生成可运行的 FastAPI 后端，
    保证「一站点一完整前后端」必然成立。"""
    head = (
        '"""蜜罐后端（离线兜底模板生成）：' + persona + '"""\n'
        'import json\n'
        'import os\n'
        'import time\n'
        'from pathlib import Path\n'
        '\n'
        'from fastapi import FastAPI, Request\n'
        'from fastapi.responses import JSONResponse\n'
        'from fastapi.staticfiles import StaticFiles\n'
        '\n'
        'BASE_DIR = Path(__file__).resolve().parent.parent\n'
        'LOG = Path(__file__).resolve().parent / "honeypot.log"\n'
        'PERSONA = ' + json.dumps(persona, ensure_ascii=False) + '\n'
        '\n'
        'app = FastAPI(title="Honeypot Site", docs_url=None)\n'
        '\n'
        'CRED_KEYS = ("username", "password", "passwd", "pwd", "email", "code", "captcha", "otp")\n'
        '\n'
        '\n'
        'async def _fields(request: Request) -> dict:\n'
        '    try:\n'
        '        j = await request.json()\n'
        '        if isinstance(j, dict):\n'
        '            return j\n'
        '    except Exception:\n'
        '        pass\n'
        '    try:\n'
        '        return dict(await request.form())\n'
        '    except Exception:\n'
        '        return {}\n'
        '\n'
        '\n'
        'def _log_creds(fields: dict, ip: str):\n'
        '    rec = {"ts": time.strftime("%Y-%m-%d %H:%M:%S"), "ip": ip,\n'
        '           "credentials": {k: v for k, v in fields.items()\n'
        '                           if k.lower() in CRED_KEYS}}\n'
        '    try:\n'
        '        with LOG.open("a", encoding="utf-8") as f:\n'
        '            f.write(json.dumps(rec, ensure_ascii=False) + "\\n")\n'
        '    except Exception:\n'
        '        pass\n'
        '\n'
        '\n'
    )
    body = []
    n_ep = 0
    for it in interfaces[:10]:
        method = str(it.get("method") or "GET").upper()
        path = str(it.get("path") or "")
        if not path.startswith("/"):
            continue
        n = n_ep
        n_ep += 1
        desc = str(it.get("desc") or it.get("response") or "数据接口").replace('"', "'")[:80]
        if method == "GET":
            body.append(
                f'@app.get("{path}")\n'
                f'async def ep_{n}():\n'
                f'    """{desc}"""\n'
                f'    return {{"code": 0, "msg": "ok", "data": [{{"id": 1, "name": PERSONA + " 示例数据"}}]}}\n'
                f'\n\n')
        else:
            body.append(
                f'@app.post("{path}")\n'
                f'async def ep_{n}(request: Request):\n'
                f'    """{desc}"""\n'
                f'    fields = await _fields(request)\n'
                f'    _log_creds(fields, request.client.host if request.client else "-")\n'
                f'    return {{"ok": True, "msg": "登录成功", '
                f'"token": "hp-" + os.urandom(8).hex()}}\n'
                f'\n\n')
    tail = (
        'app.mount("/", StaticFiles(directory=BASE_DIR / "frontend", html=True), name="static")\n'
        '\n'
        '\n'
        'if __name__ == "__main__":\n'
        '    import uvicorn\n'
        '    uvicorn.run(app, host="127.0.0.1", port=int(os.getenv("HP_SITE_PORT", "8899")))\n'
    )
    return {
        "backend/app.py": head + ("" if not body else "".join(body)) + tail,
        "backend/requirements.txt": "fastapi\nuvicorn\n",
    }


def _extract_json_array(text: str) -> list[dict]:
    """容错解析 LLM 输出的 JSON 数组（容忍 markdown 围栏/前后杂文字）"""
    text = (text or "").strip()
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text, flags=re.S)
    lo, hi = text.find("["), text.rfind("]")
    if lo < 0 or hi <= lo:
        return []
    try:
        arr = json.loads(text[lo:hi + 1])
        return arr if isinstance(arr, list) else []
    except Exception:
        return []


def _backend_audit(files: dict[str, str], interfaces: list[dict]) -> list[str]:
    """Step 4 静态自检：后端文件齐备 + 接口路径实现齐备"""
    issues = []
    app = files.get("backend/app.py", "")
    if not app:
        return ["缺少 backend/app.py"]
    if "FastAPI" not in app:
        issues.append("app.py 未使用 FastAPI")
    if "frontend" not in app:
        issues.append("app.py 未挂载 frontend 静态目录")
    if "honeypot.log" not in app:
        issues.append("登录接口未把凭据写入 honeypot.log")
    if "uvicorn.run(" in app and re.search(r"^import uvicorn", app, re.M) is None:
        issues.append("使用了 uvicorn.run 但缺少 import uvicorn")
    if re.search(r'host\s*=\s*["\'](?!127\.0\.0\.1|0\.0\.0\.0)[\w.]+["\']', app):
        issues.append('uvicorn 绑定地址必须是 127.0.0.1（本地蜜罐）')
    for it in interfaces[:10]:
        path = str(it.get("path") or "")
        method = str(it.get("method") or "GET").upper()
        if not path:
            continue
        if f'"{path}"' not in app and f"'{path}'" not in app and f"({path})" not in app:
            issues.append(f"接口未实现：{method} {path}")
    return issues


def _static_audit(files: dict[str, str]) -> bool:
    """Step 4 静态自检（前端）：所有 HTML 产物都必须是完整文档

    LLM 常只吐一个片段（<h1>内部 VIP 数据</h1>），直接对外服务会渲染成裸片段，
    攻击者一眼看出是拼装页面。这里只做静态判定，补全由 _complete_html 负责。
    """
    for rel, content in (files or {}).items():
        if not str(rel).lower().endswith((".html", ".htm")):
            continue
        low = str(content or "").lower()
        if "<html" not in low and "<!doctype html" not in low:
            return False
    return True


def _complete_html(rel: str, content: str) -> str:
    """把 LLM 给的 HTML 片段补全为完整文档（自检不通过时补）"""
    if _static_audit({rel: content}):
        return content
    title = Path(rel).stem or "页面"
    return ("<!DOCTYPE html><html lang='zh'><head><meta charset='utf-8'>"
            f"<title>{title}</title></head><body>{content}</body></html>")


def _patch_backend(files: dict[str, str]) -> dict[str, str]:
    """自动修补 LLM 生成代码的常见低级遗漏（无需再花一轮 LLM 修正）"""
    app = files.get("backend/app.py")
    if app:
        # from __future__ 必须位于文件最前：先归位，再补 import uvicorn（否则会插错位置）
        m = re.search(r"^from __future__ import [^\n]+\n", app, re.M)
        if m and m.start() != 0:
            app = m.group(0) + app[:m.start()] + app[m.end():]
        if "uvicorn.run(" in app and not re.search(r"^import uvicorn", app, re.M):
            # from __future__ 必须是第一条语句：uvicorn 插在它之后
            fm = re.match(r"(from __future__ import [^\n]+\n)", app)
            app = app[:fm.end(1)] + "import uvicorn\n" + app[fm.end(1):] if fm else \
                "import uvicorn\n" + app
        # 绑定地址强制 127.0.0.1：LLM 常把源站 IP/域名写进 host 导致本机无法启动
        app = re.sub(r'(host\s*=\s*["\'])(?!127\.0\.0\.1|0\.0\.0\.0)[\w.]+(["\'])',
                     r"\g<1>127.0.0.1\g<2>", app)
        # 变量式兜底：任何带引号的内网 IP 字符串（HOST="10.0.0.1" 等写法）统一改写为 127.0.0.1
        app = re.sub(
            r'''(["'])(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\1''',
            r"\g<1>127.0.0.1\g<1>", app)
        files["backend/app.py"] = app
    return files


def _deploy(clone_id: str, site_dir: Path, interfaces: list[dict],
            downloaded: list[dict], source_url: str) -> str:
    """Step 5：DLP 扫描落盘文件 + index.html/文本资产入库 SiteGraph 对外服务"""
    fr = site_dir / "frontend"
    brand, slug, domain = growth.brand_of_clone(clone_id)
    index_html = ""
    # 入口页优先级：指挥模型生成的仿冒首页（site_dir/index.html）> 源站抓取内容
    # （frontend/index.html）。仿冒首页才是蜜罐对外的脸，源站内容只能兜底。
    llm_idx = site_dir / "index.html"
    idx_path = llm_idx if llm_idx.exists() else fr / "index.html"
    if idx_path.exists():
        index_html = idx_path.read_text(encoding="utf-8")
        idx_path.write_text(growth.dlp_scan(
            growth.normalize_brand(index_html, brand, slug, domain)), encoding="utf-8")
        index_html = idx_path.read_text(encoding="utf-8")
        if idx_path != fr / "index.html":
            # 同步到前端目录：独立后端与 SiteGraph 对外服务同一张脸
            (fr / "index.html").write_text(index_html, encoding="utf-8")

    # 文本资产做 DLP 扫描；全部已下载资产入库 SiteGraph（二进制原样，运行时可回源自愈）
    for item in downloaded:
        fp = fr / item["path"]
        if not fp.exists():
            continue
        ext = fp.suffix.lower()
        ctype = _TEXT_CTYPE.get(ext, "application/octet-stream")
        data = fp.read_bytes()
        if ext in _TEXT_CTYPE:
            text = growth.normalize_brand(data.decode("utf-8", "replace"),
                                          brand, slug, domain)
            fp.write_text(growth.dlp_scan(text), encoding="utf-8")
            data = fp.read_bytes()
        node_path = "/" + item["path"].removesuffix(".html")
        store.add_node(clone_id, node_path, data, "llm-clone",
                       title=item["path"], born_from=item["url"],
                       content_type=ctype)
    if index_html:
        store.add_node(clone_id, "/index", index_html, "llm-clone",
                       title="入口页", born_from=source_url)

    # 站点元数据（一站点一完整前后端的清单）
    meta = {
        "id": clone_id,
        "source_url": source_url,
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "frontend": "frontend/index.html + 同源静态资产",
        "backend": "backend/app.py（FastAPI，凭据记录 honeypot.log）",
        "run": "cd backend && pip install -r requirements.txt && python app.py",
        "interfaces": interfaces,
        "assets": downloaded,
    }
    (site_dir / "site.json").write_text(
        json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    return index_html


async def run_clone(source_url: str, persona: str) -> str:
    """控制台入口：下载前端 → LLM 分析接口 → LLM 生成后端 → 自检 → 部署"""
    return await _run(source_url, persona)


_STALE_MINUTES = 20
_INTERIM_STATES = ("DOWNLOADING", "ANALYZING", "BUILDING", "AUDITING")


def fail_stale_clones():
    """僵尸任务清扫：中间状态停留超过阈值（进程重启/异常挂起遗留）→ 标记超时失败。
    由 run.py 同步周期调用，保证克隆列表永远不会永久卡在 BUILDING。"""
    now = datetime.datetime.now()
    for c in store.list_clones():
        if c.get("status") not in _INTERIM_STATES:
            continue
        try:
            created = datetime.datetime.fromisoformat(c["created_at"])
        except Exception:
            continue
        if (now - created).total_seconds() > _STALE_MINUTES * 60:
            store.set_clone_status(c["id"], "FAILED: 超时（流水线熔断，任务被清扫）")
            events.broadcast("clone.FAILED", c["id"], "-",
                             f"克隆任务 {c['id']} 中间状态停留超 {_STALE_MINUTES} 分钟，已清扫为失败")


def _live(clone_id: str):
    """LLM 流式片段 → SSE 实时推送（监控大屏可见 LLM 正在产出）"""
    def on_chunk(text: str, kind: str):
        events.publish("clone.llm", clone_id, text)
    return on_chunk


def _user_suffix(clone_id: str) -> str:
    """对话框用户指令注入当前阶段提示词（无指令返回空串）"""
    from . import clone_runner
    cmds = clone_runner.drain_cmds(clone_id)
    return ("\n\n【用户附加指令】（必须遵守）\n" + cmds) if cmds else ""


async def _run(source_url: str, persona: str, clone_id: str | None = None) -> str:
    if not clone_id:
        clone_id = time.strftime("%Y%m%d_%H%M%S")  # 站点 ID 用时间命名，无乱码
    site_dir = _SITES_DIR / clone_id
    store.add_clone(clone_id, source_url, persona, "DOWNLOADING")
    events.broadcast("clone.progress", clone_id, "-", f"开始克隆 {source_url} → sites/{clone_id}/")
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=20,
                                     headers={"User-Agent": UA}) as client:
            # ---- Step 1：真实下载前端 ----
            html, downloaded = await _download_frontend(client, source_url, site_dir)
            store.set_clone_status(clone_id, "ANALYZING")
            events.broadcast("clone.progress", clone_id, "-",
                             f"前端下载完成：index.html + {len(downloaded)} 个同源资产已落盘 frontend/")

            # ---- Step 2：LLM 分析接口（总熔断 300s，超时用推断接口降级，绝不卡死） ----
            store.set_clone_status(clone_id, "ANALYZING")
            hints = _interface_hints(html)
            material = html[:MAX_ANALYZE_CHARS]
            try:
                out, used = await asyncio.wait_for(llm_gateway.chat(
                    [{"role": "system", "content": "你是接口分析引擎，只输出 JSON 数组。"},
                     {"role": "user", "content": _ANALYZE_PROMPT.replace(
                         "{hints}", json.dumps(hints, ensure_ascii=False)
                     ).replace("{material}", material) + _user_suffix(clone_id)}],
                    task="blueprint", max_tokens=4096, timeout=90,
                    on_chunk=_live(clone_id)), timeout=300)
            except asyncio.TimeoutError:
                out, used = None, None
                events.broadcast("clone.progress", clone_id, "-", "接口分析总超时（300s），降级为推断接口")
            events.publish_flush("clone.llm", clone_id)
            interfaces = _extract_json_array(out)
            if not interfaces:
                interfaces = [{"method": "POST", "path": "/admin/login",
                               "request": "form: username, password",
                               "response": "登录成功", "desc": "登录接口（页面含登录表单，推断）"}]
                events.broadcast("clone.progress", clone_id, "-",
                                 "接口分析未解析出 JSON，使用推断的默认登录接口")
            events.broadcast("clone.progress", clone_id, "-",
                             f"接口分析完成（{used}）：识别 {len(interfaces)} 个接口 "
                             + ", ".join(f"{i.get('method')} {i.get('path')}" for i in interfaces[:5]))

            # ---- Step 3：LLM 生成后端（总熔断 560s：3 次重试上限；超时立即走离线兜底，绝不卡 BUILDING） ----
            store.set_clone_status(clone_id, "BUILDING")
            t_build = time.time()
            iface_txt = json.dumps(interfaces, ensure_ascii=False, indent=1)
            try:
                bout, _ = await asyncio.wait_for(llm_gateway.chat(
                    [{"role": "system", "content": "你是后端生成引擎，只输出 ```file:<路径>``` 代码块。"},
                     {"role": "user", "content": _BUILD_PROMPT.replace(
                         "{persona}", persona).replace(
                         "{interfaces}", iface_txt).replace("{material}", material[:15000]) + _user_suffix(clone_id)}],
                    task="blueprint", max_tokens=MAX_BUILD_TOKENS, timeout=180,
                    on_chunk=_live(clone_id)), timeout=560)
            except asyncio.TimeoutError:
                bout = None
                events.broadcast("clone.progress", clone_id, "-",
                                 f"后端生成总超时（{int(time.time()-t_build)}s），立即切换离线兜底")
            events.publish_flush("clone.llm", clone_id)
            if not bout:
                # 指挥模型不可用：离线兜底按接口清单程序化生成后端，保证完整前后端
                files = _offline_backend_files(interfaces, persona)
                events.broadcast("clone.progress", clone_id, "-",
                                 "指挥模型不可用，已用离线兜底模板生成后端")
            else:
                files = _parse_files(bout)
                if "backend/app.py" not in files:
                    offline = _offline_backend_files(interfaces, persona)
                    offline.update(files)
                    files = offline
                    events.broadcast("clone.progress", clone_id, "-",
                                     "指挥模型未输出 backend/app.py，已并入离线兜底后端")
            events.broadcast("clone.progress", clone_id, "-",
                             f"后端生成完成：{len(files)} 个文件")

            # ---- Step 4：静态自检 + 自动修补 + 一轮修正（总熔断 300s） ----
            store.set_clone_status(clone_id, "AUDITING")
            files = _patch_backend(files)
            issues = _backend_audit(files, interfaces)
            if issues and bout:
                events.broadcast("clone.progress", clone_id, "-",
                                 f"后端自检发现 {len(issues)} 个问题，回喂指挥模型修正")
                try:
                    fix_out, _ = await asyncio.wait_for(llm_gateway.chat(
                        [{"role": "system", "content": "你是后端生成引擎，只输出 ```file:<路径>``` 代码块。"},
                         {"role": "user", "content": _FIX_PROMPT.replace(
                             "{issues}", "\n".join(f"- {i}" for i in issues)
                         ).replace("{prev}", bout[:12000]) + _user_suffix(clone_id)}],
                        task="blueprint", max_tokens=MAX_BUILD_TOKENS, timeout=180,
                        on_chunk=_live(clone_id)), timeout=300)
                except asyncio.TimeoutError:
                    fix_out = None
                    events.broadcast("clone.progress", clone_id, "-", "修正轮总超时（300s），保留自检修补结果")
                events.publish_flush("clone.llm", clone_id)
                fixed = _parse_files(fix_out) if fix_out else {}
                if fixed:
                    remaining = _backend_audit(fixed, interfaces)
                    files = fixed
                    events.broadcast("clone.progress", clone_id, "-",
                                     f"修正后剩余 {len(remaining)} 个问题，DLP 兜底后部署")
            elif issues:
                events.broadcast("clone.progress", clone_id, "-",
                                 f"后端自检 {len(issues)} 个问题（离线兜底产物），DLP 兜底后部署")

            # ---- Step 5：落盘 + 部署 ----
            brand, slug, domain = growth.brand_of_persona(persona)
            for rel, content in files.items():
                rel = rel.replace("\\", "/")
                if ".." in rel:
                    continue
                fp = site_dir / rel
                fp.parent.mkdir(parents=True, exist_ok=True)
                content = growth.dlp_scan(
                    growth.normalize_brand(content, brand, slug, domain))
                fp.write_text(_complete_html(rel, content), encoding="utf-8")
            index_html = _deploy(clone_id, site_dir, interfaces, downloaded, source_url)
            if not index_html:
                store.set_clone_status(clone_id, "FAILED: 前端 index.html 缺失")
                events.broadcast("clone.FAILED", clone_id, "-", "未获取到 index.html，克隆中止")
                return clone_id
            store.add_ledger(clone_id, "commander-clone", "/index", "llm-clone",
                             f"克隆站点：前端{1 + len(downloaded)}文件 + 后端{len(files)}文件 + "
                             f"{len(interfaces)}接口")
            store.set_clone_status(clone_id, "DEPLOYED")
            events.broadcast("growth.node.created", clone_id, "-",
                             f"站点克隆完成 → data/sites/{clone_id}/（frontend/ + backend/ + site.json，"
                             f"后端启动：cd backend && python app.py）")
            return clone_id
    except Exception as e:
        store.set_clone_status(clone_id, f"FAILED: {str(e)[:120]}")
        events.broadcast("clone.FAILED", clone_id, "-", f"克隆失败：{str(e)[:120]}")
        return clone_id


async def morph(clone_id: str, instruction: str = "") -> dict:
    """整体蜜罐变形：指挥模型审视当前 SiteGraph，生成新的诱饵页面写入节点"""
    clone = store.get_clone(clone_id)
    if not clone:
        return {"error": f"蜜罐 {clone_id} 不存在"}
    digest = store.digest_nodes(clone_id)
    brand, slug, domain = growth.brand_of_persona(clone.get("persona") or "")
    out, _ = await llm_gateway.chat(
        [{"role": "system", "content":
            "你是蜜罐变形引擎，只输出 ```file:<路径>``` 代码块，路径形如 decoys/xxx.html。"},
         {"role": "user", "content":
            f"蜜罐人设：{clone['persona']}\n当前站点结构：\n{digest}\n"
            f"变形指令（留空则自行研判最有诱导价值的方向）：{instruction or '（自行研判）'}\n"
            "生成 1-2 个新诱饵页面（自包含 HTML，含可交互假数据、登录入口 action=/admin/login，"
            "品牌延续人设，内嵌看似敏感的虚构数据诱惑攻击者深入）。"
            "注意：HTML 内嵌 JSON 必须用原始字符（{\"a\": 1}），禁止 &quot; 等实体；"
            "<script type=\"application/json\"> 内必须是纯 JSON。"}],
        task="blueprint", max_tokens=MAX_BUILD_TOKENS, timeout=300)
    if not out:
        return {"error": "指挥模型不可用"}
    files = _parse_files(out)
    base = _SITES_DIR / clone_id
    created = []
    for rel, content in files.items():
        rel = rel.replace("\\", "/")
        if ".." in rel:
            continue
        content = growth.normalize_html(growth.dlp_scan(
            growth.normalize_brand(content, brand, slug, domain)))
        (base / rel).parent.mkdir(parents=True, exist_ok=True)
        (base / rel).write_text(content, encoding="utf-8")
        path = "/" + rel.removesuffix(".html")
        store.add_node(clone_id, path, content, "llm-morph", title=rel,
                       born_from="morph")
        store.add_ledger(clone_id, "morph", path, "llm-morph", "指挥模型变形生成")
        created.append(path)
    events.broadcast("growth.node.created", clone_id, "-",
                     f"蜜罐变形：新增诱饵 {created} → clone:{clone_id}")
    return {"ok": True, "created": created}


_MORPH_PROMPT = """你是蜜罐的「指挥靶站变形」引擎，与用户对话式协作：用户描述期望的变形方向，
你据此生成新的诱饵页面（自包含 HTML），让攻击者以为打进了真实后台。

【回复规则】
1. 先用一段话说明本次变形思路（造什么页面、为什么能勾住攻击者、诱饵数据是什么），再给代码块。
2. 代码块格式：```file:<相对路径>```，路径相对站点根目录，例如 decoys/admin.html、decoys/admin/users.html。
3. 每个页面必须自包含（内联 CSS/JS），延续蜜罐人设品牌，含可交互假数据与登录入口 action=/admin/login。
4. 数据必须虚构但逼真（订单/用户/财务/日志等），让攻击者觉得已得手而继续深入。
5. 一次最多生成 3 个页面。只输出代码块，不要输出其它说明性代码块。
6. HTML 中嵌入 JSON 必须使用原始字符（如 {"title": "..."}），严禁写成 &quot; 等 HTML 实体；
   <script type="application/json"> 内必须是纯 JSON，否则浏览器 JSON.parse 会失败、卡片会把实体当文本显示。
"""

_MORPH_HIST_MAX = 6


async def morph_chat(clone_id: str, instruction: str,
                     history: list[dict] | None = None) -> dict:
    """指挥靶站变形（对话式）：流式输出指挥模型回复，并把生成的页面落到蜜罐目录 + SiteGraph"""
    clone = store.get_clone(clone_id)
    if not clone:
        return {"error": f"蜜罐 {clone_id} 不存在"}
    digest = store.digest_nodes(clone_id)
    brand, slug, domain = growth.brand_of_persona(clone.get("persona") or "")
    msgs = [{"role": "system", "content": _MORPH_PROMPT}]
    for h in (history or [])[-_MORPH_HIST_MAX:]:
        role = h.get("role")
        content = str(h.get("content") or "").strip()
        if role in ("user", "assistant") and content:
            msgs.append({"role": role, "content": content[:2000]})
    msgs.append({"role": "user", "content":
        f"蜜罐人设：{clone['persona']}\n当前站点结构：\n{digest}\n"
        f"变形指令：{instruction or '（自行研判最有诱导价值的方向）'}"})
    events.publish("morph.llm", clone_id, "", flush_len=1)
    out, _ = await llm_gateway.chat(
        msgs, task="blueprint", max_tokens=MAX_BUILD_TOKENS, timeout=300,
        on_chunk=lambda t, kind: events.publish("morph.llm", clone_id, t))
    events.publish_flush("morph.llm", clone_id)
    if not out:
        return {"error": "指挥模型不可用"}
    files = _parse_files(out)
    base = _SITES_DIR / clone_id
    created = []
    for rel, content in files.items():
        rel = rel.replace("\\", "/")
        if ".." in rel:
            continue
        content = growth.normalize_html(growth.dlp_scan(
            growth.normalize_brand(content, brand, slug, domain)))
        (base / rel).parent.mkdir(parents=True, exist_ok=True)
        (base / rel).write_text(content, encoding="utf-8")
        path = "/" + rel.removesuffix(".html")
        store.add_node(clone_id, path, content, "llm-morph", title=rel,
                       born_from="morph")
        store.add_ledger(clone_id, "morph", path, "llm-morph", "指挥模型变形生成")
        created.append(path)
    if created:
        events.broadcast("growth.node.created", clone_id, "-",
                         f"靶站变形：新增诱饵 {created} → clone:{clone_id}")
    return {"ok": True, "created": created}
