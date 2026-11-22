"""靶站入口（攻击者视角，默认 8888，生产换域名+反代）：
按请求实际到达的端口解析站点绑定 → 挂载的蜜罐 clone → 拟真引擎主管线"""
from fastapi import FastAPI, Request
from starlette.responses import Response

from . import config, engine
from .common_routes import router as common_router

app = FastAPI(title="Honeypot Site Node", docs_url=None, redoc_url=None)
app.include_router(common_router)

_UNBOUND = """<!DOCTYPE html><html><head><meta charset="utf-8"><title>Site under maintenance</title></head>
<body style="font-family:sans-serif;text-align:center;padding-top:120px;color:#666">
<h2>站点维护中</h2><p>Site under scheduled maintenance</p><hr style="width:180px"><small>nginx</small></body></html>"""


@app.on_event("startup")
def startup():
    engine.init_runtime()


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "HEAD"])
async def honeypot_site(request: Request, path: str):
    """按本请求实际到达的端口解析绑定 → 挂载的蜜罐 clone → 主管线
    （一个 site 实例可同时服务任意多个端口绑定）"""
    server = request.scope.get("server") or ("?", config.SITE_PORT)
    port = server[1] if len(server) > 1 and isinstance(server[1], int) else config.SITE_PORT
    try:
        site = engine.store.get_site_by_port(port)
    except Exception:
        site = None
    if not site:
        return Response(_UNBOUND, status_code=503, media_type="text/html")
    return await engine.handle(request, path, site["clone_id"], site=site)
