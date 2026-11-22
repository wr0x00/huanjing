"""一键启动 + 动态多靶站监听管理器：
  管理端   http://127.0.0.1:9000/console
  靶站     控制台「靶站管理」里挂载哪个端口，2 秒内自动在该端口拉起；
           模板带 backend/app.py 的靶站走「实例模式」（复制模板独立进程运行，数据隔离），
           其余走内置拟真引擎（SiteGraph 节点服务）。
           停用/删除靶站则自动停止对应监听/实例进程。
用法：.venv\\Scripts\\python run.py
"""
import threading
import time

import uvicorn

from honeypot import cloner, config, engine, instances, store
from honeypot.app_console import app as console_app
from honeypot.app_site import app as site_app

_servers: dict[int, uvicorn.Server] = {}
_lock = threading.Lock()
RESCAN_INTERVAL = 2  # 秒


def _ensure_listener(port: int):
    """拟真引擎模式：内置 SiteGraph 服务"""
    with _lock:
        if port in _servers:
            return
        server = uvicorn.Server(uvicorn.Config(
            site_app, host=config.SITE_HOST, port=port, log_level="warning"))
        threading.Thread(target=server.run, daemon=True).start()
        _servers[port] = server
        print(f"[+] 靶站监听已拉起: 0.0.0.0:{port}")


def _stop_listener(port: int):
    with _lock:
        server = _servers.pop(port, None)
    if server:
        server.should_exit = True
        print(f"[-] 靶站监听已停止: {port}")


def sync_listeners():
    """对齐 sites 表与当前监听/实例：
    启用 + 模板带后端 → 实例模式（instances.sync 独立进程，端口由实例进程绑定）；
    启用 + 无后端模板 → 拟真引擎监听；停用/删除 → 停止"""
    try:
        want = {int(s["port"]): s for s in store.list_sites() if s["enabled"]}
    except Exception:
        return
    cloner.fail_stale_clones()  # 僵尸克隆任务清扫（卡 BUILDING 等 → 超时失败）

    # 实例模式：模板带 backend/app.py 的站点（端口由独立进程绑定，不走 uvicorn _servers）
    instance_sites = [s for p, s in want.items() if s["clone_id"] and instances.has_backend(s["clone_id"])]
    instance_ports = {int(s["port"]) for s in instance_sites}
    instances.sync(instance_sites)

    # 拟真引擎模式：其余启用的端口
    for port in set(want) - instance_ports - set(_servers):
        _ensure_listener(port)
    for port in set(_servers) - (set(want) - instance_ports):
        _stop_listener(port)


def main():
    engine.init_runtime()
    sync_listeners()  # 启动时立即拉起已配置靶站/实例

    threading.Thread(
        target=lambda: uvicorn.run(console_app, host=config.CONSOLE_HOST,
                                   port=config.CONSOLE_PORT, log_level="warning"),
        daemon=True).start()
    print(f"[*] 管理端 : http://127.0.0.1:{config.CONSOLE_PORT}/console")
    print(f"[*] 靶站监听管理器每 {RESCAN_INTERVAL}s 与 sites 表同步（挂载即生效）")

    while True:
        time.sleep(RESCAN_INTERVAL)
        sync_listeners()


if __name__ == "__main__":
    main()
