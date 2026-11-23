"""安全专项测试：出站 URL 策略（SSRF）+ 端口清理不越权"""
import os
import tempfile

os.environ.setdefault("HP_DB_PATH", os.path.join(tempfile.mkdtemp(), "test_sec.db"))

from honeypot import instances, urlguard  # noqa: E402


# --------------------------------------------------------------------------- #
# SSRF：URL 策略
# --------------------------------------------------------------------------- #
def test_urlguard_blocks_internal_targets():
    """回环/私网/链路本地/元数据/保留段/CGNAT 一律拒绝"""
    blocked = [
        "http://127.0.0.1:9000/api/overview",
        "http://localhost/admin",
        "http://10.0.0.5/internal",
        "http://192.168.1.1/router",
        "http://172.16.0.9/x",
        "http://169.254.169.254/latest/meta-data/",   # 云元数据
        "http://100.64.0.1/cgnat",                     # CGNAT：is_private 不覆盖
        "http://[::1]:8080/",
        "http://[::ffff:127.0.0.1]/",                 # IPv4 映射绕过
        "http://[fd00::1]/",
        "http://[fe80::1]/",
        "http://0.0.0.0/",
        "http://240.0.0.1/",
        "file:///etc/passwd",
        "gopher://127.0.0.1:11211/",
    ]
    for u in blocked:
        try:
            urlguard.check_url(u)
        except urlguard.UrlNotAllowed:
            continue
        raise AssertionError(f"应被拒绝但放行了：{u}")


def test_urlguard_allows_public_and_allowlist(monkeypatch):
    """公网地址放行；白名单主机即使指向内网也放行（运维登记的自有资产）"""
    monkeypatch.setattr(urlguard, "resolve_host", lambda host: ["93.184.216.34"])
    assert urlguard.check_url("https://example.com/x") == "https://example.com/x"
    monkeypatch.setattr(urlguard, "resolve_host", lambda host: ["127.0.0.1"])
    try:
        urlguard.check_url("https://intranet.corp/api")
        raise AssertionError("内网地址应被拒绝")
    except urlguard.UrlNotAllowed:
        pass
    assert urlguard.check_url("https://intranet.corp/api",
                              allowed_hosts={"intranet.corp"}) == "https://intranet.corp/api"


def test_console_clone_api_rejects_ssrf(monkeypatch):
    """控制台克隆入口：指向内网的 source_url 直接被拒，不启动后台任务"""
    from fastapi.testclient import TestClient
    from honeypot.app_console import app as console_app
    c = TestClient(console_app)
    started = []
    monkeypatch.setattr("honeypot.clone_runner.start",
                        lambda *a, **k: started.append(a) or "x")
    r = c.post("/api/clones", json={"source_url": "http://127.0.0.1:9000/api/overview"})
    assert "error" in r.json()
    assert not started


# --------------------------------------------------------------------------- #
# 端口清理：不越权
# --------------------------------------------------------------------------- #
def _fake_subprocess(monkeypatch, netstat, cmdlines, killed):
    """替换 instances.subprocess.run：按 argv 分派返回"""
    real_run = instances.subprocess.run

    class R:
        def __init__(self, stdout=""):
            self.stdout = stdout
            self.stderr = ""
            self.returncode = 0

    def fake_run(cmd, *a, **kw):
        argv = list(cmd)
        if argv[0] == "netstat":
            return R(netstat)
        if argv[0] == "powershell":
            return R(cmdlines)
        if argv[0] == "taskkill":
            killed.append(argv[-1])
            return R("")
        return real_run(cmd, *a, **kw)

    monkeypatch.setattr(instances.subprocess, "run", fake_run)


def test_kill_port_only_kills_own_instance(monkeypatch):
    """端口被外部进程占用 → 只报冲突，绝不动手杀；本项目实例进程才清理"""
    inst = instances.config.DATA_DIR / "instances" / "site123"
    netstat = ("  TCP    127.0.0.1:8901          0.0.0.0:0              LISTENING       4321\n"
               "  TCP    127.0.0.1:8902          0.0.0.0:0              LISTENING       4322\n")
    cmdlines = ("4321|C:\\python.exe C:\\other\\nginx.exe -c nginx.conf\n"
                f"4322|C:\\python.exe -u {inst}\\backend\\app.py\n")
    killed = []
    _fake_subprocess(monkeypatch, netstat, cmdlines, killed)
    monkeypatch.setattr(instances, "instance_dir", lambda sid: inst)
    foreign = instances._kill_port(8901, "site123")
    assert killed == []                      # 4321 是外部进程 → 未被杀
    assert foreign == ["4321"]              # 已如实上报
    foreign2 = instances._kill_port(8902, "site123")
    assert killed == ["4322"]               # 4322 属于本实例 → 被清理
    assert foreign2 == []
