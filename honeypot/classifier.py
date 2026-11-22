"""请求分类器：三级分类（规则签名 → 意图分级），热路径零 LLM 开销"""
SCANNER_UAS = [
    "sqlmap", "nikto", "nmap", "masscan", "gobuster", "dirbuster", "dirsearch",
    "wfuzz", "ffuf", "nuclei", "zgrab", "acunetix", "nessus", "whatweb", "wpscan",
]
SCANNER_PATH_HINTS = [
    ".git", "wp-admin", "wp-login", "wp-content", "phpmyadmin", "xmlrpc.php",
    "actuator", ".svn", "cgi-bin", "/etc/passwd", "phpinfo", "admin.php",
]


def classify(ua: str, path: str) -> dict:
    """返回 {level: noise|probe|human, tool: str}
    noise  = 批量扫描器泛洪（泛化 404，不生长）
    probe  = 定向文件/目录探测（触发小生长）
    human  = 拟人交互（走 LLM 长尾）
    """
    ua_low = (ua or "").lower()
    for tool in SCANNER_UAS:
        if tool in ua_low:
            return {"level": "noise", "tool": tool}
    # 常见客户端工具族（弱信号，仅影响展示，不影响生长决策）
    for mark, tool in (("curl/", "curl"), ("python-urllib", "python-urllib"),
                       ("python-requests", "python-requests"), ("wget", "wget"),
                       ("go-http-client", "go-http"), ("okhttp", "java-http")):
        if mark in ua_low:
            return {"level": "human", "tool": tool}
    if not ua_low:
        return {"level": "human", "tool": "no-ua"}
    p = path.lower()
    for hint in SCANNER_PATH_HINTS:
        if hint in p:
            return {"level": "probe", "tool": "path_scanner"}
    return {"level": "human", "tool": "browser"}
