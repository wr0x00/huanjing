"""出站 URL 策略（SSRF 防护）

克隆源站与运行时回源都会按用户提供的 URL 发起请求，若不设防，
攻击者/误配置可借道把蜜罐主机变成内网跳板（访问 127.0.0.1、云元数据
169.254.169.254、内网服务，甚至回环里的其它管理端口）。

规则（对每一次请求生效，含重定向的每一跳）：
  1. 仅允许 http/https
  2. 主机名不得是本机/元数据服务的常见别名
  3. 主机名解析出的**每一个** IP 都必须是公网可路由地址：
     拒绝回环、私网、链路本地、保留、组播、未指定、CGNAT(100.64/10)、
     以及 IPv4 映射的 IPv6（::ffff:127.0.0.1 这类绕过）
  4. 每次请求（含重定向、每次 DNS 重新解析）都重新校验 —— 不缓存放行结论

豁免：config.ALLOWED_OUTBOUND_HOSTS 里的主机（运维显式登记的自有资产）。
"""
import ipaddress
import socket
from urllib.parse import urlsplit

from . import config

ALLOWED_SCHEMES = ("http", "https")

# 常见本机 / 云元数据别名（DNS 解析前先按名拒绝，防止解析器被劫持）
_BLOCKED_HOSTS = {
    "localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback",
    "metadata", "metadata.google.internal", "metadata.goog",
    "instance-data", "instance-data.ec2.internal",
}

# CGNAT 共享地址段：Python 的 is_private 不覆盖，必须单独判定
_CGNAT_V4 = ipaddress.ip_network("100.64.0.0/10")
# IETF 协议保留段（192.0.0.0/24 等）
_RESERVED_V4 = [
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("198.18.0.0/15"),
]


class UrlNotAllowed(Exception):
    """出站 URL 被策略拒绝"""


def _ip_disallowed(ip: ipaddress._BaseAddress) -> bool:
    """该 IP 是否禁止出站访问"""
    if isinstance(ip, ipaddress.IPv6Address):
        mapped = ip.ipv4_mapped
        if mapped is not None:      # ::ffff:127.0.0.1 → 按 IPv4 判定
            ip = mapped
        elif ip.sixtofour:
            ip = ip.sixtofour
    if ip.is_loopback or ip.is_private or ip.is_link_local:
        return True
    if ip.is_reserved or ip.is_multicast or ip.is_unspecified:
        return True
    if not ip.is_global:            # 覆盖 CGNAT 等 Python 未归入 private 的段
        return True
    if ip.version == 4:
        if ip in _CGNAT_V4:
            return True
        if any(ip in net for net in _RESERVED_V4):
            return True
    return False


def resolve_host(host: str) -> list[str]:
    """解析主机名 → 全部 IP 字符串（任一解析失败即整体失败）"""
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        raise UrlNotAllowed(f"域名解析失败：{host}（{e.strerror or e}）") from e
    return list(dict.fromkeys(info[4][0] for info in infos))


def check_url(url: str, allowed_hosts: set[str] | None = None) -> str:
    """校验出站 URL；通过返回原 URL，否则抛 UrlNotAllowed"""
    parts = urlsplit(url)
    if parts.scheme not in ALLOWED_SCHEMES:
        raise UrlNotAllowed(f"仅允许 http/https：{url}")
    host = (parts.hostname or "").strip().lower()
    if not host:
        raise UrlNotAllowed(f"URL 缺少主机名：{url}")
    allow = allowed_hosts if allowed_hosts is not None else set(config.ALLOWED_OUTBOUND_HOSTS)
    if host in allow:
        return url
    if host in _BLOCKED_HOSTS:
        raise UrlNotAllowed(f"禁止访问内网/元数据主机名：{host}")
    for raw in resolve_host(host):
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError:
            raise UrlNotAllowed(f"无法解析的地址：{raw}") from None
        if _ip_disallowed(ip):
            raise UrlNotAllowed(f"目标 {ip} 属于内网/保留地址，禁止访问（{host}）")
    return url


def guard_hook(allowed_hosts: set[str] | None = None):
    """httpx 请求钩子：每次请求（含重定向每一跳）都重新校验目标地址。

    httpx 在 follow_redirects 模式下，每一跳都会触发 request 事件钩子，
    因此重定向到内网、乃至 DNS 重绑定（每次重解析）都会被拦下。
    """
    async def _hook(request):
        # DNS 解析是阻塞调用，放线程池避免卡住事件循环
        import asyncio
        await asyncio.to_thread(check_url, str(request.url), allowed_hosts)
    return _hook
