"""水印与 Canary Token：零宽字符水印编解码 + 回连 token 生成"""
import hashlib

ZW = {"0": "\u200b", "1": "\u200c"}
REV = {v: k for k, v in ZW.items()}


def session_marker(sid: str) -> str:
    """把 session_id 映射为 32 位零宽字符指纹（注入到响应内容中）"""
    bits = bin(int(hashlib.sha1(sid.encode()).hexdigest()[:8], 16))[2:].zfill(32)
    return "".join(ZW[b] for b in bits)


def decode_marker(marker: str, candidate_sids) -> str | None:
    """给定泄露文本中的零宽串与候选会话，反查来源会话"""
    by_marker = {session_marker(s): s for s in candidate_sids}
    return by_marker.get(marker)


def mint_token_id(sid: str, asset: str) -> str:
    return hashlib.sha1(f"{sid}|{asset}".encode()).hexdigest()[:12]


def canary_url(sid: str, asset: str, callback_base: str) -> tuple[str, str]:
    """返回 (canary_url, token_id)——攻击者触碰即回连记录出口 IP"""
    tid = mint_token_id(sid, asset)
    return f"{callback_base.rstrip('/')}/t/{tid}", tid
