"""混合模型网关 v3（fuckai 同款实现）：Provider 全部存 DB（控制台可增删改），任务经「指挥模型优先」路由。

对齐 sec-tools/fuckai/fuckai/client.py 的 ChatClient 语义：
  * 统一 OpenAI 兼容协议 POST {base_url}/chat/completions
  * Authorization: Bearer 无条件发送（key 为空也发，保持与 fuckai 一致）
  * max_tokens=None 表示不限制输出长度 → 请求体省略该字段
  * 正文为空时兜底取 reasoning_content（思考模型额度被思考过程吃光的场景）
  * SSE 流式按行读取（httpx aiter_lines），上游忽略 stream 直接回整段 JSON 时降级解析
  * ping 用 "Reply with exactly: PONG" + temperature=0

所有模块不直连厂商，一律经 chat() 调用；无任何可用模型时返回 None，由调用方降级模板。
"""
import asyncio
import json
import sys
import time

import httpx

from . import config, store


def _log(*a):
    print("[llm-gateway]", *a, file=sys.stderr, flush=True)


# --------------------------------------------------------------------------- #
# ChatClient：fuckai 同款（异步 httpx 版）
# --------------------------------------------------------------------------- #
class ChatClient:
    """OpenAI 兼容 ChatClient。

    temperature 采样温度；timeout 单请求超时秒数；
    max_tokens=None 表示不限制输出长度（请求体省略该字段，由模型/服务端决定）。
    """

    def __init__(self, base_url: str, api_key: str, model: str,
                 temperature: float = 0.0, timeout: int = 120,
                 max_tokens: int | None = 1024):
        self.base_url = (base_url or "").rstrip("/")
        self.api_key = api_key or ""
        self.model = model or ""
        self.temperature = temperature
        self.timeout = timeout
        self.max_tokens = max_tokens

    # ---- 内部：构造请求 ----
    def _payload(self, messages, temperature=None, stream=False,
                 json_mode=False) -> dict:
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature if temperature is None else temperature,
        }
        # max_tokens=None → 不限制输出长度：直接省略字段，避免思考模型额度被 reasoning 吃光
        if self.max_tokens is not None:
            payload["max_tokens"] = self.max_tokens
        if json_mode:
            payload["response_format"] = {"type": "json_object"}
        if stream:
            payload["stream"] = True
        return payload

    def _headers(self, stream=False) -> dict:
        # 与 fuckai 一致：Authorization 无条件发送，即便 key 为空
        h = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }
        if stream:
            h["Accept"] = "text/event-stream"
        return h

    def _url(self) -> str:
        if not self.base_url or not self.model:
            raise RuntimeError("模型端点未配置：请先在模型网关中填写 Endpoint 与模型名")
        return f"{self.base_url}/chat/completions"

    # ---- 非流式 ----
    async def chat(self, messages, temperature=None, json_mode=False) -> str:
        payload = self._payload(messages, temperature, json_mode=json_mode)
        url = self._url()
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                r = await client.post(url, json=payload, headers=self._headers())
                if r.status_code >= 400:
                    body = r.text[:300]
                    raise RuntimeError(f"HTTP {r.status_code} 调用失败: {body}")
                data = r.json()
        except httpx.HTTPError as e:
            raise RuntimeError(f"连接失败 ({self.base_url}): {e}") from e
        except (ValueError, json.JSONDecodeError) as e:
            raise RuntimeError(f"响应解析失败: {e}") from e

        choices = data.get("choices") or []
        if not choices:
            raise RuntimeError(f"上游未返回 choices: {json.dumps(data, ensure_ascii=False)[:200]}")
        msg = choices[0].get("message") or {}
        text = msg.get("content")
        # 思考模型把额度耗在思考上，正文为空时兜底取思考内容
        if not text:
            text = msg.get("reasoning_content") or ""
        return text or ""

    # ---- 流式 ----
    async def chat_stream(self, messages, temperature=None, json_mode=False):
        """逐段产出 ('reasoning'|'content', text)。"""
        payload = self._payload(messages, temperature, json_mode=json_mode, stream=True)
        url = self._url()
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(self.timeout, read=self.timeout)) as client:
                async with client.stream("POST", url, json=payload,
                                        headers=self._headers(stream=True)) as resp:
                    if resp.status_code >= 400:
                        body = (await resp.aread()).decode("utf-8", errors="replace")[:300]
                        raise RuntimeError(f"HTTP {resp.status_code} 调用失败: {body}")
                    ctype = resp.headers.get("Content-Type", "")
                    # 部分网关/后端会忽略 stream 参数直接回 JSON，需兼容
                    if "text/event-stream" not in ctype:
                        raw = (await resp.aread()).decode("utf-8", errors="replace")
                        try:
                            data = json.loads(raw)
                        except Exception:
                            raise RuntimeError(f"上游返回非 SSE 且无法解析 JSON: {raw[:200]}")
                        base_resp = data.get("base_resp") or {}
                        if base_resp.get("status_code") not in (0, None):
                            raise RuntimeError(
                                f"上游返回错误: {base_resp.get('status_msg') or base_resp}")
                        choices = data.get("choices") or []
                        if choices:
                            msg = choices[0].get("message") or {}
                            think = msg.get("reasoning_content")
                            if think:
                                yield ("reasoning", think)
                            text = msg.get("content") or ""
                            if text:
                                yield ("content", text)
                        return
                    # 按行读取：一次性 read() 会在缓冲区攒满才返回，导致流式变成整段输出
                    finished = False
                    async for line in resp.aiter_lines():
                        if finished:
                            continue
                        line = (line or "").strip()
                        if not line.startswith("data:"):
                            continue
                        data = line[5:].strip()
                        if data == "[DONE]":
                            # 标记结束但继续把剩余数据读完：直接 break 会强断上游连接，
                            # 浏览器侧表现为 fetch 报 ERR_ABORTED
                            finished = True
                            continue
                        try:
                            obj = json.loads(data)
                        except ValueError:
                            continue
                        choices = obj.get("choices") or []
                        if not choices:
                            continue
                        delta = choices[0].get("delta") or {}
                        think = delta.get("reasoning_content")
                        if think:
                            yield ("reasoning", think)
                        text = delta.get("content")
                        if text:
                            yield ("content", text)
        except httpx.HTTPError as e:
            raise RuntimeError(f"连接失败 ({self.base_url}): {e}") from e

    # ---- 探活 ----
    async def ping(self) -> str:
        return await self.chat([{"role": "user", "content": "Reply with exactly: PONG"}],
                               temperature=0.0)


def client_of(provider: dict, temperature: float | None = None,
               timeout: int = 120, max_tokens: int | None = None) -> ChatClient:
    """由 Provider 行构造 ChatClient（max_tokens 默认不限制输出长度）。"""
    temp = provider.get("temperature")
    if temperature is None:
        temperature = 0.7 if temp is None else float(temp)
    return ChatClient(
        provider.get("endpoint") or "",
        provider.get("key") or "",
        provider.get("model") or "",
        temperature=float(temperature),
        timeout=timeout,
        max_tokens=max_tokens,
    )


# --------------------------------------------------------------------------- #
# Provider 路由
# --------------------------------------------------------------------------- #
def _providers() -> list[dict]:
    """DB 中全部启用的 Provider，指挥模型排最前"""
    rows = store.list_providers()
    commander = store.get_setting("commander_provider_id")
    rows.sort(key=lambda r: (r["id"] != commander, ))
    return rows


def commander() -> dict | None:
    cid = store.get_setting("commander_provider_id")
    if not cid:
        return None
    p = store.get_provider(cid)
    return p if p and p["enabled"] else None


def provider_status() -> list[dict]:
    cid = store.get_setting("commander_provider_id")
    return [{
        "id": p["id"], "name": p["name"], "base_url": p["endpoint"], "model": p["model"],
        "temperature": p.get("temperature", 0.7),
        "configured": bool(p["key"]) or p["endpoint"].startswith("http://127."),
        "enabled": bool(p["enabled"]),
        "commander": p["id"] == cid,
    } for p in store.list_providers()]


async def _call(provider: dict, messages, json_mode: bool, max_tokens: int | None,
                timeout: int = 45) -> str:
    """单次调用（保留旧签名语义）。"""
    cli = client_of(provider, timeout=timeout, max_tokens=max_tokens)
    return await cli.chat(messages, json_mode=json_mode)


async def _chat_once(cli: ChatClient, messages, json_mode: bool, on_chunk) -> str:
    """单次调用。on_chunk 提供时走流式聚合：每个片段实时回调（让 UI 看到 LLM 正在产出），
    同时拼成完整文本返回；流式失败/空回复时自动回退非流式。"""
    if on_chunk is None:
        return await cli.chat(messages, json_mode=json_mode)
    parts: list[str] = []
    try:
        async for kind, text in cli.chat_stream(messages, json_mode=json_mode):
            parts.append(text)
            try:
                on_chunk(text, kind)
            except Exception:
                pass  # 回调绝不影响生成
    except Exception:
        if parts:
            return "".join(parts)
        raise
    full = "".join(parts)
    if full.strip():
        return full
    return await cli.chat(messages, json_mode=json_mode)


async def chat(messages, task: str = "answer", json_mode: bool = False,
               max_tokens: int | None = 3000, timeout: int = 60,
               on_chunk=None) -> tuple[str | None, str | None]:
    """指挥模型优先，其余启用 Provider 依次降级；每个 Provider 重试 3 次（网关 500/截断常为瞬时故障），
    重试间加 1.5s 退避。全部失败返回 (None, None)，由调用方离线降级模板。
    每次尝试用 asyncio.wait_for 硬超时：慢滴字节会不断刷新 httpx 的 read 超时，
    不加总熔断时单次调用可能无限挂起（BUILDING 卡死的根因）。
    on_chunk(chunk_text, kind)：实时拿到 LLM 流式片段（kind ∈ reasoning/content）。"""
    for p in _providers():
        if not p["enabled"]:
            continue
        cli = client_of(p, timeout=timeout, max_tokens=max_tokens)
        for attempt in (1, 2, 3):
            try:
                content = await asyncio.wait_for(
                    _chat_once(cli, messages, json_mode, on_chunk), timeout=timeout)
                if (content or "").strip():
                    return content, p["name"]
                _log(f"{p['name']} 第{attempt}次空回复（reasoning 耗尽/截断），重试")
            except asyncio.TimeoutError:
                _log(f"{p['name']} 第{attempt}次硬超时（>{timeout}s），重试")
            except Exception as e:
                _log(f"{p['name']} 第{attempt}次异常: {type(e).__name__} {str(e)[:120]}")
            if attempt < 3:
                await asyncio.sleep(1.5)
    _log("全部 Provider 失败，交由调用方离线降级")
    return None, None


# --------------------------------------------------------------------------- #
# 连通性测试（fuckai 同款：ping + 重试 + 宽松超时）
# --------------------------------------------------------------------------- #
async def _ping_once(p: dict, timeout: int) -> str:
    cli = client_of(p, temperature=0.0, timeout=timeout, max_tokens=None)
    return await cli.ping()


async def test_provider(pid: str, retries: int = 3, timeout: int = 30) -> dict:
    """探活：fuckai 同款 ping 语义 + 重试（上游网关常有间歇性 500），超时放宽到 30s。"""
    p = store.get_provider(pid)
    if not p:
        return {"id": pid, "ok": False, "note": "Provider 不存在"}
    last = ""
    t0 = time.perf_counter()
    for attempt in range(1, max(1, retries) + 1):
        try:
            reply = await _ping_once(p, timeout)
            if (reply or "").strip():
                return {"id": pid, "name": p["name"], "ok": True,
                        "note": (reply or "").strip()[:60],
                        "elapsed_ms": int((time.perf_counter() - t0) * 1000),
                        "attempts": attempt}
            last = "空回复（模型异常或上游未返回内容）"
            _log(f"{p['name']} 第{attempt}次空回复，重试")
        except Exception as e:
            last = str(e)[:120]
            _log(f"{p['name']} 第{attempt}次探活异常: {type(e).__name__} {last}")
    return {"id": pid, "name": p["name"], "ok": False, "note": last or "连接失败",
            "elapsed_ms": int((time.perf_counter() - t0) * 1000),
            "attempts": max(1, retries)}


async def test_all() -> list[dict]:
    """控制台「测试全部连接」：并行探活（串行会让页面最长等 N×超时）"""
    import asyncio
    rows = store.list_providers()
    return list(await asyncio.gather(*(test_provider(p["id"]) for p in rows)))


def seed_from_env():
    """首次初始化：把 .env 里的三个出厂 Provider 迁入 DB（幂等）"""
    if store.list_providers():
        return
    for name, p in config.LLM_PROVIDERS.items():
        store.add_provider(name, p["base_url"], p["model"], p.get("key") or "")
    if not store.get_setting("commander_provider_id"):
        first = store.list_providers()
        if first:
            store.set_setting("commander_provider_id", first[0]["id"])
