"""生长引擎：未命中请求 → 生长决策 → LLM 页面工厂（无模型时离线模板降级）→ 固化 SiteGraph"""
import html as html_mod
import json
import re

from . import config, events, llm_gateway, store, watermark

GROW_PROMPT_SYSTEM = (
    "你是蜜罐站点生长器，为一家虚构公司生成完全虚构的网页片段。"
    f"公司人设：{config.PERSONA}。"
    "铁律：1) 只能输出虚构数据与虚构业务内容；2) 禁止输出真实可利用的漏洞代码或真实个人信息；"
    "3) 页面要看起来真实可信、业务逻辑自洽；4) 只输出 JSON；"
    "5) HTML 中嵌入 JSON 一律使用原始字符（如 {\"a\": 1}），"
    "严禁使用 &quot; &amp; 等 HTML 实体；<script type=\"application/json\"> 内必须是纯 JSON。"
)


def _wrap(title: str, body: str) -> str:
    return (f"<!DOCTYPE html><html lang='zh'><head><meta charset='utf-8'>"
            f"<title>{html_mod.escape(title)}</title></head><body>{body}</body></html>")


def _fallback_page(path: str) -> dict:
    """无 LLM 时的确定性降级模板：按路径关键词给拟真页面"""
    p = path.lower()
    if "admin" in p:
        body = (f"<h2>{html_mod.escape(config.PERSONA)} · 内部管理</h2><hr><ul>"
                "<li><a href='/admin/users'>用户列表</a></li>"
                "<li><a href='/admin/orders'>订单管理</a></li>"
                "<li><a href='/admin/db_dump'>数据备份（2023-12）</a></li></ul>"
                "<!-- old crm moved: /admin_old/users_bak -->")
        return {"title": "内部管理", "html": _wrap("内部管理", body)}
    if "search" in p:
        rows = "".join(f"<tr><td>商品{i}</td><td>¥{99 + i}.00</td><td>有货</td></tr>"
                       for i in range(1, 6))
        body = f"<h3>搜索结果</h3><table border='1'>{rows}</table>"
        return {"title": "搜索", "html": _wrap("搜索", body)}
    if "user" in p or "order" in p:
        rows = "".join(f"<tr><td>20231{i:03d}</td><td>张三{i}</td><td>¥{100 + i}.50</td></tr>"
                       for i in range(1, 9))
        body = f"<h3>业务数据</h3><table border='1'><tr><th>单号</th><th>客户</th><th>金额</th></tr>{rows}</table>"
        return {"title": "业务数据", "html": _wrap("业务数据", body)}
    body = (f"<h2>{html_mod.escape(config.PERSONA)}</h2><p>页面迁移中，旧入口见归档目录。</p>"
            f"<!-- archived: {path.rstrip('/')}/_bak -->")
    return {"title": "归档页", "html": _wrap("归档页", body)}


def _parse_llm_json(content: str) -> dict | None:
    try:
        text = re.sub(r"^```(json)?|```$", "", content.strip(), flags=re.M).strip()
        data = json.loads(text)
        if isinstance(data, dict) and data.get("html"):
            return data
    except Exception:
        pass
    return None


_DLP_PATTERNS = [
    (re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+"), "contact@starlan.example"),
    (re.compile(r"\b1[3-9]\d{9}\b"), "13800000000"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "10.0.0.1"),
]


def dlp_scan(text: str) -> str:
    """防真实数据泄漏：邮箱/手机号/IP 一律替换为虚构值（生长与克隆共用）"""
    for pat, repl in _DLP_PATTERNS:
        text = pat.sub(repl, text)
    return text


_SCRIPT_RE = re.compile(r"(<script\b[^>]*>)(.*?)(</script>)", re.S | re.I)


def normalize_html(text: str) -> str:
    """消除 LLM 产出页面里的 HTML 实体泄漏（{&quot; 的根因）：

    `<script>` 是 HTML 的原始文本区，浏览器不会解码其中的实体。LLM 常把 JSON
    写成 `{&quot;title&quot;: ...}` 放进 <script>，于是 JS 侧 JSON.parse(textContent)
    直接失败，卡片回退成把 `{&quot;...` 当普通文本显示。
    这里把 script 块内的实体还原成原始字符；同时对全页做一次双重转义收敛。
    """
    if not text or "&" not in text:
        return text

    def _fix_script(m: re.Match) -> str:
        head, body, tail = m.group(1), m.group(2), m.group(3)
        return head + html_mod.unescape(body) + tail if "&" in body else m.group(0)

    text = _SCRIPT_RE.sub(_fix_script, text)
    # &amp;quot; → &quot;（LLM 二次转义），浏览器随后在普通文本区正常解码
    return text.replace("&amp;quot;", "&quot;")


async def grow(clone_id: str, sid: str, path: str, intent: dict) -> dict | None:
    """返回 {"path","title","content"}；配额耗尽/不满足生长条件返回 None"""
    if store.quota_used_last_hour(clone_id) >= config.GROWTH_HOURLY_QUOTA:
        events.broadcast("growth.denied", clone_id, sid, f"生长配额耗尽，拒绝生长 {path}")
        return None

    digest = store.digest_nodes(clone_id)
    user_prompt = (
        f"攻击者正在探测路径：{path}（判定意图：{intent['level']}，工具特征：{intent['tool']}）。\n"
        f"会话行为画像：{json.dumps(intent.get('agent_profile') or {}, ensure_ascii=False)}。\n"
        "仅当画像标为强 Agent 行为链时，按已观测证据生成上下文连贯的下一层合成诱饵；"
        "不要把候选标记当作 Agent 确认，不提供可执行命令、真实凭据或外部目标。\n"
        f"当前站点已有结构：\n{digest}\n"
        "请生成该路径应返回的页面，要求与站点风格一致、数据虚构且自洽，"
        "可包含假后台入口、假数据列表、归档暗示等诱饵。"
        '输出 JSON：{"title": "...", "html": "<完整HTML片段>"}'
    )
    # reasoning 指挥模型思维链可耗数千 token，max_tokens 必须给足否则正文为空
    content, provider = await llm_gateway.chat(
        [{"role": "system", "content": GROW_PROMPT_SYSTEM},
         {"role": "user", "content": user_prompt}],
        task="blueprint", json_mode=True, max_tokens=32000, timeout=150)

    page = _parse_llm_json(content) if content else None
    generated_by = f"llm:{provider}" if page else "template"
    if not page:
        page = _fallback_page(path)

    html = normalize_html(dlp_scan(page["html"]))
    store.add_node(clone_id, path, html, generated_by, title=page.get("title", ""),
                   born_from=f"session:{sid}")
    store.add_ledger(clone_id, trigger=intent["level"], path=path,
                     generated_by=generated_by, note=f"session:{sid}")
    events.broadcast("growth.node.created", clone_id, sid,
                     f"站点生长：{path}（by {generated_by}）",
                     {"path": path, "generated_by": generated_by})
    return {"path": path, "title": page.get("title", ""), "content": html}
