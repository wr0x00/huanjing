"""生长引擎：未命中请求 → 生长决策 → LLM 页面工厂（无模型时离线模板降级）→ 固化 SiteGraph"""
import html as html_mod
import json
import re

from . import config, events, llm_gateway, store, watermark


def grow_prompt_system(persona: str, brand: str, slug: str, domain: str) -> str:
    """生长提示词：绑定该站点人设与品牌口径（各克隆站人设不同，不能写死全局默认）"""
    return (
        "你是蜜罐站点生长器，为一家虚构公司生成完全虚构的网页片段。"
        f"公司人设：{persona}。"
        "铁律：1) 只能输出虚构数据与虚构业务内容；2) 禁止输出真实可利用的漏洞代码或真实个人信息；"
        "3) 页面要看起来真实可信、业务逻辑自洽；4) 只输出 JSON；"
        "5) HTML 中嵌入 JSON 一律使用原始字符（如 {\"a\": 1}），"
        "严禁使用 &quot; &amp; 等 HTML 实体；<script type=\"application/json\"> 内必须是纯 JSON。"
        f"6) 品牌唯一：公司名/产品名/平台名只能使用「{brand}」，"
        f"域名只能用 {domain}，技术标识（库名/表名/路径）只能用 {slug}；"
        "不得出现任何其他公司名、品牌名或真实域名。"
    )


def brand_of_persona(persona: str) -> tuple[str, str, str]:
    """由站点人设推导品牌三元组（中文名 / 英文标识 / 域名）

    人设形如"星澜科技：一家中型电商 SaaS 公司"，取冒号前的公司名作为品牌中文名。
    """
    brand, slug, domain = config.BRAND, config.BRAND_SLUG, config.BRAND_DOMAIN
    name = str(persona or "").strip().split("：")[0].split(":")[0].strip()
    if name:
        brand = name
    return brand, slug, domain


def brand_of_clone(clone_id: str) -> tuple[str, str, str]:
    """取该克隆站点的人设品牌三元组（中文名 / 英文标识 / 域名）

    各克隆站有各自人设（如"星澜科技：一家中型电商 SaaS 公司"），
    品牌归一必须收敛到"该站点的人设"，而不是全局默认，否则同一套蜜点会串味。
    """
    try:
        clone = store.get_clone(clone_id) if clone_id else None
    except Exception:
        clone = None
    return brand_of_persona((clone or {}).get("persona") or "")


# 残留虚构品牌别名（来自历史生长/克隆数据的实测统计）。
# 蜜罐最怕自曝身份：页面上同时露出澄屿、栖云、星澜等互不相干的公司名，
# 攻击者一眼就知道是拼装的假站 —— 落库前统一收敛到站点人设。
_BRAND_CN_ALIASES = (
    "星澜", "星桥", "澄屿", "澄序", "澄川", "栖云", "栖川",
    "岚序", "岚屿", "岚桥", "青岚", "霁川", "昀川", "远屿", "远岚",
    "澜图", "澜屿", "澜川", "砚洲", "弧川", "云汀", "砺川", "蜂巢",
)
_BRAND_EN_ALIASES = (
    "starlane", "starlan", "orbitcart", "lumengrid", "northstar", "ncc",
)
# 别名替换后可能与品牌名叠字（"星澜科技" → "默认仿冒模板科技"），按尾缀收敛
_BRAND_TAILS = ("科技", "公司", "集团", "股份", "电商云", "云服务")
# 品牌衍生的商业域名统一用（starlane-commerce.cn → saas.example）
_DOMAIN_SUFFIX = (r"\.(?:com|cn|net|org|io|co|top|xyz|cc|info|biz|example|"
                  r"test|local|dev|app)\b")


def _replace_en(text: str, alias: str, slug: str) -> str:
    """英文品牌替换时保留原有大小写风格（STARLAN→SAAS，Starlan→Saas）"""
    def repl(m: re.Match) -> str:
        s = m.group(0)
        if s.isupper():
            return slug.upper()
        if s[:1].isupper():
            return slug.capitalize()
        return slug
    return re.sub(re.escape(alias), repl, text, flags=re.I)


def normalize_brand(text: str, brand: str | None = None, slug: str | None = None,
                    domain: str | None = None) -> str:
    """把文本里的各路虚构品牌收敛到站点人设（中文名 / 英文标识 / 域名统一）"""
    if not text:
        return text
    brand = brand or config.BRAND
    slug = slug or config.BRAND_SLUG
    domain = domain or config.BRAND_DOMAIN
    if not brand:
        return text

    for alias in _BRAND_CN_ALIASES:
        if alias in text:
            text = text.replace(alias, brand)
    for alias in _BRAND_EN_ALIASES:
        if alias.lower() in text.lower():
            text = _replace_en(text, alias, slug)
    for tail in _BRAND_TAILS:
        text = text.replace(brand + tail, brand)
    text = text.replace(brand + brand, brand)
    if slug and domain:
        # 品牌衍生的商业域名统一到人设域名（saas-commerce.cn → saas.example）
        text = re.sub(r"\b" + re.escape(slug) + r"[a-z0-9-]*" + _DOMAIN_SUFFIX,
                      domain, text, flags=re.I)
    return text


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
    (re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+"), f"contact@{config.BRAND_DOMAIN}"),
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
    brand, slug, domain = brand_of_clone(clone_id)
    persona = str((store.get_clone(clone_id) or {}).get("persona") or config.PERSONA)
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
        [{"role": "system", "content": grow_prompt_system(persona, brand, slug, domain)},
         {"role": "user", "content": user_prompt}],
        task="blueprint", json_mode=True, max_tokens=32000, timeout=150)

    page = _parse_llm_json(content) if content else None
    generated_by = f"llm:{provider}" if page else "template"
    if not page:
        page = _fallback_page(path)

    # 品牌归一后再落库：LLM 常自带一个"看起来像真的"公司名，
    # 多套品牌并存会让攻击者一眼识破是拼装站
    html = normalize_html(dlp_scan(normalize_brand(page["html"], brand, slug, domain)))
    title = normalize_brand(str(page.get("title") or ""), brand, slug, domain)
    store.add_node(clone_id, path, html, generated_by, title=title,
                   born_from=f"session:{sid}")
    store.add_ledger(clone_id, trigger=intent["level"], path=path,
                     generated_by=generated_by, note=f"session:{sid}")
    events.broadcast("growth.node.created", clone_id, sid,
                     f"站点生长：{path}（by {generated_by}）",
                     {"path": path, "generated_by": generated_by})
    return {"path": path, "title": title, "content": html}
