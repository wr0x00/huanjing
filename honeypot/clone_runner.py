"""克隆任务运行器：任务注册 / 实时监控 / 暂停 / 对话式人工指挥

- start()        生成时间戳任务 ID，注册 asyncio.Task 后台跑 cloner._run
- pause()        cancel 协程（在任何 await 点立即中断，LLM 请求/socket 全部断开），
                  状态置「FAILED: 已暂停」，SSE 广播 clone.paused
- command()      用户在对话框发指令：广播 clone.user → 立即调度一次 LLM 回答
                  （流式经 clone.llm 推 SSE）；任务在跑时指令同时入队，
                  下一阶段（分析/生成/修正）提示词自动附加「用户附加指令」
- running_ids()  前端判断任务是否仍在跑
"""
import asyncio
import time

_tasks: dict[str, asyncio.Task] = {}
_cmds: dict[str, list[str]] = {}   # 任务运行中待注入下一阶段提示词的用户指令


async def _wrap(clone_id: str, source_url: str, persona: str):
    from . import cloner, events, store
    try:
        await cloner._run(source_url, persona, clone_id=clone_id)
    except asyncio.CancelledError:
        # 用户暂停：清理中间态，保证列表不残留 BUILDING 僵尸
        store.set_clone_status(clone_id, "FAILED: 已暂停（用户手动中止）")
        events.broadcast("clone.paused", clone_id, "-",
                         f"克隆任务 {clone_id} 已暂停：后台协程已终止，LLM 调用已断开")
    except Exception as e:
        store.set_clone_status(clone_id, f"FAILED: {str(e)[:120]}")
        events.broadcast("clone.FAILED", clone_id, "-", f"克隆异常：{str(e)[:120]}")
    finally:
        events.publish_flush("clone.llm", clone_id)
        _tasks.pop(clone_id, None)


async def start(source_url: str, persona: str) -> str:
    from . import cloner
    clone_id = time.strftime("%Y%m%d_%H%M%S")
    while clone_id in _tasks:  # 同秒撞名保护
        clone_id += "b"
    _tasks[clone_id] = asyncio.create_task(_wrap(clone_id, source_url, persona))
    return clone_id


def pause(clone_id: str) -> dict:
    t = _tasks.get(clone_id)
    if not t or t.done():
        return {"error": "任务不存在或已结束（仅运行中的任务可暂停）"}
    t.cancel()
    _tasks.pop(clone_id, None)
    return {"ok": True, "note": "后台协程已请求取消，状态将被置为已暂停"}


# --------------------------------------------------------------------------- #
# 对话式人工指挥：用户消息 → 即时 LLM 回答（流式直播）+ 运行中任务注入下一阶段
# --------------------------------------------------------------------------- #
def drain_cmds(clone_id: str) -> str:
    """cloner 在每个阶段构造提示词前调用：取走并清空待注入的用户指令"""
    lst = _cmds.pop(clone_id, [])
    return "\n".join(f"- {t}" for t in lst)


async def _instant_reply(clone_id: str, text: str, running: bool):
    """后台即时回应：把任务上下文 + 用户消息喂给 LLM，回复流式直播到对话框"""
    from . import events, llm_gateway, store
    try:
        status = ""
        for c in store.list_clones():
            if c["id"] == clone_id:
                status = c.get("status", "")
                break
        ctx = (f"你是蜜罐克隆任务的实时助手。任务 {clone_id} 当前状态：{status or '未知'}"
               f"（{'流水线运行中，指令将被注入下一阶段' if running else '任务已结束'}）。"
               f"用户指令：「{text}」。简明回答，若是指挥类诉求，说明将如何落实到后续阶段。")
        out, used = await llm_gateway.chat(
            [{"role": "user", "content": ctx}],
            task="answer", max_tokens=2048, timeout=120,
            on_chunk=lambda t, kind: events.publish("clone.llm", clone_id, t))
        events.publish_flush("clone.llm", clone_id)
        if not out:
            events.broadcast("clone.reply", clone_id, "-",
                             "（LLM 暂不可用，未能回应；指令已记录）")
    except asyncio.CancelledError:
        raise
    except Exception as e:
        events.broadcast("clone.reply", clone_id, "-", f"助手异常：{str(e)[:100]}")


def command(clone_id: str, text: str) -> dict:
    from . import events
    running = is_running(clone_id)
    # 用户消息先上屏（落库 + SSE）
    events.broadcast("clone.user", clone_id, "-", text)
    if running:
        _cmds.setdefault(clone_id, []).append(text)
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(_instant_reply(clone_id, text, running))
    except RuntimeError:
        asyncio.run(_instant_reply(clone_id, text, running))
    return {"ok": True, "running": running,
            "queued": running, "note": "指令已注入下一阶段" if running else "已即时回应"}


def is_running(clone_id: str) -> bool:
    t = _tasks.get(clone_id)
    return bool(t and not t.done())


def running_ids() -> list[str]:
    return [cid for cid, t in _tasks.items() if not t.done()]
