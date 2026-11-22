"""SQLite 分库存储：按职责拆分为 5 个库
  site    站点信息：sites(靶站) / clones / nodes(SiteGraph)
  log     运行日志：events / packets(完整收发报文) / ledger(生长账本)
  session 会话画像：sessions（评分 / 状态 / WebRTC 溯源 IP）
  config  配置：traps / providers / settings
  asset   资产：tokens(Canary Token) 及其回连记录

同一模块内对外 API 不变，内部通过 SQL 里的表名自动路由到对应库。
"""
import atexit
import datetime
import json
import os
import re
import sqlite3
import threading
import time as _time
import uuid
import zlib
from pathlib import Path

from . import config

_init_lock = threading.RLock()
_initialized = False
# 每库一把锁：不同库的读写互不阻塞（旧版全局单锁会把所有库的 IO 串在一起）
_db_locks: dict[str, threading.RLock] = {}
_conns: dict[str, sqlite3.Connection] = {}


def _db_lock(db: str) -> threading.RLock:
    lock = _db_locks.get(db)
    if lock is None:
        lock = _db_locks[db] = threading.RLock()
    return lock


# ---------------- 热路径缓存与写合批 ----------------
# 请求路径上只碰内存，落库由后台线程每秒批量刷盘：
#   _sessions   会话行内存副本（消除每请求 3~4 次重复 SELECT/UPDATE）
#   _sess_dirty 待落库的会话 sid（绝对值写回 score/last_seen/state/tool）
#   _wq         延迟落库队列（events/packets/ledger/trap_hits 批量 executemany）
#   _traps      陷阱行内存副本（match_first 每请求免查库）
_sessions: dict[str, dict] = {}
_sess_dirty: set[str] = set()
_wq: list[tuple] = []
_wq_lock = threading.Lock()
_traps: dict[str, dict] = {}
_flusher_started = False

# 表 → 所属库
_TABLE_DB = {
    "sites": "site", "clones": "site", "nodes": "site",
    "events": "log", "packets": "log", "ledger": "log",
    "sessions": "session",
    "traps": "config", "providers": "config", "settings": "config",
    "chat_sessions": "config", "chat_messages": "config",
    "tokens": "asset",
}
_SQL_TABLE_RE = re.compile(
    r"\b(?:FROM|INTO|UPDATE|JOIN)\s+([A-Za-z_][A-Za-z0-9_]*)", re.I)

_DDL = {
    "site": """
        CREATE TABLE IF NOT EXISTS sites(
            id TEXT PRIMARY KEY, name TEXT, domain TEXT DEFAULT '',
            port INTEGER, clone_id TEXT, enabled INTEGER DEFAULT 1,
            created_at TEXT);
        CREATE TABLE IF NOT EXISTS clones(
            id TEXT PRIMARY KEY, source_url TEXT, persona TEXT,
            status TEXT, created_at TEXT);
        CREATE TABLE IF NOT EXISTS nodes(
            clone_id TEXT, path TEXT, title TEXT DEFAULT '',
            content TEXT, content_type TEXT DEFAULT 'text/html',
            generated_by TEXT, born_from TEXT DEFAULT '',
            value_score REAL DEFAULT 0, created_at TEXT,
            pruned INTEGER DEFAULT 0,
            PRIMARY KEY(clone_id, path));
    """,
    "log": """
        CREATE TABLE IF NOT EXISTS events(
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, type TEXT,
            clone_id TEXT, session_id TEXT, summary TEXT, detail TEXT);
        CREATE TABLE IF NOT EXISTS packets(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT, site_id TEXT, port INTEGER, clone_id TEXT, session_id TEXT,
            method TEXT, path TEXT, query TEXT,
            req_headers TEXT, req_body TEXT,
            status INTEGER, resp_headers TEXT, resp_body TEXT,
            has_cred INTEGER DEFAULT 0, packed INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS ledger(
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, clone_id TEXT,
            trigger TEXT, path TEXT, generated_by TEXT, note TEXT);
    """,
    "session": """
        CREATE TABLE IF NOT EXISTS sessions(
            id TEXT PRIMARY KEY, ip TEXT, ua TEXT, tool TEXT DEFAULT '',
            score REAL DEFAULT 0, state TEXT DEFAULT 'RECON',
            first_seen TEXT, last_seen TEXT,
            real_ip TEXT DEFAULT '', internal_ip TEXT DEFAULT '',
            agent_score INTEGER DEFAULT 0, agent_label TEXT DEFAULT '未判定',
            agent_signals TEXT DEFAULT '[]');
    """,
    "config": """
        CREATE TABLE IF NOT EXISTS traps(
            id TEXT PRIMARY KEY, name TEXT, match_json TEXT,
            respond_json TEXT, enabled INTEGER DEFAULT 1,
            hits INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS providers(
            id TEXT PRIMARY KEY, name TEXT, endpoint TEXT, model TEXT,
            key TEXT DEFAULT '', enabled INTEGER DEFAULT 1, created_at TEXT,
            temperature REAL DEFAULT 0.7);
        CREATE TABLE IF NOT EXISTS settings(
            key TEXT PRIMARY KEY, value TEXT);
        CREATE TABLE IF NOT EXISTS chat_sessions(
            id TEXT PRIMARY KEY, title TEXT, provider_id TEXT, model TEXT,
            temperature REAL DEFAULT 0.7, system_prompt TEXT DEFAULT '',
            history_mode TEXT DEFAULT 'compress', context_rounds INTEGER DEFAULT 6,
            history_chars INTEGER DEFAULT 300, max_tokens INTEGER DEFAULT 0,
            created_at TEXT, updated_at TEXT);
        CREATE TABLE IF NOT EXISTS chat_messages(
            id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT, role TEXT,
            content TEXT, thinking TEXT DEFAULT '', attachments TEXT DEFAULT '[]',
            ts TEXT);
    """,
    "asset": """
        CREATE TABLE IF NOT EXISTS tokens(
            token_id TEXT PRIMARY KEY, session_id TEXT, asset TEXT,
            created_at TEXT, callbacks TEXT DEFAULT '[]');
    """,
}

# 索引独立于建表：迁移老数据前先不建，迁完再一次性建（避免导入变慢）
_INDEXES = {
    "site": """
        CREATE INDEX IF NOT EXISTS idx_sites_port ON sites(port);
    """,
    "log": """
        CREATE INDEX IF NOT EXISTS idx_packets_ts ON packets(ts);
        CREATE INDEX IF NOT EXISTS idx_packets_site_ts ON packets(site_id, ts);
        CREATE INDEX IF NOT EXISTS idx_packets_session ON packets(session_id);
        CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
        CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
        CREATE INDEX IF NOT EXISTS idx_ledger_clone ON ledger(clone_id);
    """,
    "session": """
        CREATE INDEX IF NOT EXISTS idx_sessions_seen ON sessions(last_seen);
        CREATE INDEX IF NOT EXISTS idx_sessions_score ON sessions(score);
    """,
    "asset": """
        CREATE INDEX IF NOT EXISTS idx_tokens_session ON tokens(session_id);
    """,
}

# 旧单库 → 新分库 的表映射
_MIGRATE_PLAN = {
    "site": ["sites", "clones", "nodes"],
    "log": ["events", "packets", "ledger"],
    "session": ["sessions"],
    "config": ["traps", "providers", "settings"],
    "asset": ["tokens"],
}


def _now() -> str:
    return datetime.datetime.now().isoformat(timespec="seconds")


# ---------- 报文正文压缩存储 ----------
# 完整报文占了日志库 95% 体积，zlib 后约剩 30%。四个字段整行统一压缩：
# 要么全是明文 TEXT（小报文，SQL 友好），要么全是 zlib BLOB（大报文，省磁盘）。
_PACK_FIELDS = ("req_headers", "req_body", "resp_headers", "resp_body")
_MIN_COMPRESS = 256  # 小于该总长不压缩，直接存明文


def _decompress(v) -> str:
    """BLOB → 明文；解压失败按原样字节解码兜底（不丢数据）"""
    try:
        return zlib.decompress(bytes(v)).decode("utf-8", "replace")
    except Exception:
        return bytes(v).decode("utf-8", "replace")


def _as_text(v) -> str:
    """统一转成明文 str：None → 空串，bytes → 解压（或原样解码），str → 原样"""
    if v is None:
        return ""
    if isinstance(v, (bytes, bytearray)):
        return _decompress(v)
    return v


def _pack_row(*fields) -> tuple:
    """整行统一压缩四个正文字段：整行总长超阈值则四字段一律存 zlib BLOB。
    必须无条件走 zlib（即使压不小也存压缩流），否则读回时无法区分
    「压缩流」与「原始 bytes」，不可压缩内容会被误解压成空串。"""
    texts = [_as_text(f) for f in fields]
    if sum(len(t) for t in texts) < _MIN_COMPRESS:
        return tuple(texts)
    return tuple(zlib.compress(t.encode("utf-8"), 6) for t in texts)


def _unpack_rows(rows):
    """读取时把压缩字段还原成明文（旧明文行原样返回）"""
    for r in rows:
        for k in _PACK_FIELDS:
            v = r.get(k)
            if isinstance(v, (bytes, bytearray)):
                r[k] = _decompress(v)
    return rows


def _connect(db: str) -> sqlite3.Connection:
    """惰性建立分库连接；WAL + busy_timeout 支撑双入口并发读写"""
    conn = _conns.get(db)
    if conn is None:
        conn = sqlite3.connect(config.DB_PATHS[db], check_same_thread=False, timeout=15)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA busy_timeout=10000")
        _conns[db] = conn
    return conn


def _route(sql: str) -> str:
    """按 SQL 涉及的表名定位所属库"""
    names = {m.group(1).lower() for m in _SQL_TABLE_RE.finditer(sql)}
    dbs = {_TABLE_DB[n] for n in names if n in _TABLE_DB}
    if len(dbs) == 1:
        return dbs.pop()
    if not dbs:
        raise ValueError(f"无法确定目标数据库: {sql[:80]}")
    raise ValueError(f"跨库 SQL 需显式指定 db: {sql[:80]}")


def init_db():
    """幂等：双入口（靶站/控制台）lifespan 并发调用只建一次连接，消除 commit 竞态"""
    global _initialized
    with _init_lock:
        if _initialized:
            return
        for db, ddl in _DDL.items():
            conn = _connect(db)
            conn.executescript(ddl)
            conn.commit()
        # 增量迁移：WebRTC 真实 IP 溯源字段（老库幂等）
        for col in ("real_ip", "internal_ip"):
            try:
                _connect("session").execute(
                    f"ALTER TABLE sessions ADD COLUMN {col} TEXT DEFAULT ''")
            except Exception:
                pass  # 列已存在
        _connect("session").commit()
        # 增量迁移：报文压缩标记 + 凭据命中标记（老库幂等）
        for col, ddl in (("has_cred", "INTEGER DEFAULT 0"),
                         ("packed", "INTEGER DEFAULT 0")):
            try:
                _connect("log").execute(f"ALTER TABLE packets ADD COLUMN {col} {ddl}")
            except Exception:
                pass  # 列已存在
        _connect("log").commit()
        # 增量迁移：Provider 采样温度（老库幂等）
        try:
            _connect("config").execute(
                "ALTER TABLE providers ADD COLUMN temperature REAL DEFAULT 0.7")
        except Exception:
            pass  # 列已存在
        _connect("config").commit()
        for col, ddl in (("agent_score", "INTEGER DEFAULT 0"),
                         ("agent_label", "TEXT DEFAULT '未判定'"),
                         ("agent_signals", "TEXT DEFAULT '[]'")):
            try:
                _connect("session").execute(f"ALTER TABLE sessions ADD COLUMN {col} {ddl}")
            except Exception:
                pass  # 列已存在
        _connect("session").commit()
        _initialized = True
    # 老单库数据迁移（幂等，有标记）+ 索引补建
    migrate_legacy_db()
    pack_legacy_packets()
    ensure_indexes()
    _start_flusher()


def ensure_indexes():
    for db, ddl in _INDEXES.items():
        with _db_lock(db):
            conn = _connect(db)
            conn.executescript(ddl)
            conn.commit()


def q(sql: str, params=(), fetch: bool = False, db: str | None = None):
    """单条 SQL：读操作不进写事务（免 commit）；写操作完成后立即 commit。
    每库独立锁，锁内完成取行——把行转 dict 移到锁外由调用方承担。"""
    db = db or _route(sql)
    with _db_lock(db):
        conn = _connect(db)
        cur = conn.execute(sql, params)
        if fetch:
            return [dict(r) for r in cur.fetchall()]
        conn.commit()
        return cur


# ---------------- 写合批（后台 1s 批量刷盘） ----------------
def _enqueue(op: tuple):
    with _wq_lock:
        _wq.append(op)


def _flush_once():
    """把队列里的延迟写批量落库。单类合并成 executemany，一次 fsync 落全部。"""
    global _wq
    with _wq_lock:
        batch, _wq = _wq, []
    if not batch and not _sess_dirty:
        return
    events_rows, packet_rows, ledger_rows, trap_hits = [], [], [], {}
    for op in batch:
        kind = op[0]
        if kind == "event":
            events_rows.append(op[1])
        elif kind == "packet":
            packet_rows.append(op[1])
        elif kind == "ledger":
            ledger_rows.append(op[1])
        elif kind == "trap_hit":
            trap_hits[op[1]] = trap_hits.get(op[1], 0) + 1
    # 会话绝对值写回（缓存即真相源）
    with _init_lock:
        dirty = list(_sess_dirty)
        _sess_dirty.clear()
    sess_rows = []
    for sid in dirty:
        s = _sessions.get(sid)
        if s:
            sess_rows.append((_now(), s.get("score", 0), s.get("state", "RECON"),
                              s.get("tool", ""), int(s.get("agent_score", 0)),
                              s.get("agent_label", "未判定"),
                              json.dumps(s.get("agent_signals", []), ensure_ascii=False), sid))
    with _db_lock("log"):
        conn = _connect("log")
        if events_rows:
            conn.executemany("INSERT INTO events(ts,type,clone_id,session_id,summary,detail) "
                             "VALUES(?,?,?,?,?,?)", events_rows)
        if packet_rows:
            conn.executemany(
                "INSERT INTO packets(ts,site_id,port,clone_id,session_id,method,path,query,"
                "req_headers,req_body,status,resp_headers,resp_body,has_cred,packed) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,1)",
                [_pack_packet_row(r) for r in packet_rows])
        if ledger_rows:
            conn.executemany("INSERT INTO ledger(ts,clone_id,trigger,path,generated_by,note) "
                             "VALUES(?,?,?,?,?,?)", ledger_rows)
        conn.commit()
    if sess_rows:
        with _db_lock("session"):
            conn = _connect("session")
            conn.executemany("UPDATE sessions SET last_seen=?, score=?, state=?, tool=?, "
                             "agent_score=?, agent_label=?, agent_signals=? "
                             "WHERE id=?", sess_rows)
            conn.commit()
    if trap_hits:
        with _db_lock("config"):
            conn = _connect("config")
            conn.executemany("UPDATE traps SET hits=hits+? WHERE id=?",
                             [(n, tid) for tid, n in trap_hits.items()])
            conn.commit()


def _pack_packet_row(r: dict) -> tuple:
    """队列里的原始报文 → 压缩落库行（zlib CPU 开销移出请求路径）"""
    packed = _pack_row(r["req_headers"], r["req_body"], r["resp_headers"], r["resp_body"])
    cred = 1 if (r["req_body"] and "password" in r["req_body"].lower()) else 0
    return (r["ts"], r["site_id"], r["port"], r["clone_id"], r["session_id"],
            r["method"], r["path"], r["query"],
            packed[0], packed[1], r["status"], packed[2], packed[3], cred)


def _flush_loop():
    while True:
        _time.sleep(1.0)
        try:
            _flush_once()
        except Exception as e:
            print(f"[store] 写合批刷盘异常: {e}")


def _start_flusher():
    global _flusher_started
    with _init_lock:
        if _flusher_started:
            return
        _flusher_started = True
        threading.Thread(target=_flush_loop, daemon=True, name="store-flusher").start()
        atexit.register(_flush_once)  # 退出前尽力刷一次，减少尾部丢失


# ---------- 旧单库迁移（honeypot.db → 分库） ----------
def _copy_table(conn, old_schema: str, new_schema: str, table: str) -> int:
    old_cols = [r[1] for r in conn.execute(f"PRAGMA {old_schema}.table_info({table})")]
    if not old_cols:
        return 0
    new_cols = [r[1] for r in conn.execute(f"PRAGMA {new_schema}.table_info({table})")]
    common = [c for c in new_cols if c in set(old_cols)]
    if not common:
        return 0
    collist = ", ".join(common)
    cur = conn.execute(f"INSERT OR REPLACE INTO {new_schema}.{table} ({collist}) "
                       f"SELECT {collist} FROM {old_schema}.{table}")
    return cur.rowcount


def migrate_legacy_db() -> dict:
    """把旧单库 honeypot.db 的数据搬进分库结构，幂等（标记存在则跳过）"""
    legacy = config.LEGACY_DB_PATH
    if not os.path.exists(legacy):
        return {"migrated": False, "reason": "无旧单库"}
    if get_setting("db_split_migrated_at"):
        return {"migrated": False, "reason": "已迁移"}
    moved: dict[str, int] = {}
    try:
        for db, tables in _MIGRATE_PLAN.items():
            conn = _connect(db)
            conn.commit()
            conn.execute("ATTACH DATABASE ? AS old", (legacy,))
            try:
                for t in tables:
                    n = _copy_table(conn, "old", "main", t)
                    if n:
                        moved[f"{db}.{t}"] = n
                conn.commit()
            finally:
                conn.execute("DETACH DATABASE old")
    except Exception as e:
        return {"migrated": False, "reason": f"迁移失败: {e}"}
    set_setting("db_split_migrated_at", _now())
    print(f"[store] 旧单库数据已迁入分库结构: {moved}；旧库 {legacy} 可自行删除")
    return {"migrated": True, "moved": moved}


# ---------- 历史明文报文改写为压缩存储（一次性） ----------
def _row_needs_repack(row) -> bool:
    """旧明文行（packed=0）或早期版本误存为原始 bytes 的行都需要重写"""
    if not row["packed"]:
        return True
    for k in _PACK_FIELDS:
        v = row[k]
        if isinstance(v, (bytes, bytearray)):
            try:
                zlib.decompress(bytes(v))
            except Exception:
                return True  # 不是合法 zlib 流（早期版本原样存 bytes）
    return False


def pack_legacy_packets() -> int:
    """把未压缩/格式不合法的报文改写为 zlib BLOB，并回填凭据命中标记；幂等（设置项标记）"""
    if get_setting("pack_legacy_done_at"):
        return 0
    with _db_lock("log"):
        conn = _connect("log")
        rows = conn.execute(
            "SELECT id, req_headers, req_body, resp_headers, resp_body, packed "
            "FROM packets").fetchall()
        n = 0
        for r in rows:
            if not _row_needs_repack(r):
                continue
            body = _as_text(r["req_body"])
            packed = _pack_row(r["req_headers"], body, r["resp_headers"], r["resp_body"])
            cred = 1 if (body and "password" in body.lower()) else 0
            conn.execute(
                "UPDATE packets SET req_headers=?, req_body=?, resp_headers=?, "
                "resp_body=?, has_cred=?, packed=1 WHERE id=?",
                (packed[0], packed[1], packed[2], packed[3], cred, r["id"]))
            n += 1
        conn.commit()
    set_setting("pack_legacy_done_at", _now())
    if n:
        vacuum_logs()
        print(f"[store] 历史报文已改写为压缩存储: {n} 条")
    return n


# ---------- sites（靶站入口：域名/端口 → 挂载的蜜罐 clone） ----------
def add_site(name: str, port: int, clone_id: str, domain: str = "",
             enabled: bool = True) -> str:
    sid = uuid.uuid4().hex[:8]
    q("INSERT INTO sites VALUES(?,?,?,?,?,?,?)",
      (sid, name, domain, port, clone_id, 1 if enabled else 0, _now()))
    return sid


def list_sites():
    return q("SELECT * FROM sites ORDER BY created_at DESC", fetch=True)


def get_site_by_port(port: int):
    rows = q("SELECT * FROM sites WHERE port=? AND enabled=1", (port,), fetch=True)
    return rows[0] if rows else None


def update_site(site_id: str, **fields):
    allowed = ("name", "domain", "port", "clone_id", "enabled")
    sets, params = [], []
    for k, v in fields.items():
        if k in allowed and v is not None:
            sets.append(f"{k}=?")
            params.append(1 if (k == "enabled" and v is not None) else v)
    if not sets:
        return
    params.append(site_id)
    q(f"UPDATE sites SET {', '.join(sets)} WHERE id=?", tuple(params))


def delete_site(site_id: str):
    q("DELETE FROM sites WHERE id=?", (site_id,))


# ---------- clones ----------
def add_clone(cid: str, source_url: str, persona: str, status="CRAWLING"):
    q("INSERT OR REPLACE INTO clones VALUES(?,?,?,?,?)",
      (cid, source_url, persona, status, _now()))


def set_clone_status(cid: str, status: str):
    q("UPDATE clones SET status=? WHERE id=?", (status, cid))


def list_clones():
    return q("SELECT * FROM clones ORDER BY created_at DESC", fetch=True)


def get_clone(cid: str):
    rows = q("SELECT * FROM clones WHERE id=?", (cid,), fetch=True)
    return rows[0] if rows else None


# ---------- SiteGraph nodes ----------
def add_node(clone_id, path, content, generated_by, title="", born_from="",
             content_type="text/html"):
    q("INSERT OR REPLACE INTO nodes VALUES(?,?,?,?,?,?,?,?,?,0)",
      (clone_id, path, title, content, content_type, generated_by, born_from, 0, _now()))


def get_node(clone_id, path):
    rows = q("SELECT * FROM nodes WHERE clone_id=? AND path=? AND pruned=0",
             (clone_id, path), fetch=True)
    return rows[0] if rows else None


def list_nodes(clone_id):
    return q("SELECT path,title,generated_by,born_from,value_score,created_at,pruned,"
             "content_type,LENGTH(COALESCE(content,'')) AS size "
             "FROM nodes WHERE clone_id=? ORDER BY created_at ASC", (clone_id,), fetch=True)


def digest_nodes(clone_id) -> str:
    rows = list_nodes(clone_id)
    return "\n".join(f"- {r['path']} ({r['generated_by']})" for r in rows) or "- /（种子首页）"


def quota_used_last_hour(clone_id) -> int:
    cutoff = (datetime.datetime.now() - datetime.timedelta(hours=1)).isoformat(timespec="seconds")
    row = q("SELECT COUNT(*) c FROM nodes WHERE clone_id=? AND generated_by LIKE 'llm%' "
            "AND created_at>=?", (clone_id, cutoff), fetch=True)
    return row[0]["c"]


# ---------- sessions ----------
def get_or_create_session(sid, ip, ua, tool=""):
    """热路径全程内存：命中缓存 0 次 SQL；未命中查库一次；新会话插入一次。
    score/last_seen/state/tool 的后续变更走缓存，由写合批线程统一落库。"""
    s = _sessions.get(sid)
    if s:
        s.setdefault("agent_score", 0)
        s.setdefault("agent_label", "未判定")
        s.setdefault("agent_signals", [])
        s["last_seen"] = _now()
        if tool and not s.get("tool"):
            s["tool"] = tool
        _sess_dirty.add(sid)
        return s
    rows = q("SELECT * FROM sessions WHERE id=?", (sid,), fetch=True, db="session")
    if rows:
        s = rows[0]
        s["agent_score"] = int(s.get("agent_score") or 0)
        s["agent_label"] = s.get("agent_label") or "未判定"
        try:
            s["agent_signals"] = json.loads(s.get("agent_signals") or "[]")
        except (TypeError, json.JSONDecodeError):
            s["agent_signals"] = []
        if tool and not s.get("tool"):
            s["tool"] = tool
            _sess_dirty.add(sid)
        _sessions[sid] = s
        return s

    now = _now()
    q("INSERT INTO sessions(id,ip,ua,tool,score,state,first_seen,last_seen,"
      "real_ip,internal_ip,agent_score,agent_label,agent_signals) "
      "VALUES(?,?,?,?,?,?,?,?,?,'',0,'未判定','[]')",
      (sid, ip, ua, tool, 0, "RECON", now, now, ""), db="session")
    s = {"id": sid, "ip": ip, "ua": ua, "tool": tool, "score": 0, "state": "RECON",
         "first_seen": now, "last_seen": now, "real_ip": "", "internal_ip": "",
         "agent_score": 0, "agent_label": "未判定", "agent_signals": []}
    _sessions[sid] = s
    return s


def session_snapshot(sid) -> dict:
    """只读取会话（命中缓存 0 次 SQL）；不存在则返回空壳（不建会话）"""
    s = _sessions.get(sid)
    if s:
        return s
    rows = q("SELECT * FROM sessions WHERE id=?", (sid,), fetch=True, db="session")
    s = rows[0] if rows else {"id": sid, "ip": "", "ua": "", "tool": "", "score": 0,
                              "state": "RECON", "real_ip": "", "internal_ip": ""}
    if rows:
        _sessions[sid] = s
        s["agent_score"] = int(s.get("agent_score") or 0)
        s["agent_label"] = s.get("agent_label") or "未判定"
        try:
            s["agent_signals"] = json.loads(s.get("agent_signals") or "[]")
        except (TypeError, json.JSONDecodeError):
            s["agent_signals"] = []
    return s


# Agent 证据信号注册表：稳定键 → (权重, 中文说明)
# 稳定键保证历史回放幂等（同一证据反复命中不会重复计分）；
# 说明文本仅用于展示，可随时调整而不影响已落库证据。
AGENT_SIGNAL_REGISTRY = {
    # 陷阱侧语义证据
    "client_marker": (8, "客户端指纹诱饵被读取（探针式访问标记文件）"),
    "semantic_task_read": (12, "语义诱饵被读取（任务指令被提取）"),
    "result_api_probe": (5, "结果诱饵接口被探测"),
    "semantic_followthrough": (30, "按语义诱饵跟进执行（读懂后按要求回访）"),
    # 行为侧证据（agentdetect 产出）
    "ua_fake_browser": (8, "UA 伪装浏览器（自称 Mozilla 却无 sec-*/Accept-Language 浏览器专属头）"),
    "tool_non_browser": (4, "非浏览器客户端（curl/python 等，弱信号）"),
    "ua_task_mark": (12, "UA 内嵌任务标识（LLM worker 任务名痕迹）"),
    "ua_ioc_match": (10, "UA 命中已知 Agent 框架字符串线索（低置信度）"),
    "header_id_token": (6, "Header 线索 x-id-token（未验证候选，低置信度）"),
    "multi_family_parallel": (14, "同一来源 10 分钟内 ≥3 类工具族并行（多 worker 编排特征）"),
    "multi_session_parallel": (10, "同一来源短窗内多会话/多身份并行"),
    "multi_ua_per_worker": (16, "同一来源多会话使用多种不同 UA（每 worker 专属 UA，编排式 Agent 强特征）"),
    "burst_silence": (14, "突发-静默交替节奏（批请求后静默再换方向，Agent 推理间歇特征）"),
    "deny_variant_retry": (12, "被拒（401/403/404/429）后对同一目标改写路径变体重试"),
    "chain_recon_cred": (14, "行为链：侦察(robots/.git/备份/swagger)→凭据探测，阶段推进有序"),
    "chain_postauth": (14, "行为链：凭据探测后连续深入后台（结果驱动分支）"),
    "multi_surface": (10, "多攻击面切换（后台/API/备份/文档间按结果跳转）"),
    "path_diversity": (6, "大路径多样性（≥20 个不同路径的定向枚举）"),
    "burst_rate": (10, "一分钟窗口请求数超本地基线（突发扫描）"),
    "window_path_diversity": (8, "一分钟窗口内路径多样性超基线（枚举式爬取）"),
    "deny_target_spray": (12, "一分钟窗口内对多个目标集中喷洒（被拒后继续广撒）"),
    "multi_identity_parallel": (14, "同一凭据/令牌身份跨多个会话与工具族并行使用（多身份编排）"),
}


def signal_desc(signal: str) -> str:
    """稳定键 → 中文说明（兼容旧的自由文本信号）"""
    item = AGENT_SIGNAL_REGISTRY.get(signal)
    return item[1] if item else signal


def agent_label_for(score: int) -> str:
    """分层置信度标签：0 → 未判定；>0 候选线索；≥20 疑似 Agent；≥40 强 Agent 行为链"""
    score = int(score or 0)
    if score <= 0:
        return "未判定"
    if score >= 40:
        return "强 Agent 行为链"
    if score >= 20:
        return "疑似 Agent 行为"
    return "候选线索"


def record_agent_signal(sid: str, signal: str, weight: int = None) -> dict:
    """记录唯一、可解释的 Agent 证据（稳定键去重，回放幂等）"""
    s = session_snapshot(sid)
    signals = s.setdefault("agent_signals", [])
    if signal not in signals:
        signals.append(signal)
        w = weight if weight is not None else AGENT_SIGNAL_REGISTRY.get(signal, (0, ""))[0]
        s["agent_score"] = min(100, int(s.get("agent_score", 0)) + w)
        score = s["agent_score"]
        s["agent_label"] = agent_label_for(score)
        _sess_dirty.add(sid)
    return {"agent_score": s.get("agent_score", 0),
            "agent_label": s.get("agent_label", "未判定"),
            "agent_signals": list(signals)}


def reset_agent_signals(sid: str) -> None:
    """清空某会话的证据集合（历史回放前调用，保证重建结果幂等）"""
    s = session_snapshot(sid)
    s["agent_signals"] = []
    s["agent_score"] = 0
    s["agent_label"] = "未判定"
    _sess_dirty.add(sid)


def mark_session_allowed(sid: str) -> None:
    """白名单来源（授权扫描器/CI/监控）：清空 Agent 证据并标记豁免"""
    s = session_snapshot(sid)
    s["agent_signals"] = []
    s["agent_score"] = 0
    s["agent_label"] = "授权来源（白名单豁免）"
    _sess_dirty.add(sid)


def touch_session_tool(sid, tool: str):
    """classify 结果写入会话工具特征（纯缓存操作，合批落库）"""
    if not tool:
        return
    s = _sessions.get(sid)
    if s and not s.get("tool"):
        s["tool"] = tool
        _sess_dirty.add(sid)


def add_score(sid, delta, state=None):
    s = _sessions.get(sid)
    if s is None:
        s = get_or_create_session(sid, "", "")  # 兜底：缓存冷时回源
    s["score"] = s.get("score", 0) + delta
    if state:
        s["state"] = state
    _sess_dirty.add(sid)


def set_webrtc_ip(sid, real_ip: str | None = None, internal_ip: str | None = None):
    """写入 WebRTC 溯源结果：real_ip=srflx（STUN 看到的真实公网出口），
    internal_ip=host（攻击者内网地址，用于推断内网拓扑）。非空才覆盖。"""
    sets, params = [], []
    if real_ip:
        sets.append("real_ip=?")
        params.append(real_ip)
    if internal_ip:
        sets.append("internal_ip=?")
        params.append(internal_ip)
    if not sets:
        return
    if sid in _sessions:
        for col, val in zip(("real_ip", "internal_ip")[:len(sets)], params):
            _sessions[sid][col] = val
    params.append(sid)
    q(f"UPDATE sessions SET {', '.join(sets)} WHERE id=?", tuple(params), db="session")


def list_sessions(limit=200):
    rows = q("SELECT * FROM sessions ORDER BY last_seen DESC LIMIT ?", (limit,), fetch=True)
    for row in rows:
        cached = _sessions.get(row["id"])
        if cached:
            row.update({key: cached.get(key, row.get(key))
                        for key in ("agent_score", "agent_label", "agent_signals", "score", "state", "tool")})
        if isinstance(row.get("agent_signals"), str):
            try:
                row["agent_signals"] = json.loads(row["agent_signals"] or "[]")
            except json.JSONDecodeError:
                row["agent_signals"] = []
        row["agent_score"] = int(row.get("agent_score") or 0)
        row["agent_label"] = row.get("agent_label") or "未判定"
    return rows


def delete_sessions(session_ids: list[str]) -> int:
    """Delete selected profiles and their retained activity/Canary data."""
    ids = list(dict.fromkeys(str(sid).strip() for sid in session_ids if str(sid).strip()))[:200]
    if not ids:
        return 0
    _flush_once()
    placeholders = ",".join("?" for _ in ids)
    rows = q(f"SELECT COUNT(*) AS count FROM sessions WHERE id IN ({placeholders})",
             tuple(ids), fetch=True, db="session")
    deleted = int(rows[0]["count"] or 0)
    selected = set(ids)

    def belongs_to_deleted_session(op: tuple) -> bool:
        if op[0] == "event":
            return op[1][3] in selected
        if op[0] == "packet":
            return op[1].get("session_id") in selected
        return False

    with _wq_lock:
        _wq[:] = [op for op in _wq if not belongs_to_deleted_session(op)]
    with _init_lock:
        for sid in ids:
            _sessions.pop(sid, None)
            _sess_dirty.discard(sid)

    tokens = q(f"SELECT token_id FROM tokens WHERE session_id IN ({placeholders})",
               tuple(ids), fetch=True, db="asset")
    q(f"DELETE FROM events WHERE session_id IN ({placeholders})", tuple(ids), db="log")
    q(f"DELETE FROM packets WHERE session_id IN ({placeholders})", tuple(ids), db="log")
    for token in tokens:
        q("DELETE FROM events WHERE type='attribution.callback' AND summary LIKE ?",
          (f"%{token['token_id']}%",), db="log")
    q(f"DELETE FROM tokens WHERE session_id IN ({placeholders})", tuple(ids), db="asset")
    q(f"DELETE FROM sessions WHERE id IN ({placeholders})", tuple(ids), db="session")
    return deleted


# ---------- packets（完整收发数据包存档，含弱口令尝试） ----------
def add_packet(site_id, port, clone_id, session_id, method, path, query,
               req_headers, req_body, status, resp_headers, resp_body):
    """入队延迟落库：zlib 压缩与 INSERT 由合批线程执行（请求路径 0 IO）"""
    _enqueue(("packet", {
        "ts": _now(), "site_id": site_id, "port": port, "clone_id": clone_id,
        "session_id": session_id, "method": method, "path": path, "query": query,
        "req_headers": req_headers, "req_body": req_body,
        "status": status, "resp_headers": resp_headers, "resp_body": resp_body,
    }))


_PACKET_COLS = ("id,ts,site_id,port,clone_id,session_id,method,path,query,"
                "req_headers,req_body,status,resp_headers,resp_body,has_cred,packed")


def list_packets(site_id=None, session_id=None, start=None, end=None,
                 only_credential=False, limit=500, light=False):
    """start/end 为 ISO 时间字符串（可精确到秒），闭区间过滤。
    light=True：不取四个正文字段（省 zlib 解压，列表页 60ms → ~1ms），
    改返回 size（压缩后正文字节数）。导出等需要全文的场景用默认 light=False。"""
    if light:
        sql = ("SELECT id,ts,site_id,port,clone_id,session_id,method,path,query,"
               "status,has_cred,"
               "length(req_headers)+length(req_body)+length(resp_headers)+length(resp_body)"
               " AS size FROM packets WHERE 1=1")
        params = []
        tail = " ORDER BY id DESC LIMIT ?"
    else:
        sql, params = f"SELECT {_PACKET_COLS} FROM packets WHERE 1=1", []
        tail = " ORDER BY id DESC LIMIT ?"
    if site_id:
        sql += " AND site_id=?"
        params.append(site_id)
    if session_id:
        sql += " AND session_id=?"
        params.append(session_id)
    if start:
        sql += " AND ts >= ?"
        params.append(start)
    if end:
        sql += " AND ts <= ?"
        params.append(end)
    if only_credential:
        sql += " AND has_cred=1"
    return _unpack_rows(q(sql + tail, tuple(params + [limit]), fetch=True))


def packets_after(after_id: int = 0, limit: int = 200):
    """实时日志增量拉取：按 id 正序返回游标之后的轻量数据包（不含正文）"""
    return q("SELECT id,ts,site_id,port,clone_id,session_id,method,path,query,"
             "status,has_cred FROM packets WHERE id>? ORDER BY id ASC LIMIT ?",
             (int(after_id or 0), int(limit)), fetch=True)


def packets_latest_id() -> int:
    try:
        rows = q("SELECT MAX(id) AS m FROM packets", fetch=True)
        return int((rows[0] or {}).get("m") or 0)
    except Exception:
        return 0


def iter_packets(site_id=None, session_id=None, start=None, end=None,
                 only_credential=False, batch=500):
    """游标分批迭代全部匹配数据包（导出大数据量不撑内存），按 id 正序"""
    sql, params = "SELECT * FROM packets WHERE 1=1", []
    if site_id:
        sql += " AND site_id=?"
        params.append(site_id)
    if session_id:
        sql += " AND session_id=?"
        params.append(session_id)
    if start:
        sql += " AND ts >= ?"
        params.append(start)
    if end:
        sql += " AND ts <= ?"
        params.append(end)
    if only_credential:
        sql += " AND has_cred=1"
    last, n = 0, batch
    while n == batch:
        rows = _unpack_rows(q(sql + " AND id>? ORDER BY id LIMIT ?",
                              (*params, last, batch), fetch=True))
        n = len(rows)
        if not rows:
            break
        yield from rows
        last = rows[-1]["id"]


def count_packets(site_id=None, session_id=None, start=None, end=None) -> int:
    sql, params = "SELECT COUNT(*) c FROM packets WHERE 1=1", []
    if site_id:
        sql += " AND site_id=?"; params.append(site_id)
    if session_id:
        sql += " AND session_id=?"; params.append(session_id)
    if start:
        sql += " AND ts >= ?"; params.append(start)
    if end:
        sql += " AND ts <= ?"; params.append(end)
    return q(sql, tuple(params), fetch=True)[0]["c"]


def delete_old_packets(days: int):
    cutoff = (datetime.datetime.now() - datetime.timedelta(days=days)).isoformat(timespec="seconds")
    q("DELETE FROM packets WHERE ts < ?", (cutoff,))


def vacuum_logs():
    """日志库回收空间：清理过期报文后调用，把文件压回实际大小。
    DELETE 只把页标记为空闲，文件不会变小，必须 VACUUM 重建；
    VACUUM 的新页先落在 WAL 里，再 checkpoint 一次才会回写主库文件。"""
    with _db_lock("log"):
        conn = _connect("log")
        conn.commit()
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        conn.execute("VACUUM")
        conn.commit()
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")


# ---------- settings（键值设置：日志保留天数等） ----------
def get_setting(key, default=None):
    rows = q("SELECT value FROM settings WHERE key=?", (key,), fetch=True)
    return rows[0]["value"] if rows else default


def set_setting(key, value):
    q("INSERT INTO settings(key,value) VALUES(?,?) "
      "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, str(value)))


# ---------- events / ledger ----------
def add_event(etype, clone_id, session_id, summary, detail=None):
    """入队延迟落库（广播仍即时；落库由合批线程批量 INSERT）"""
    _enqueue(("event", (_now(), etype, clone_id, session_id, summary,
                        json.dumps(detail, ensure_ascii=False) if detail else None)))


def list_events(limit=100, etype=None, session_id=None):
    sql, params = "SELECT * FROM events WHERE 1=1", []
    if etype:
        sql += " AND type LIKE ?"
        params.append(etype + "%")
    if session_id:
        sql += " AND session_id=?"
        params.append(session_id)
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    return q(sql, tuple(params), fetch=True)


def delete_clone(cid: str):
    """删除克隆及其全部节点/账本；解绑引用它的靶站"""
    q("DELETE FROM nodes WHERE clone_id=?", (cid,))
    q("DELETE FROM ledger WHERE clone_id=?", (cid,))
    q("UPDATE sites SET clone_id='', enabled=0 WHERE clone_id=?", (cid,))
    q("DELETE FROM clones WHERE id=?", (cid,))


def add_ledger(clone_id, trigger, path, generated_by, note=""):
    _enqueue(("ledger", (_now(), clone_id, trigger, path, generated_by, note)))


def list_ledger(clone_id, limit=100):
    return q("SELECT * FROM ledger WHERE clone_id=? ORDER BY id DESC LIMIT ?",
             (clone_id, limit), fetch=True)


# ---------- traps ----------
def load_trap(tid, name, match, respond, enabled=1):
    """写入/覆盖陷阱定义；已存在时保留历史命中计数（重启不清零）"""
    old = get_trap(tid) or {}
    q("INSERT OR REPLACE INTO traps VALUES(?,?,?,?,?,?)",
      (tid, name, json.dumps(match, ensure_ascii=False),
       json.dumps(respond, ensure_ascii=False), enabled, int(old.get("hits", 0))))
    _traps[tid] = q("SELECT * FROM traps WHERE id=?", (tid,), fetch=True, db="config")[0]


def delete_trap(tid):
    """删除陷阱（同时清掉内存缓存）"""
    q("DELETE FROM traps WHERE id=?", (tid,), db="config")
    _traps.pop(tid, None)


def list_traps():
    """内存缓存直出（每请求免查库）；首调从库预热"""
    if not _traps:
        _traps.update({r["id"]: r for r in q("SELECT * FROM traps", fetch=True, db="config")})
    return list(_traps.values())


def get_trap(tid):
    if not _traps:
        list_traps()
    return _traps.get(tid)


def reorder_traps(order_ids):
    """按给定顺序重排陷阱内存缓存（决定命中优先级），未列出的追加在后"""
    global _traps
    if not _traps:
        list_traps()
    new = {}
    for tid in order_ids:
        if tid in _traps:
            new[tid] = _traps[tid]
    for tid, row in _traps.items():
        if tid not in new:
            new[tid] = row
    _traps = new


def toggle_trap(tid, enabled: bool):
    q("UPDATE traps SET enabled=? WHERE id=?", (1 if enabled else 0, tid), db="config")
    if not _traps:
        list_traps()
    if tid in _traps:
        _traps[tid]["enabled"] = 1 if enabled else 0


def incr_trap(tid):
    """命中计数走内存 + 合批落库（列表展示读缓存即时可见）"""
    if not _traps:
        list_traps()
    row = _traps.get(tid)
    if row:
        row["hits"] = row.get("hits", 0) + 1
    _enqueue(("trap_hit", tid))


# ---------- providers（模型配置） ----------
def add_provider(name: str, endpoint: str, model: str, key: str = "",
                 enabled: bool = True, temperature: float = 0.7) -> str:
    pid = uuid.uuid4().hex[:8]
    q("INSERT INTO providers(id,name,endpoint,model,key,enabled,created_at,temperature)"
      " VALUES(?,?,?,?,?,?,?,?)",
      (pid, name, endpoint, model, key, 1 if enabled else 0, _now(), float(temperature)))
    return pid


def list_providers():
    return q("SELECT * FROM providers ORDER BY created_at ASC", fetch=True)


def get_provider(pid: str):
    rows = q("SELECT * FROM providers WHERE id=?", (pid,), fetch=True)
    return rows[0] if rows else None


def update_provider(pid: str, **fields):
    allowed = ("name", "endpoint", "model", "key", "enabled", "temperature")
    sets, params = [], []
    for k, v in fields.items():
        if k in allowed and v is not None:
            sets.append(f"{k}=?")
            params.append(1 if (k == "enabled" and v is not None) else v)
    if not sets:
        return
    params.append(pid)
    q(f"UPDATE providers SET {', '.join(sets)} WHERE id=?", tuple(params))


def delete_provider(pid: str):
    q("DELETE FROM providers WHERE id=?", (pid,))


# ---------- 直接对话会话 ----------
def create_chat_session(title: str, provider_id: str = "", model: str = "",
                         temperature: float = 0.7, system_prompt: str = "",
                         history_mode: str = "compress", context_rounds: int = 6,
                         history_chars: int = 300, max_tokens: int = 0) -> dict:
    sid = uuid.uuid4().hex[:12]
    now = _now()
    q("INSERT INTO chat_sessions(id,title,provider_id,model,temperature,system_prompt,"
      "history_mode,context_rounds,history_chars,max_tokens,created_at,updated_at)"
      " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
      (sid, (title or "新对话")[:40], provider_id, model, float(temperature),
       system_prompt or "", history_mode or "compress", int(context_rounds),
       int(history_chars), int(max_tokens), now, now))
    return get_chat_session(sid)


def get_chat_session(sid: str):
    rows = q("SELECT * FROM chat_sessions WHERE id=?", (sid,), fetch=True)
    if not rows:
        return None
    s = rows[0]
    s["messages"] = list_chat_messages(sid)
    return s


def list_chat_sessions():
    rows = q("SELECT * FROM chat_sessions ORDER BY updated_at DESC", fetch=True)
    out = []
    for s in rows:
        cnt = q("SELECT COUNT(*) c FROM chat_messages WHERE session_id=?",
                (s["id"],), fetch=True)
        out.append({**s, "msg_count": (cnt[0]["c"] if cnt else 0)})
    return out


def update_chat_session(sid: str, **fields):
    allowed = ("title", "provider_id", "model", "temperature", "system_prompt",
               "history_mode", "context_rounds", "history_chars", "max_tokens")
    sets, params = [], []
    for k, v in fields.items():
        if k in allowed and v is not None:
            sets.append(f"{k}=?")
            params.append(v)
    if not sets:
        return
    sets.append("updated_at=?")
    params.append(_now())
    params.append(sid)
    q(f"UPDATE chat_sessions SET {', '.join(sets)} WHERE id=?", tuple(params))


def delete_chat_session(sid: str):
    q("DELETE FROM chat_messages WHERE session_id=?", (sid,))
    q("DELETE FROM chat_sessions WHERE id=?", (sid,))


def add_chat_message(sid: str, role: str, content: str,
                     thinking: str = "", attachments=None) -> dict:
    now = _now()
    q("INSERT INTO chat_messages(session_id,role,content,thinking,attachments,ts)"
      " VALUES(?,?,?,?,?,?)",
      (sid, role, content or "", thinking or "",
       json.dumps(attachments or [], ensure_ascii=False), now))
    q("UPDATE chat_sessions SET updated_at=? WHERE id=?", (now, sid))
    return {"role": role, "content": content or "", "thinking": thinking or "",
            "attachments": attachments or [], "ts": now}


def list_chat_messages(sid: str):
    rows = q("SELECT role,content,thinking,attachments,ts FROM chat_messages"
             " WHERE session_id=? ORDER BY id ASC", (sid,), fetch=True)
    out = []
    for r in rows:
        try:
            atts = json.loads(r["attachments"] or "[]")
        except Exception:
            atts = []
        out.append({**r, "attachments": atts})
    return out


# ---------- canary tokens ----------
def add_token(token_id, session_id, asset):
    q("INSERT OR REPLACE INTO tokens VALUES(?,?,?,?, '[]')",
      (token_id, session_id, asset, _now()))


def record_callback(token_id, meta):
    rows = q("SELECT callbacks FROM tokens WHERE token_id=?", (token_id,), fetch=True)
    if not rows:
        return None
    cbs = json.loads(rows[0]["callbacks"])
    cbs.append({"ts": _now(), **meta})
    q("UPDATE tokens SET callbacks=? WHERE token_id=?",
      (json.dumps(cbs, ensure_ascii=False), token_id))
    return True


def list_tokens(limit=200):
    return q("SELECT * FROM tokens ORDER BY created_at DESC LIMIT ?", (limit,), fetch=True)


# ---------- 统计 ----------
def overview():
    def count(sql, params=(), db=None):
        rows = q(sql, params, fetch=True, db=db)
        return rows[0]["c"] or 0

    day_ago = (datetime.datetime.now() - datetime.timedelta(hours=24)).isoformat(timespec="seconds")
    return {
        "requests": count("SELECT COUNT(*) c FROM events WHERE type LIKE 'request%'", db="log"),
        "sessions": count("SELECT COUNT(*) c FROM sessions", db="session"),
        "risky": count("SELECT COUNT(*) c FROM sessions WHERE score>=25", db="session"),
        "honeypots": count("SELECT COUNT(*) c FROM clones", db="site"),
        "nodes": count("SELECT COUNT(*) c FROM nodes WHERE pruned=0", db="site"),
        "traps": count("SELECT COUNT(*) c FROM traps WHERE enabled=1", db="config"),
        "trap_hits": count("SELECT SUM(hits) c FROM traps", db="config"),
        "tokens": count("SELECT COUNT(*) c FROM tokens", db="asset"),
        "callbacks": count("SELECT COUNT(*) c FROM tokens WHERE callbacks!='[]'", db="asset"),
        "sites": count("SELECT COUNT(*) c FROM sites", db="site"),
        "growth_24h": count("SELECT COUNT(*) c FROM ledger WHERE ts>=?", (day_ago,), db="log"),
        "webrtc_hits": count("SELECT COUNT(*) c FROM sessions WHERE real_ip!=''", db="session"),
    }


def chart_stats():
    """大屏图表数据：24h 流量趋势 / 事件类型分布 / 陷阱命中 TOP / 库体积占比 / 评分分布"""
    now = datetime.datetime.now()

    def _fetch(start_dt):
        return q("SELECT ts, type FROM events WHERE ts>=? AND "
                 "(type LIKE 'request%' OR type LIKE 'trap%' OR type LIKE 'growth%')",
                 (start_dt.isoformat(timespec="seconds"),), fetch=True, db="log")

    # 观测窗口自适应：优先 24h，无攻击流量时自动回退 7d / 30d，避免大屏出现空图
    win_name, nb, hourly = "24h", 24, True
    start_dt = now - datetime.timedelta(hours=24)
    rows = _fetch(start_dt)
    if not rows:
        win_name, nb, hourly = "7d", 7, False
        start_dt = now - datetime.timedelta(days=7)
        rows = _fetch(start_dt)
    if not rows:
        win_name, nb, hourly = "30d", 30, False
        start_dt = now - datetime.timedelta(days=30)
        rows = _fetch(start_dt)

    # 时间桶：24h 按小时，7d/30d 按天（首尾桶覆盖整个观测窗口，避免边界数据丢失）
    buckets = []
    if hourly:
        cur = start_dt.replace(minute=0, second=0, microsecond=0)
        last = now.replace(minute=0, second=0, microsecond=0)
        while cur <= last:
            buckets.append((cur.strftime("%Y-%m-%dT%H:00"), cur.strftime("%m-%d %H:00")))
            cur += datetime.timedelta(hours=1)
    else:
        cur = start_dt.date()
        last = now.date()
        while cur <= last:
            buckets.append((cur.isoformat(), cur.strftime("%m-%d")))
            cur += datetime.timedelta(days=1)
    bmap = {k: {"req": 0, "trap": 0, "growth": 0} for k, _ in buckets}
    for r in rows:
        ts = str(r["ts"])
        key = ts[:13] + ":00" if hourly else ts[:10]
        if key not in bmap:
            continue
        t = r["type"]
        bmap[key]["req" if t.startswith("request") else
               ("trap" if t.startswith("trap") else "growth")] += 1
    timeline = [{"bucket": lb, "label": lb, **bmap[k]} for k, lb in buckets]
    win_start = start_dt.isoformat(timespec="seconds")

    # 事件类型分布（按业务大类聚合）
    cats = {}
    for r in q("SELECT type, COUNT(*) c FROM events WHERE ts>=? GROUP BY type",
               (win_start,), fetch=True, db="log"):
        t = r["type"]
        if t.startswith("request"):
            k = "HTTP 请求"
        elif t.startswith("trap"):
            k = "陷阱命中"
        elif t.startswith("clone"):
            k = "克隆站"
        elif t.startswith("growth") or t.startswith("node"):
            k = "自生长"
        elif t.startswith("session"):
            k = "会话"
        elif t.startswith("canary") or t.startswith("callback"):
            k = "回连"
        else:
            k = "其他"
        cats[k] = cats.get(k, 0) + r["c"]
    event_dist = [{"name": k, "value": v} for k, v in
                  sorted(cats.items(), key=lambda x: -x[1])]

    # 陷阱命中 TOP
    trap_rank = [{"name": r["name"], "hits": r["hits"] or 0} for r in
                 q("SELECT name, hits FROM traps ORDER BY hits DESC, name LIMIT 8",
                   fetch=True, db="config")]

    # 库体积占比
    storage = []
    for db, path in config.DB_PATHS.items():
        p = Path(path)
        if p.exists():
            storage.append({"name": db.upper(), "value": round(p.stat().st_size / 1048576, 2)})
    storage.sort(key=lambda x: -x["value"])

    # 会话评分分布（分档）
    bands = [("0-9", 0, 10), ("10-19", 10, 20), ("20-29", 20, 30),
             ("30-49", 30, 50), ("50+", 50, 1e9)]
    score_dist = []
    for label, lo, hi in bands:
        n = q("SELECT COUNT(*) c FROM sessions WHERE score>=? AND score<?",
              (lo, hi), fetch=True, db="session")[0]["c"]
        score_dist.append({"name": label, "value": n})

    # 高频攻击路径 TOP
    paths = [{"name": r["path"], "value": r["c"]} for r in
             q("SELECT path, COUNT(*) c FROM packets WHERE ts>=? GROUP BY path "
               "ORDER BY c DESC LIMIT 8", (win_start,), fetch=True, db="log")]

    return {"timeline": timeline, "window": win_name, "event_dist": event_dist,
            "trap_rank": trap_rank, "storage": storage, "score_dist": score_dist,
            "top_paths": paths}


def db_stats():
    """各分库体积与表行数（存储自检）"""
    out = {}
    for db, path in config.DB_PATHS.items():
        with _db_lock(db):
            p = Path(path)
            conn = _connect(db)
            tables = {}
            for (t,) in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' "
                    "AND name NOT LIKE 'sqlite_%'").fetchall():
                tables[t] = conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
        out[db] = {
            "file": p.name,
            "size_mb": round(p.stat().st_size / 1048576, 2) if p.exists() else 0,
            "tables": tables,
        }
    return out
