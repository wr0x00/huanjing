## artex对抗记录

以 ARTEX（本地部署的自主攻防 Agent 平台）对蜜罐靶站（端口 8888）发起两轮实战，验证蜜罐的**拖住 / 取证 / 研判**能力。以下数据全部来自蜜罐自身落库的报文与事件，非人工整理。

### 对抗环境

| 项 | 值 |
| --- | --- |
| 攻击方 | ARTEX 自主攻防平台（`http://127.0.0.1:8787/`），多模块并发、UA 内嵌任务标识 |
| 防守方 | 幻境蜜罐默认靶站 `:8888`（clone=seed）、控制台 `:9000` |
| 观测口径 | `data/hp_log.db` 报文库（2659 条）+ `data/hp_session.db` 会话库（51 个会话） |

### 第一轮：语义诱饵探针（11-19 23:20）

ARTEX 以显式 UA 探测语义诱饵链：

```
Mozilla/5.0 (compatible; ArtEx/1.0) sqlmap/1.7 profile-browser-test
```

| 请求 | 结果 |
| --- | --- |
| `GET /robots.txt` | 200，返回带 `Disallow: /internal/agent-task.txt` 的诱饵索引 |
| `GET /internal/agent-task.txt` | 200，读取到语义任务诱饵（含 `AGENT-OBS-7F3A` 标记） |
| `GET /api/internal/audit-status` | 200，**按诱饵要求跟进回访**结果接口 |

两个探针会话全部判为**强 Agent 行为链**（agent_score=100），9 个信号全中：`client_marker` / `semantic_task_read` / `result_api_probe` / `semantic_followthrough` / `ua_ioc_match` / `ua_task_mark` / `header_id_token` / `multi_family_parallel` / `multi_ua_per_worker`。这验证了「语义诱饵 → 读取 → 跟进回访」整条链路的可观测性。

### 第二轮：多模块并发爆破（11-20 14:00–14:32，32 分钟）

| 指标 | 数值 |
| --- | --- |
| 独立会话 | 19 个（16 个不同 UA 串，归并 11 个工具家族：curl / Python-urllib / Chrome 伪装 / 裸 Mozilla / dir-probe / recon-probe / worker-shell / authorized-pentest / pentest-* / poc-* / final-check） |
| 请求总量 | 2556 条（200 × 1506，404 × 1050） |
| Agent 研判 | **强 Agent 行为链 17 个 + 疑似 Agent 行为 2 个**，零漏判 |
| 命中信号 | `multi_family_parallel` 19、`multi_ua_per_worker` 19、`multi_surface` 12、`burst_rate` 11、`ua_fake_browser` 10、`window_path_diversity` 9、`ua_task_mark` 8、`deny_target_spray` 8、`chain_recon_cred` 4、`chain_postauth` 4 |
| 最高会话风险分 | 4022（`071ab5698e42`，560 请求）、2302（`37f2b978e09e`，844 请求）、1919（`5e03f6ce7d30`，557 请求） |
| 单会话拖住时长 | 1462 秒（curl/7.88.1，557 请求）、1271 秒（560 请求）、294 秒（dir-probe，844 请求） |

**攻击链路还原**

```
踩点            →  /robots.txt 16 · /swagger 13 · /api/swagger.json 12 · /.git/config 13
诱饵读取        →  /backup_2023.sql.gz 19 · /.env 7 · /actuator/env 9 · /.git/HEAD 6
接口枚举        →  /v2/api-docs 9 · /admin/db_dump 14 · /admin/system 14
凭据爆破        →  POST /admin/login 439 次 · POST /api/login 152 次 · POST /admin/mfa/verify 20 次
深入后台        →  /admin/users 33 · /admin/orders 21 · /admin/dashboard 16
未命中探测      →  1050 次 404（/v2/* 业务接口、/metrics、/admin/settings 等）
```

**捕获的凭据字典**（明文口令入库即脱敏，仅保留账号维度）：`admin:admin123`（14 次）、`admin:admin`、`admin:123456`、`admin:888888`、`admin:qwerty`、`admin:Admin@123`、`test:123456`、`root:root`、`guest:guest`、`demo:demo`、`operator:operator`、`zhangsan:123456`、`admin:Starlan@2023` 等 28 组，覆盖 JSON 与表单两种编码、username/account/email 三种字段名变体。

### 蜜罐侧战果

| 能力 | 战果 |
| --- | --- |
| 陷阱应答 | 967 次（`t_admin_login` 436、`t_api_login` 114、`t_backup_db` 99、`t_actuator` 99、`t_swagger_api` 47、`t_git_refs` 29、`t_ide_workspace` 14 …） |
| 凭据捕获 | 128 条 `trap.credential` 事件，口令字段全部 `[REDACTED]` |
| 意图判定 | 1100 次未命中请求进入判定（噪声不消耗模型额度） |
| 反薅生长 | 1042 次因配额拒绝生长，避免被无限撑大 |
| 实时生长 | 58 个页面在攻击过程中被 LLM 现场造出来：`/admin/dashboard`、`/admin/users`、`/admin/db_dump`、`/admin/index.html`、`/swagger` … 攻击者点开的每个后台入口都长成了可交互页面 |
| 溯源回连 | 4 次 `attribution.callback`，其中 3 次来自攻击者源（`Mozilla/5.0 dir-probe` ×2、`curl/7.88.1` ×1） |
| 会话留痕 | 19 个会话全量报文落库，可逐条导出复现 |

### 被识破的伪点（诚实记录）

同一批 439 次登录尝试的逐次结果暴露了三个仿真缺陷：

| 伪点 | 实证 | 影响 |
| --- | --- | --- |
| 任意凭据均登录成功 | 439 次 `/admin/login` 尝试中 **410 次直接进后台**、11 次进 MFA、仅 18 次报"用户名或密码错误"；连 `probe_nonexistent_zzz`、`zzz_nonexistent_9x` 这类明显不存在的账号也登录成功 | 高水平 Agent 可据此判定"假后台"，是当前最刺眼的破绽 |
| 两个登录入口自相矛盾 | 同期 `/api/login` 152 次尝试里 102 次明确返回"用户名或密码错误"（含被捕获最多的 `admin:admin123` 共 14 次），而 `/admin/login` 第 4 次起任意凭据直接进后台 | 同一套弱口令在两个入口结果相反，等于自曝仿真 |
| 尝试次数决定成败 | 第 4 次提交即进后台，与凭据内容无关 | 同上，且可被脚本稳定复现 |
| 品牌与模板自相矛盾 | 失败页 `<h3>星澜运营后台</h3>`、成功页 `<title>星澜运营后台</title>`、后台 `<h2>星澜科技 · 运营管理后台</h2>`，而站点人设为"默认仿冒模板" | 品牌残留破坏了仿冒一致性，且直接指向"这是伪造的" |

其中「admin/admin123 反而失败、随便一个乱码账号却能进后台」的反差，是 Agent 在对话里点名蜜罐漏洞的直接依据 —— 已列入待修：假登录改为**校验凭据**（错误凭据恒返回失败并置 401，仅命中弱口令库才放行 MFA → 后台），并把残留品牌统一到站点人设。

---
