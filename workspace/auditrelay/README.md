# auditrelay — 审计馈送中继（独立服务）

一个**独立运行**的审计馈送中继。它只通过现有网关（`dpgw`）的**只读**透明日志接口
拉取**已签名树头**和**叶记录**，自行逐字节验证后写入自己的**独立镜像仓库**。
中继没有上游的签名密钥，只有**验证**密钥：它能验真，绝不能伪造。

零第三方依赖，仅使用 Python 3.11 标准库；与网关共用同一套 RFC 9162 Merkle 规则与
canonical-JSON HMAC 验签算法（字节级一致），但不导入、不打开、不改动网关的任何数据。

## 信任与停止语义

每轮同步严格按序执行，任何一步失败都**整体不提交**，保留最后可信位置：

1. `GET /v1/transparency` 取当前签名树头（STH），用带外配置的验证密钥验 HMAC；
2. 拒绝**回退高度**（签名有效但 `tree_size` 小于已可信高度）；
3. 对每个未镜像序号 `GET /v1/transparency/inclusion/<i>`，校验
   叶哈希可由信封重算、叶索引稠密无洞、包含证明能折叠到 STH 根；
4. 用所有新叶重放 Merkle frontier，最终根必须等于 STH 根；旧 frontier 必须仍折叠到
   上一个可信根（绑定同一条历史）；
5. 全部通过后在**单事务**内写入整批叶子并原子推进 高度/frontier/STH。

| 情形 | 行为 |
|---|---|
| 上游不可用（连接失败/5xx/超时） | `upstream_unavailable`，停在可信位点 |
| 返回回退高度 | `fallback_height`，拒绝，位点不动 |
| 树头签名错误 | `bad_signature`，位点不动 |
| 区间缺口（缺叶） | `interval_gap`，整批不提交，位点不动 |
| 叶被篡改 / 证明不成立 / 根不符 | `leaf_hash_mismatch` / `proof_invalid` / `root_mismatch`，位点不动 |
| 上游冻结 | 只读到冻结时刻的最后可信树头，冻结后的增长不可见 |
| 恢复 | 从保留的可信高度精确续传，绝不补造记录 |

网络拉取与验证明文在**租户服务锁之外**进行（仅持有同步锁），慢/冻结的上游不会
阻塞任何租户的投递。

## 多租户隔离与投递语义

- 每个审计租户有独立的**筛选规则**（事件类型、主体前缀、payload 等值；`any`/`all`）
  和独立的**消费位点 cursor**、独立令牌（`artok.<租户>.<随机>`）。
- 投递包覆盖按**原始序号连续**的闭区间 `[seq_start, seq_end]`：
  - 命中记录携带完整信封 + 包含证明；
  - 未命中记录只暴露**哈希锚点**（不含内容），保证区间可验且不泄漏被排除数据；
  - 区间总是**终止于一条命中记录**，绝不越过、绝不跳号，也不补造。
- 投递为**短租约**。`delivery_id` 由 `(租户, 区间, 筛选版本)` 确定性派生，
  包体为 canonical JSON（不含 attempt/持有者等易变字段）。因此：
  - **超时重投**：相同 `delivery_id`、**字节完全相同**，只增加 `attempt` 并换新租约令牌；
  - **进程重启**：从独立 SQLite 中读出同一 open 包，仍是同一 id 与同一字节；
  - 同一活跃消费者重取：返回相同字节。
- **确认只接受当前包末端** `ack_seq == seq_end`：
  - 早于末端 → `wrong_ack`；跳过末端 → `skip_ack`；位点均不移动；
  - 重复确认已确认的包 → 幂等成功，位点不重复推进；
  - 携带的 `payload_sha256` 与服务字节不符 → `payload_mismatch`。
- 拒绝项（均记录、不移动位点）：
  越租户令牌 `cross_tenant_token`、无效令牌 `invalid_token`、
  旧租约/非当前持有者 `old_lease`、双消费者抢活跃租约 `lease_held`、
  运行中存在未结清投递包时改筛选 `filter_locked`、
  已停用租户 `tenant_inactive`（停用保留状态与位点，仅禁止新租约；存量包仍可幂等确认）。
- **慢租户不阻塞其他租户**：各租户位点/租约相互独立。

## 独立持久化

```
relay-home/
  relay.sqlite   # 验证后的镜像叶 + 租户 + 投递包(含字节blob) + 事件/拒绝日志
  config.json    # 上游URL、只读令牌、验证密钥、租约TTL、admin令牌 (0600)
```

## HTTP API

租户面（租户 Bearer 令牌）：

| 方法 | 路径 | 说明 |
|---|---|---|
| GET  | `/v1/relay/<tid>/status` | 位点、镜像高度、积压、当前租约 |
| POST | `/v1/relay/<tid>/filter` | 替换筛选（无 open 包时才允许） |
| POST | `/v1/relay/<tid>/deliveries` | 获取短租约投递包 `{consumer,max_items,lease_seconds}` |
| GET  | `/v1/relay/<tid>/deliveries/<dlv>` | 重取同一字节 |
| POST | `/v1/relay/<tid>/deliveries/<dlv>/ack` | `{ack_seq,lease_token,payload_sha256}` |

管理面（admin Bearer 令牌）：

| 方法 | 路径 | 说明 |
|---|---|---|
| GET  | `/v1/admin/status` | 镜像高度、上游态、租户、事件、拒绝原因 |
| POST | `/v1/admin/sync` | 立即跑一轮拉取/验证 |
| POST | `/v1/admin/tenants` / GET `/v1/admin/tenants` | 建租户 / 列表 |
| POST | `/v1/admin/tenants/<tid>/active` | 停用/启用 |
| GET  | `/v1/admin/events` | 同步/投递/拒绝事件流 |

运维页面：`GET /ops`（镜像高度、积压、租约持有者、重试次数、拒绝原因，自动刷新）。

## CLI

```bash
# 初始化（指向现有网关只读接口，带外拿到 transparency 验证密钥）
python -m auditrelay init ./relay-home \
  --upstream-url http://127.0.0.1:8080 \
  --upstream-token <gateway-read-token> \
  --upstream-secret <secrets.json 中的 transparency_secret，hex>

# 运行（HTTP API + 后台同步 + /ops 运维台）
python -m auditrelay serve ./relay-home --port 8090

# 内置可故障注入的演示上游（无需真实网关即可演示全部异常）
python -m auditrelay serve ./relay-home --demo --demo-seed 8 --port 8090
python -m auditrelay demo ./relay-home mode offline|fallback|badsig|gap|freeze
python -m auditrelay demo ./relay-home append --type share_issued --subj s1

# 租户操作
python -m auditrelay tenant-create ./relay-home aud --filter-json '{"rules":[{"event_types":["share_issued"]}]}'
python -m auditrelay acquire ./relay-home aud --token <tok> --consumer c1 --lease-seconds 30 --out pkg.json
python -m auditrelay ack ./relay-home aud <delivery_id> <seq_end> --token <tok> --lease-token <lease_tok>

# 离线投递包校验器（无需运行中继、无需网络）
python -m auditrelay verify pkg.json --home ./relay-home --tenant aud
```

## 离线投递包校验器

`auditrelay/offline_verify.py` 对一个捕获的包文件与验证密钥，离线检查：

- 内嵌签名树头验签通过；
- 每个命中条目的叶哈希可由信封重算；
- 每条记录的包含证明在其原始序号处折叠到签名根；
- 条目稠密覆盖 `[seq_start,seq_end]`、无洞、有序；
- 命中标记确实满足包内冻结的筛选规则；未命中条目不得携带信封；
- canonical 包字节的 SHA256（与服务端 `payload_sha256` 一致，佐证重投/重启字节不变）。

任一不满足即非零退出并给出原因。

## 测试

```bash
python3 -m unittest tests.test_audit_relay -v   # 28 个中继场景测试
```

覆盖：首次同步、断线续传、回退高度、错签、缺口、篡改叶、冻结上游、
隔离筛选与位点、双消费者抢租约、超时重投（同 id 同字节）、进程重启、
仅末端确认、跳段/错误确认、重复确认幂等、越租户令牌、旧租约、
运行中改筛选拒绝、租户停用、慢租户不阻塞、离线验签（含篡改包拒绝）。
