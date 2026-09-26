# 技能包供应链登记处

技能包清单、能力声明、审查签署、隔离和回滚的完整领域服务。
仓库在原有领域合同、策略与事件资料基础上，提供一个仅依赖 Python 标准库、
以 SQLite 持久化的可运行参考实现。

## 能力总览

| 需求 | 实现 |
| --- | --- |
| 接收包清单、文件摘要、依赖、入口点与能力声明 | `catalog.upload` / `service.submit_package` |
| 内容+依赖+入口点+能力指纹去重，重复上传不产生新版本 | `versions` 唯一约束 + `Catalog.upload` |
| 版本差异比较（文件/依赖/入口点/能力） | `Catalog.diff` → `VersionDiff` |
| 按风险路由到代码审查 / 数据所有者 / 财务审批 | `PolicyBook.route`，支付级需三角色 |
| 签署只覆盖确定的内容摘要与能力集合，漂移失效 | HMAC 签署固定载荷，放行与启用前重新核验 |
| 租户启用检查地区、套餐、冲突能力 | `TenantDirectory.enable_skill` 三道闸门 |
| 按确定规则灰度分组 | `stable_bucket(salt, tenant_id)`，规则开批后锁定 |
| 异常率越线冻结新分配并回滚到最近安全版本 | `RolloutService.report_result` 自动冻结+回滚 |
| 隔离单个版本、列出受影响任务 | `RolloutService.isolate_version` |
| 验证历史安装确切清单 | `TenantDirectory.verify_install` |
| 重复上传/并发审批不产生两个正式版本 | `BEGIN IMMEDIATE` + 唯一约束 + 幂等放行 |
| 重启后审查与回滚批次连续 | 全部事实落盘；`RegistryService.recover` 接续 rolling_back 批次 |

## 目录

- `domain/contract.json`：实体、状态、事件类型和关键业务规则。
- `domain/policies.json`：可被程序读取的风险路由、冲突组、地区白名单、套餐与灰度默认值。
- `examples/events.json`：按业务发生时间排列的事件样例。
- `examples/end_to_end_demo.py`：覆盖全部流程的可运行演示。
- `skillregistry/`：服务实现（见下文模块说明）。
- `tools/validate_contract.py`：使用 Python 标准库和 SQLite 验证资料一致性。
- `tests/`：43 个单元/并发/重启测试。

## 模块说明

```text
skillregistry/
├── canonical.py  # 规范 JSON、SHA-256 摘要、确定性分桶、HMAC 签署与核验
├── errors.py     # 领域错误
├── policy.py     # 风险路由、套餐、地区、能力冲突
├── store.py      # SQLite 表结构、BEGIN IMMEDIATE 即时事务、事件日志
├── catalog.py    # 包登记、上传去重、版本编号、差异比较
├── reviews.py    # 审查路由、签署、漂移核验、并发放行
├── tenants.py    # 租户闸门（地区/套餐/冲突）、安装记录与历史清单核验
├── rollout.py    # 灰度批次、确定性分组、异常冻结、回滚、隔离、重启恢复
└── service.py    # 门面，启动时恢复中断的回滚
```

## 快速开始

```python
from skillregistry.service import RegistryService
from skillregistry.canonical import stable_bucket

service = RegistryService("/tmp/registry.db")

# 1. 上传（内部完成登记、清单核验、风险路由）
result = service.submit_package("家庭助手", {
    "files": [{"path": "main.py", "size": 120, "sha256": "..."}],
    "dependencies": [{"name": "requests", "constraint": "^2.31", "digest": "..."}],
    "entrypoints": [{"name": "run", "command": "./bin/run"}],
    "capabilities": ["mail.read", "device.home.control"],
})
version_id = result["version_id"]

# 2. 按路由结果签署（elevated 需要 code_review + data_owner）
status = service.reviews.review_status(version_id)
for role in status["required_approvers"]:
    service.reviews.sign_review(version_id, role, f"user-{role}")
formal_no = service.reviews.approve(version_id)   # 分配正式版本号

# 3. 租户启用（自动检查地区、套餐、冲突、签署时效）
service.tenants.register_tenant("ent-cn", "enterprise", "cn-north")
service.tenants.enable_skill("ent-cn", "家庭助手", version_id)

# 4. 灰度：确定性分组，同一 (盐, 租户) 永远同组
batch_id = service.rollout.start_rollout(version_id)
service.rollout.assign(batch_id, "ent-cn", open_groups={"canary"})

# 5. 异常越线 → 冻结 + 自动回滚到最近安全版本
service.rollout.report_result(batch_id, errors=2, total=20)
```

## 关键设计

### 版本唯一性与并发

- 候选版本指纹 = SHA-256(内容摘要 + 依赖摘要 + 入口点摘要 + 能力摘要)，
  对规范化 JSON 计算，字段顺序不影响结果。重复上传复用同一版本。
- 所有写操作走 `BEGIN IMMEDIATE` 即时事务，配合
  `unique(package_id, fingerprint)`、`unique(package_id, formal_version_no)`，
  把并发上传与并发审批串行化；并发审批的落败方幂等返回同一版本号。

### 签署边界与漂移

签署载荷是固定结构，**只**含版本标识与四类确定摘要、必需角色、策略版本：

```json
{
  "payload_version": 1,
  "review_id": "...",
  "version_id": "...",
  "content_digest": "...",
  "deps_digest": "...",
  "entrypoint_digest": "...",
  "capability_digest": "...",
  "required_approvers": ["code_review", "data_owner"],
  "policy_version": "2026-09-01"
}
```

版本行不可变，签署不会延伸到新版本；放行、启用、灰度分配前都重新
计算摘要并验签，内容/依赖/能力漂移直接令签署失效。

### 灰度、冻结与回滚

- 分组只由 `blake2b(salt:tenant_id) % 100` 决定，重启/换进程一致。
- 批次开始时盐值、组占比、阈值固化（`rules_locked=1`），之后修改被拒。
- 累计异常率达到阈值（且样本数达标）→ 批次冻结、停发新分配，
  版本回滚到最近 `approved` 安全版本；回滚逐条安装推进并逐事务落盘，
  进程重启后 `recover()` 接续完成。
- `rollback_version` 还覆盖手动启用、没有批次的安装。

### 历史可核验

每个安装固化签署版本的 `manifest_digest` 与 `deps_digest`；
`verify_install` 用现场清单重算比对，任何增删改或依赖漂移都会
把安装标记为 `drifted` 并记录 `install.drift_detected` 事件。

## 构建

```bash
python3 -m compileall -q .
```

## 测试

```bash
python3 -m unittest discover -s tests -v
```

包含上传去重、风险路由、签署漂移、租户三道闸门、确定性灰度、
异常冻结回滚、单版本隔离、历史清单核验、并发上传/审批（8 线程）、
重启后继续审查与回滚等共 43 个用例。

## 资料校验

```bash
python3 tools/validate_contract.py
```

## 完整流程演示

```bash
python3 examples/end_to_end_demo.py
```

所有命令都在项目根目录执行，仅需 Python 3.11+，不需要外部数据库或服务。
