# 展柜微环境异常复原台

展柜微环境异常复原台面向文物保护工程师、预防性保护馆员和展览值班主管，提供本地运行的 HTTP JSON API。系统记录展柜、展品和传感器异常，完成风险分级、现场复核、干预方案审核、操作执行、恢复观察、重新开放签署及证据封存。

数据保存在本地 JSON 快照中。每次业务写入都检查 `expected_revision`，以 `request_id` 保证幂等，并追加带前序摘要的审计事件。快照通过临时文件同步后原子替换；服务启动时会校验完整审计链和在途展柜/传感器唯一索引。同一展柜与传感器存在未封存事件时，创建接口返回 `ACTIVE_INCIDENT_CONFLICT` 及原事件编号、状态和 revision；封存会在同一事务中释放索引。

## 构建与测试

```bash
go build ./...
go test ./...
```

## 运行

默认仅监听高位回环地址 `127.0.0.1:19081`：

```bash
go run ./cmd/server
```

可以用 `-addr` 指定其他回环地址，并用 `-data` 指定数据文件：

```bash
go run ./cmd/server -addr=127.0.0.1:19082 -data=var/microenvironment.json
```

也可以通过 `PORT` 指定端口，服务会绑定 `127.0.0.1:<PORT>`。显式提供非回环 IP 会被拒绝。

## 自检

以下命令会创建临时数据目录，在指定地址真实启动 HTTP 服务，执行从异常登记到主管签署封存的完整流程，然后主动退出：

```bash
go run ./cmd/server -self-check -addr=127.0.0.1:19081
```

## API 使用约定

写命令的 JSON 包含 `meta.request_id`、`meta.actor_id`、`meta.actor_role` 和除创建外必需的 `meta.expected_revision`。也可分别通过 `X-Request-ID`、`X-Actor-ID`、`X-Actor-Role` 和 `If-Match` 请求头覆盖这些值。重复的 `request_id` 会重放首次成功响应，并返回 `Idempotent-Replay: true`。

主要入口为 `POST /v1/environment-incidents`，可通过 `discovery_readings` 原子登记最多 100 条按时间递增的发现读数；未提供时仍使用顶层单条读数。启用 `calibration_reference` 时须同时提供未来的 `calibration_expires_at`，每条发现读数须提供 `quality` 或 `quality_note`。系统按传感器状态、校准参考一致性和采样间隔封存质量标记；低质量读数保留为原始证据但不参与风险峰值选择。登记响应同时固化基线版本，重复 `request_id` 返回同一快照和 revision。异常详情、列表、时间线和证据摘要分别通过 `/v1/environment-incidents/{incidentID}`、`/v1/environment-incidents`、`/v1/environment-incidents/{incidentID}/timeline` 和 `/v1/environment-incidents/{incidentID}/evidence` 查询。

列表默认是未封存工作队列，支持可重复的 `status`、`risk_level`，以及 `display_case_id`、`deadline_status`、`evidence_gap`、`escalation_status`、`owner_id`、`limit`、`cursor` 参数。`stats=true` 在同一存储快照内返回事件数、平均处置分钟数、超时数、封存率、展柜/风险/状态分组和证据缺口事件编号，并在 `meta.generated_at` 标明统计时刻。升级状态为 `normal`、`due_soon`、`overdue_unacknowledged`、`overdue_acknowledged` 或 `archived`；响应同时给出各状态计数和逾期未确认数量。值班主管通过 `/deadline-acknowledgements` 登记责任人、下一行动和限时承诺，原 `response_deadline` 不会被确认命令修改。

现场复核命令同时接收 `independent_reading`、校准参考、替代监测安排及结构化 `cause_hypotheses`，并只允许风险保持或升级、期限保持或提前。每项假设有独立标识和追加式结论历史，通过 `/inspection/hypotheses/{hypothesisID}/validations` 登记支持或排除证据；方案提交会检查原因证据门禁。不可信传感器可通过 `/sensor-handover` 提交同一校准参考下的新旧重叠读数并原子切换当前来源。

现场复核完成前可通过 `/discovery-readings`（或 `/readings`）追加按时间递增的发现读数，系统保留风险重评估历史并只收紧处置期限；`/inspection-report` 提供独立仪表差值、可信度和交接覆盖报告。

方案以 `version` 留存；退回时每项 `correction_requirements` 包含责任步骤、风险说明和完成证据要求，重提使用 `base_version`、带 `evidence` 的 `correction_resolutions` 和安全参数变化说明。可选 `safety_envelope` 登记温湿度变化率、暴露时长、停止阈值及回退责任，审核通过后冻结在该版本。执行登记须通过 `step_results` 逐项对应批准方案、为耗材提供有效批次、带单位数量和 `expires_at`，并可用 `deviations` 登记材料替代、非关键步骤改序或参数偏离；校准参考不一致或漂移越界会生成待复核的 `calibration_drift` 偏差并阻止观察。必须复核的偏差由另一名保护工程师通过执行记录下的偏差复核入口决定。验证失败后的补充执行通过 `failed_verification_id` 引用最近失败轮次，成功后自动开启新观察窗口。

可用 `/plans/diff?from_version=&to_version=` 查询方案逐字段差异，执行时可显式提交 `plan_version` 和冻结的 `safety_envelope`；`/materials`（或 `/material-tracking`）按事件汇总耗材批次、用量、执行人及临期预警。

观察接口单批最多 100 条，按风险和敏感等级生成不可放宽的恢复策略。`warning`、阈值超限或采样间隔过长会中断当前连续区段但保留原始证据；写入响应带最新进度，`GET /recovery-progress` 只读返回稳定分钟、有效读数、剩余要求和预计最早验证时间，正式验证复用同一口径。

`GET /reopen-readiness` 逐项显示状态、角色、复核、方案、偏差、观察、验证、证据和暂缓门禁。恢复合格后，值班主管可通过 `/reopen-holds` 登记结构化暂缓和补证期限，再逐项引用证据解决；最终签署会在同一事务中重新检查全部门禁。封存证据查询返回不可变清单摘要、分类计数和即时完整性状态。`GET /healthz` 提供健康检查；`GET /internal/self-check` 仅接受回环客户端请求。

`/recovery-progress` 现同时返回观察区段统计和异常中断回放，`/verification-history`（或 `/verifications`）返回各轮验证对比及补充干预建议；暂缓到期可由主管调用 `/reopen-holds/{holdID}/renew` 提交新的未来复核期限。时间线支持 `event_type`、`actor_id`、`from`、`to`、`limit`、`cursor` 筛选分页，并返回证据缺口。
