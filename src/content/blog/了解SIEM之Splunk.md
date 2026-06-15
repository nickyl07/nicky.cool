---
title: 了解SIEM之Splunk
description: "学习笔记" 
pubDate: 2026-05-09
lastModDate: ''
ogImage: true
toc: true
share: true
giscus: true
search: true
---

## 引言

本文将对Splunk做一个简单了解。

在 SOC（安全运营中心）环境中，**SIEM（安全信息和事件管理）** 平台负责汇聚所有安全设备的日志，并通过检测引擎和安全专家进行实时分析。**Splunk** 通常被用作这一流程的核心大脑。

本质上，Splunk 是一个“针对机器数据的搜索引擎”。无论是防火墙、VPN、端点防护（EDR）还是域控（AD），只要是机器产生的、带时间戳的日志（Machine Data），它都能处理并建立索引。你可以将其理解为日志界的 Google，通过搜索和关联，满足各种复杂的安全分析需求。

Splunk在官网有初次下载60天试用，可以下载来摸索一下。



方向：安全威胁检测、事故响应及合规审计

### “Splunk 在 SOC 流程中起什么作用？”

Splunk 的核心价值在于**关联分析**与**威胁狩猎**。

**关联分析**：单独看“多次登录失败”可能只是员工忘密码，但如果关联到“随后该 IP 访问了敏感数据库”，这就是撞库攻击。

**威胁狩猎**：即使没有告警，分析师也会主动在 Splunk 中搜索异常流量或可疑进程。

### 安全插件：Splunk Enterprise Security (ES)

**Splunk ES**是 Splunk 专门为安全设计的“高级版”统一平台，可与智能代理 AI、SOAR、UEBA 和 SIEM 无缝集成。

可以使用官网的导览链接来了解和使用：

[Splunk Enterprise Security Product Tour | Thanks | Splunk](https://www.splunk.com/en_us/form/splunk-enterprise-security-premier-product-tour/thanks.html)

![image-20260510133330568](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260510152054062.png)

- **Notable Events（显著事件）：** 在 ES 中，告警不叫 Alert，叫 Notable Events。
- **Asset & Identity（资产与身份）：** ES 会把 IP 自动关联到具体的员工姓名和设备。
- **Threat Intelligence（威胁情报）：** ES 可以自动导入外部的黑名单 IP、恶意域名（IoC），并与公司日志实时比对。

------

### SOC 常见技术题

#### 1. “如果让你在 Splunk 里查暴力破解或异常流量，你怎么查？”

安全搜索场景 (SPL)：

- **暴力破解搜索逻辑**

  我们需要统计失败登录（EventCode 常见为 4625）并按用户分组，设定阈值。

  > `index=windows sourcetype=WinEventLog EventCode=4625 | stats count by user | where count > 10`

- **发现异常 IP 访问**

  > `index=firewall action=allowed | stats sum(bytes) as total_traffic by src_ip | sort - total_traffic` (找出流量发送最大的异常 IP)



#### 2. "什么是 CIM，为什么它对安全分析很重要？"

核心在于数据标准化。CIM 就像是“同声传译”。不同设备对“源 IP”的称呼不同（有的叫 `src`，有的叫 `source_ip`）。CIM 将它们统一命名为 `src`。如果没有 CIM，你写一个查攻击的语句要适配几十种设备，有了 CIM，一条语句就能查所有设备。



#### 3. "谈谈你对 Notable Events 的理解。如果你发现了一个 Notable Event，你接下来的排查步骤是什么？"

Notable Event 是多个底层规则被触发后生成的综合安全事件，我会优先根据其 **Urgency（紧急程度）** 和 **Risk Score（风险评分）** 来决定分诊顺序。排查步骤如下：

1. **确定范围：** 查看触发告警的原始日志。
2. **上下文关联：** 搜索该 IP 在过去 24 小时内的所有行为（`src_ip=xxx`）。
3. **横向移动检查：** 看看该账号是否在其他服务器上有登录记录。
4. **情报比对：** 检查该 IP 是否在威胁情报黑名单中。

#### 4. "如何区分 False Positive (误报) 和 True Positive (实报)？"

在 Splunk 中查看 **Context（上下文）**。比如一个 SQL 注入告警，我会通过 Splunk 查看该源 IP 在告警前后的所有行为。如果该 IP 是内部扫描器的，那就是误报；如果是外部未知 IP 且后续有大量数据流出，那就是实报。

#### 5. "请描述一下你平时如何用 Splunk 进行安全调查？"

“在日常的安全运营中，当我在 Splunk ES 监控面板上收到一个关于**‘疑似内部主机横向移动’**的 Notable Event（告警）时：

1. **收集上下文：** 我首先会提取出触发告警的源 IP 和目标 IP。通过 Splunk 的 `lookup` 命令，我快速定位出目标 IP 是一台核心数据库。
2. **编写 SPL 追溯：** 我会使用 SPL 扩大时间窗口，搜索该源 IP 在过去 4 小时内的所有行为日志（`index=* src_ip="异常IP"`）。
3. **发现异常：** 我通过 `stats` 命令统计并发现，该 IP 在短时间内对内网多个网段触发了大量的 `EventCode=4625`（Windows 登录失败）日志。
4. **得出结论与处置：** 结合这些数据，我判断这是一次实质性的内网横向扫描行为，随后将该 IP 提交给网络组进行封禁隔离，并将详细的 Splunk 报表导出作为事故响应（IR）的证据。”



安全术语（结合 Splunk）

**Data Models（数据模型）：** 为了提高搜索速度，安全数据通常会先经过“加速”。面试时提到“数据模型加速（Acceleration）”会显得你很专业。

**Lookups（查找）：** 用来关联外部数据（比如一个包含所有 VIP 员工名单的 CSV 文件），防止漏掉针对高管的攻击。

**Macros（宏）：** 把复杂的搜索逻辑封装成简写，提高响应速度。