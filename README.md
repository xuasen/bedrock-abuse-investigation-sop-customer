# Amazon Bedrock 异常调用自查 SOP

> 版本：v1.0 | 日期：2026-05-07  
> 适用场景：发现 Bedrock 调用量异常、费用突增、疑似未授权调用时的排查指南

---

## 免责声明

本文档为通用排查指导，帮助您快速定位 Bedrock 异常调用的原因。如涉及严重安全事件，建议联系 AWS Support 或专业安全团队协助处理。

---

## 一、盗用分类与特征

| 类型 | 典型特征 | 风险等级 |
|------|----------|----------|
| 凭证泄露（长期 Key） | 外部 IP + AKIA 开头 + 调用量暴增 + 7x24 不间断 | 🔴 高 |
| 临时凭证窃取（SSRF/IMDS） | 外部 IP + ASIA 开头 + 来源为 EC2 角色 | 🔴 高 |
| 内部人员滥用 | 公司 IP + 非工作时间 + 调用量缓慢增长 | 🟡 中 |
| 应用层/供应链攻击 | 正常执行环境 + 调用模式突变 | 🟠 中高 |
| 跨账户滥用 | userIdentity 中出现非本组织账户 ID | 🟡 中 |
| 内鬼私建代理 | 内网 IP + 新建未知 EC2/ECS + 对外暴露端口 | 🟡 中 |

### 常见泄露途径

| 途径 | 说明 |
|------|------|
| 代码仓库泄露 | Access Key 硬编码在代码中，推送到 GitHub/GitLab 公开仓库 |
| .env 文件泄露 | 配置文件被意外提交或暴露 |
| CI/CD 日志泄露 | 构建日志中打印了环境变量 |
| EC2 IMDS 被利用 | 实例存在 SSRF 漏洞，攻击者通过 169.254.169.254 获取临时凭证 |
| 第三方服务泄露 | 把 Key 配置在第三方 SaaS 中，该平台被攻破 |
| 员工离职未回收 | 离职人员仍持有有效的长期 Access Key |

---

## 二、排查流程（决策树）

```
发现异常调用
    │
    ▼
┌─ Step 1: 确认数据源 ─────────────────────────────────────────┐
│                                                               │
│  A. CloudTrail 日志（投递到 CloudWatch Logs）                  │
│     → 有 sourceIPAddress, userAgent, userIdentity 等          │
│                                                               │
│  B. Bedrock Model Invocation Log                              │
│     → 日志组: /aws/bedrock/model-invocation                   │
│     → 有 identity.arn, modelId, operation, errorCode          │
│                                                               │
│  ⚠️ 两者字段不同，请确认您查询的是哪个日志组                  │
│  ⚠️ 如果都未启用，请先启用（见第七节）                        │
└───────────────────────────────────────────────────────────────┘
    │
    ▼
┌─ Step 2: 看 sourceIPAddress ─────────────────────────────────┐
│                                                               │
│  外部公网 IP（非贵司出口 IP）→ 转 Step 3A                    │
│  公司出口 IP                 → 转 Step 3B                    │
│  VPC 内网 IP（10.x/172.x）  → 转 Step 3C                    │
└───────────────────────────────────────────────────────────────┘
    │
    ▼
┌─ Step 3A: 外部 IP ───────────────────────────────────────────┐
│                                                               │
│  查 accessKeyId 前缀：                                        │
│                                                               │
│  AKIA（长期 Key）                                             │
│    → 🔴 凭证泄露（GitHub/CI/.env）                            │
│    → 立即禁用 Key → 扫描代码仓库                              │
│                                                               │
│  ASIA（临时凭证）                                             │
│    → 查 userIdentity.type：                                   │
│      - AssumedRole + 本账户角色 → SSRF/IMDS 窃取              │
│      - AssumedRole + 外部账户   → 跨账户滥用                  │
│      - FederatedUser            → SSO 凭证泄露                │
│    → 查源角色的 EC2 是否有 SSRF 漏洞                          │
│    → 查信任策略是否过松                                       │
└───────────────────────────────────────────────────────────────┘
    │
    ▼
┌─ Step 3B: 公司 IP ───────────────────────────────────────────┐
│                                                               │
│  检查：                                                       │
│  1. 调用时间是否在工作时间内？                                │
│  2. 调用量是否与业务匹配？                                    │
│  3. 调用的模型是否为业务所需？                                │
│  4. userAgent 是否为已知应用 SDK？                            │
│                                                               │
│  异常 → 🟡 内部人员滥用                                       │
│  正常 → 可能是合法业务，结束排查                              │
│                                                               │
│  ⚠️ 注意：攻击者通过 VPN 或被入侵的终端也会显示公司 IP       │
│     需结合 userAgent 和调用模式综合判断                        │
└───────────────────────────────────────────────────────────────┘
    │
    ▼
┌─ Step 3C: 内网 IP ───────────────────────────────────────────┐
│                                                               │
│  查调用来自哪个资源：                                         │
│                                                               │
│  已知应用（Lambda/ECS）+ 调用突增                             │
│    → 🟠 应用被注入/供应链攻击                                 │
│    → 检查依赖包、运行时环境变量                               │
│                                                               │
│  未知资源（新建 EC2/ECS）                                     │
│    → 🟡 内鬼私建代理                                          │
│    → 审计 RunInstances/CreateService 记录                     │
└───────────────────────────────────────────────────────────────┘
```

---

## 三、排查命令

### 3.1 全貌查询 — CloudTrail 日志

> 前提：CloudTrail 已投递到 CloudWatch Logs

```
fields @timestamp, sourceIPAddress, userIdentity.arn, userIdentity.accessKeyId,
       userIdentity.type, userAgent, eventName, requestParameters.modelId, errorCode
| filter eventSource = "bedrock.amazonaws.com"
| filter eventName like /InvokeModel/
| stats count(*) as calls,
        dc(sourceIPAddress) as uniqueIPs,
        earliest(@timestamp) as firstSeen,
        latest(@timestamp) as lastSeen
  by userIdentity.accessKeyId, userIdentity.arn, sourceIPAddress, userAgent
| sort calls desc
```

### 3.2 全貌查询 — Bedrock Model Invocation Log

> 日志组：`/aws/bedrock/model-invocation`

```
fields @timestamp, modelId, identity.arn, operation, errorCode, inferenceRegion
| stats count(*) as calls,
        earliest(@timestamp) as firstSeen,
        latest(@timestamp) as lastSeen
  by identity.arn, modelId, operation, errorCode
| sort calls desc
```

### 3.3 按 IP 统计调用来源

```
filter eventSource = "bedrock.amazonaws.com"
| filter eventName like /InvokeModel/
| stats count(*) as calls by sourceIPAddress
| sort calls desc
```

### 3.4 按小时查看调用趋势（发现突增）

```
filter eventSource = "bedrock.amazonaws.com"
| filter eventName like /InvokeModel/
| stats count(*) as calls by bin(1h)
| sort @timestamp desc
```

---

## 四、针对性验证

### 4.1 验证「凭证泄露」

```bash
# 查看 IAM 用户的 Access Key 列表
aws iam list-access-keys --user-name <username>

# 查 Key 最后使用时间和区域
aws iam get-access-key-last-used --access-key-id <AKIA...>

# 生成凭证报告，查看所有用户的 Key 状态
aws iam generate-credential-report
aws iam get-credential-report --query Content --output text | base64 -d

# 立即禁用泄露的 Key
aws iam update-access-key --access-key-id <AKIA...> --status Inactive --user-name <username>

# 扫描代码仓库（使用 trufflehog 或 gitleaks）
trufflehog github --org=<your-org> --only-verified
```

### 4.2 验证「IMDS/SSRF 窃取临时凭证」

```bash
# 查 EC2 实例的 IMDS 配置（HttpTokens=optional 表示 IMDSv1 仍开启）
aws ec2 describe-instances \
  --query 'Reservations[*].Instances[*].{Id:InstanceId,IMDS:MetadataOptions.HttpTokens}' \
  --output table

# 查安全组是否对外暴露 Web 端口
aws ec2 describe-security-groups --group-ids <sg-xxx>

# 强制 IMDSv2（修复）
aws ec2 modify-instance-metadata-options --instance-id <i-xxx> --http-tokens required
```

### 4.3 验证「内部人员滥用」

```
# 查该用户调用了哪些模型
fields requestParameters.modelId
| filter userIdentity.arn = "arn:aws:iam::<account-id>:user/<username>"
| filter eventSource = "bedrock.amazonaws.com"
| stats count(*) by requestParameters.modelId

# 查是否有人修改了网络配置（开后门）
fields @timestamp, userIdentity.arn, eventName
| filter userIdentity.arn = "arn:aws:iam::<account-id>:user/<username>"
| filter eventName in [
    "AuthorizeSecurityGroupIngress",
    "CreateNatGateway",
    "CreateRoute",
    "RunInstances",
    "CreateVpcEndpoint"
  ]
```

### 4.4 验证「应用层/供应链攻击」

```bash
# 查 Lambda 环境变量是否被篡改
aws lambda get-function-configuration --function-name <function-name> \
  --query 'Environment.Variables'

# 检查依赖安全
pip audit          # Python
npm audit          # Node.js

# 查应用角色调用量按小时分布（CloudTrail）
fields @timestamp
| filter userIdentity.arn like /role\/<YourAppRole>/
| filter eventSource = "bedrock.amazonaws.com"
| stats count(*) by bin(1h)
```

### 4.5 验证「跨账户滥用」

```
# 查非本账户的调用
fields userIdentity.accountId, userIdentity.arn
| filter eventSource = "bedrock.amazonaws.com"
| filter userIdentity.accountId != "<your-account-id>"
| stats count(*) by userIdentity.accountId, userIdentity.arn

# 查角色信任策略是否过松
aws iam list-roles \
  --query 'Roles[*].{Name:RoleName,Trust:AssumeRolePolicyDocument}' \
  --output json
```

---

## 五、应急响应流程

| 阶段 | 时间要求 | 动作 |
|------|----------|------|
| **止血** | 5 分钟内 | ① 禁用泄露的 Access Key<br>② 撤销临时凭证（修改角色权限为 Deny All）<br>③ 必要时设置 Bedrock Service Quota 为 0<br>④ 组织级别可用 SCP 限制 Bedrock 调用 |
| **取证** | 1 小时内 | ① 导出 CloudTrail 日志<br>② 导出 Bedrock Model Invocation Log<br>③ 记录异常 IP、时间范围、调用量<br>④ 截图保存关键证据 |
| **根因分析** | 4 小时内 | ① 按决策树定位盗用类型<br>② 确认影响范围（模型、调用量、费用）<br>③ 确认是否有数据泄露风险 |
| **修复** | 24 小时内 | ① 轮换所有可能泄露的凭证<br>② 修复漏洞（SSRF/依赖/权限）<br>③ 强制 IMDSv2<br>④ 收紧 IAM 策略（最小权限） |
| **加固** | 1 周内 | ① 启用 Bedrock 调用日志<br>② 配置 CloudWatch 告警<br>③ 配置 AWS Budgets 费用告警<br>④ 启用 GuardDuty<br>⑤ 使用 VPC Endpoint 限制调用来源<br>⑥ 定期审计 Key 和信任策略 |

### 止血命令参考

```bash
# 禁用 Access Key
aws iam update-access-key --access-key-id <AKIA...> --status Inactive --user-name <username>

# 给角色附加 Deny All 策略（撤销临时凭证的权限）
aws iam put-role-policy --role-name <role-name> \
  --policy-name DenyAll \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}'

# 设置 Bedrock 配额为 0（紧急情况）
aws service-quotas request-service-quota-increase \
  --service-code bedrock \
  --quota-code <quota-code> \
  --desired-value 0
```

---

## 六、预防措施清单

| 优先级 | 措施 | 防御场景 |
|--------|------|----------|
| **P0** | 禁止长期 Access Key，使用 IAM Role | 凭证泄露 |
| **P0** | 启用 GitHub/GitLab Secret Scanning | 代码仓库泄露 |
| **P0** | 强制 IMDSv2（所有 EC2 实例） | SSRF 窃取凭证 |
| **P0** | 配置 Bedrock 调用量 CloudWatch 告警 | 所有类型 |
| **P0** | 配置 AWS Budgets 费用告警 | 所有类型 |
| **P1** | 使用 VPC Endpoint + 安全组限制调用来源 | 外部调用、内鬼代理 |
| **P1** | 启用 GuardDuty | 异常 API 调用检测 |
| **P1** | 最小权限 IAM 策略 | 内部滥用、跨账户 |
| **P1** | SCP 限制非必要区域的 Bedrock 访问 | 所有类型 |
| **P1** | 启用 Bedrock Model Invocation Logging | 取证需要 |
| **P2** | 定期轮换凭证 + 审计未使用的 Key | 凭证泄露 |
| **P2** | 依赖包安全扫描（CI 集成） | 供应链攻击 |

---

## 七、前置条件：启用必要的日志

### 7.1 启用 CloudTrail（如未启用）

CloudTrail 默认记录管理事件，但需要创建 Trail 才能投递到 CloudWatch Logs 或 S3 进行查询。

```bash
# 创建 Trail 并投递到 S3
aws cloudtrail create-trail \
  --name bedrock-audit-trail \
  --s3-bucket-name <your-log-bucket> \
  --is-multi-region-trail

aws cloudtrail start-logging --name bedrock-audit-trail
```

### 7.2 启用 Bedrock Model Invocation Logging

在 AWS Console 中：
1. 进入 Amazon Bedrock → Settings → Model invocation logging
2. 选择 CloudWatch Logs 作为目标
3. 日志组会自动创建为 `/aws/bedrock/model-invocation`

或通过 CLI：
```bash
aws bedrock put-model-invocation-logging-configuration \
  --logging-config '{
    "cloudWatchConfig": {
      "logGroupName": "/aws/bedrock/model-invocation",
      "roleArn": "arn:aws:iam::<account-id>:role/<logging-role>"
    },
    "textDataDeliveryEnabled": true,
    "imageDataDeliveryEnabled": false,
    "embeddingDataDeliveryEnabled": false
  }'
```

---

## 八、快速判断口诀

> **先看 IP，再看 Key 类型，最后看调用模式。90% 的情况 30 秒内能定性。**

| 现象 | 定性 | 立即动作 |
|------|------|----------|
| 外部 IP + AKIA | 长期 Key 泄露 | 禁用 Key → 扫仓库 |
| 外部 IP + ASIA + 本账户角色 | SSRF/IMDS 窃取 | 查实例漏洞 → 强制 IMDSv2 |
| 外部 IP + ASIA + 外部账户 | 跨账户滥用 | 收紧信任策略 |
| 公司 IP + 非工作时间 + 大量调用 | 内部人员转卖 | 锁定人员 → 审计操作历史 |
| 正常应用角色 + 调用量突增 | 应用被注入 | 检查依赖 → 查运行时 |
| 内网 IP + 新建 EC2 | 内鬼建代理 | 审计资源创建记录 |

---

## 九、参考资料

- [Amazon Bedrock 安全最佳实践](https://docs.aws.amazon.com/bedrock/latest/userguide/security-best-practices.html)
- [AWS CloudTrail 用户指南](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/)
- [Amazon GuardDuty 用户指南](https://docs.aws.amazon.com/guardduty/latest/ug/)
- [IAM 最佳实践](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [EC2 实例元数据服务 (IMDS) 安全](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html)
- [AWS Security Hub](https://docs.aws.amazon.com/securityhub/latest/userguide/)

---

*如有疑问或需要进一步协助，请联系 AWS 技术支持或您的客户团队。*
