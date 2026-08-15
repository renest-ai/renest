# specs · Renest 开放格式规范

> 既有红线:**格式先于实现,格式即真相源**。三端(pod 代理、服务端、桌面)
> 与逃生舱 `restore.sh` 都是这部宪法的**消费者**;任何格式变更必须升版本号
> 并同步本目录、`restore.sh`、`bag_lint`。
>
> 既有红线:逃生舱 `restore.sh` 只依赖 `curl/jq/sha256sum/git/uv`,不依赖本项目
> 任何其他代码就能完整重建一个资产包。"外人不用我们一行代码,照文档能
> 实现读写"是本目录的验收标准,不是口号。

## 版本索引

| 组件 | 版本 | 状态 | 文档 |
|---|---|---|---|
| manifest 格式 | v1 | **冻结**(2026-07-14,早期真机实测 第二跑) | [`manifest.md`](manifest.md) + [`manifest.schema.json`](manifest.schema.json) |
| 退出码 / error_class | — | 冻结基线 | [`restore-protocol.md`](restore-protocol.md) |

## 阅读顺序

1. **[`manifest.md`](manifest.md)** —— 资产包(bag)清单 v1 的逐字段语义规范。
   形状权威在 `manifest.schema.json`(JSON Schema draft 2020-12,CI 与
   `bag_lint` 直接消费),语义权威在 `manifest.md`。二者同 PR 维护。
2. **[`restore-protocol.md`](restore-protocol.md)** —— 退出码表与 error_class
   词汇表的**唯一权威**。0/2/3 前置码 + S0 预检(60–66)+ S1..S5 五段闸
   (10–59),逐码列名 + retryable + 产生方 + 语义;RESTORE_FAIL /
   RESTORE_NOTICE 单行契约(key=value)。代码侧权威 = `../src/renest/errors.py`,
   二者由 `../tests/consistency/test_protocol_matches_code.py` 逐码锁死。
3. **[`examples/`](examples/)** —— 实战验证过的样例:三个 `*.nest.json`
   (最简 SDXL / Wan i2v / API 转发诚实边界)+ 一个 `*.pack-spec.json` 落袋模板,
   均已随 2.0 迁移(`format_version: "2.0"` + `code_deps[].role`)。
   **当前格式版本是 2.1** 增 `entrypoint.success.expect_artifact`,纯增量);
   样例**有意仍停在 2.0** —— 它们同时充当"2.0 的包在 2.1 读者上照读不误"的活证据。
   `crossver-v1.1-draft.nest.json` **只作历史存照**:2.0 断了 1.x 读兼容
   ,它现在的用途是钉住"旧包必须被明确拒绝、报的是版本不支持而不是
   崩在别处",见 `../tests/unit/test_lint.py`。**不要照它写新包。**
4. **[`conformance/`](conformance/)** —— golden(合法)与 invalid(必红)fixtures,
   后续工作 填充(见该目录 README)。

## 目录布局

```
specs/
├── README.md               # 本文件:导览 + 版本索引
├── manifest.md             # manifest v2.0 语义规范
├── manifest.schema.json    # manifest v2.0 JSON Schema(形状权威)
├── FORMAT-CHANGE-CHECKLIST.md  # 升版必做八步(绊线测试盯着它)
├── restore-protocol.md     # 退出码 + error_class 唯一权威
└── examples/               # 验证过的 nest / pack-spec 样例
└── conformance/            # golden + invalid fixtures(后续工作 填充)
    ├── golden/
    └── invalid/
```

> 本目录是"未来开源主仓"的一部分,按"内容将来全部公开"的卫生标准维护
> (不落密钥、不落商业信息)。
