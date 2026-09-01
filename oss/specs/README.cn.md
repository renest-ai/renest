# specs · Renest 开放格式规范

> **格式先于实现,格式即真相源。** 三端(pod 代理、服务端、桌面客户端)
> 与逃生舱 `restore.sh` 都是本规范的**消费者**。任何格式变更必须升版本号,
> 并同步本目录、`restore.sh` 与 `renest lint`。
>
> 逃生舱只依赖 `curl`、`jq`、`sha256sum`、`tar`、`uv`,不依赖本项目任何
> 其他代码就能完整重建一个资产包。"外人不用我们一行代码,照文档能实现
> 读写"是本目录的验收标准,不是口号。

## 版本索引

| 组件 | 版本 | 状态 | 文档 |
|---|---|---|---|
| manifest 格式 | 2.9 | **当前版本** | [`manifest.md`](manifest.md) + [`manifest.schema.json`](manifest.schema.json) |
| 退出码 / `error_class` | — | 冻结基线 | [`restore-protocol.md`](restore-protocol.md) |

本目录每份文档都有一份中文对照本与它并排,文件名为 `*.cn.md`。不带后缀的
那个名字是英文正本,`.cn.md` 是译本。两份有出入时,以英文那份为准。

## 阅读顺序

1. **[`manifest.md`](manifest.md)** —— 资产包清单的逐字段语义。形状权威在
   `manifest.schema.json`(JSON Schema draft 2020-12,CI 与 `renest lint`
   直接消费),语义权威在 `manifest.md`。二者在同一次改动里一起维护。
2. **[`restore-protocol.md`](restore-protocol.md)** —— 退出码表与 `error_class`
   词汇表的**唯一权威**。前置码 0/2/3、S0 预检(60–67)、S1..S5 五段闸
   (10–59),逐码列出名字、是否值得重试、谁能产生、什么含义;外加
   `RESTORE_FAIL` / `RESTORE_NOTICE` 单行契约。代码侧权威实现是
   `../src/renest/errors.py`,二者由
   `../tests/consistency/test_protocol_matches_code.py` 逐码锁死。
3. **[`examples/`](examples/)** —— 跑过真机的样例:三个 `*.nest.json`
   (最简 SDXL 资产包、一个视频生成资产包、一个演示外部 API 调用诚实边界的),
   外加一个 `*.pack-spec.json` 打包模板。
   样例**有意停在较老的小版本**:它们同时充当"老包在新读者上照读不误"的活证据。
   `crossver-v1.1-draft.nest.json` **只作历史存照**:2.0 断了 1.x 读兼容,
   它现在的用途是钉住"旧包必须被明确拒绝、报的是版本不支持而不是崩在别处"
   (见 `../tests/unit/test_lint.py`)。**不要照它写新包。**
4. **[`conformance/`](conformance/)** —— golden(必须通过)与 invalid(必须失败)
   两类 fixtures;见该目录的 README。
5. **[`escape-hatch-versions.md`](escape-hatch-versions.md)** —— `restore.sh`
   出过的每一版,按脚本自身的 sha256 登记,附它是为哪一版资产包格式写的、
   以及后来在它身上发现的问题。从格式 2.3 起,每个资产包里都带一份脚本副本,
   落在 `.renest/escape/restore.sh` 并在那里冻结,所以这张表是判断"手里这份
   是哪一版"的唯一途径。机器可读的孪生表:
   [`escape-hatch-versions.json`](escape-hatch-versions.json)。

## 目录布局

```
specs/
├── README.md                   # 本文件:导览 + 版本索引
├── manifest.md                 # manifest 逐字段语义
├── manifest.schema.json        # manifest JSON Schema(形状权威)
├── restore-protocol.md         # 退出码与 error_class,唯一权威
├── serve-api.md                # 本机 HTTP 接口面
├── escape-hatch-versions.md    # restore.sh 出过的每一版,按 sha256 登记
├── escape-hatch-versions.json  # 同一张表,机器可读
├── examples/                   # 验证过的 nest / pack-spec 样例
└── conformance/                # golden 与 invalid fixtures
    ├── golden/
    └── invalid/
```

> 本目录是公开发布的。它按"这里面的东西全部对外"的卫生标准维护:
> 不落密钥,不落内部商业信息。
