# restore-protocol · 退出码与 error_class 唯一权威

> 状态:**冻结基线**( / 1.3 的规范化落地)。
> 本文件是退出码表与 error_class 词汇表的**唯一权威文档**。任何消费者
> —— `bag`(代理层)、`restore.sh`(逃生舱)、broker 编排器、遥测解析器 ——
> 必须以本表为准。代码侧的权威实现是 `oss/src/renest/errors.py`;二者由
> `oss/tests/consistency/test_protocol_matches_code.py` 逐码双向锁死:任一
> 侧改动而另一侧没跟,该测试即红。
>
> 既有红线(格式即真相源):改任何一码 = 格式变更,必须升版本号并同步
> 本文件、`errors.py`、`restore.sh`、`bag_lint`。新增失败类只准在**本段码段
> 内**取下一个空闲个位;跨段取号 = 破坏性变更,走版本流程。
>
> **上一句怎么读(2026-07-26 落定,免得每次新增都重新辩论一遍)**:
> "改任何一码"指**改动已有码的含义**——那是破坏性的,要走版本流程。
> **在本段内取下一个空闲个位新增一类,是这条规则明许的非破坏路径**,
> 不升 manifest 格式版本号:manifest schema 一个字节没变,而
> `test_format_version_pinned.py` 那颗绊线比的正是 manifest 版本三处一致
> (`restore.py` / `pack.py` / 升版清单),与错误码无关。
> 新增仍必须做的是**四处同步**(本文件、`errors.py`、`restore.sh`、lint)
> ——由 `test_protocol_matches_code.py` 逐码双向锁死。
> 先例:16 `OBJECT_MISSING`( A4)。

---

## 1. 编码规则(十位 = 段位)

- **前置码 0 / 2 / 3**:"还没进任何一段就死了"的通用码,不属于任何 Sx 段。
- **段内码**:十位数字 = 段位(S1..S5 → 1x..5x,S0 预检 → 6x);个位 =
  段内 error_class 序号;**`x0` 保留给该段的未分类失败(`UNKNOWN`)**。
- `error_class` 字符串 = 退出码常量名去掉 `S?_` 前缀(SCREAMING_SNAKE);
  `UNKNOWN` 为所有段共享的 `x0` 槽,故是 **(段, error_class) 二元组** —— 而
  非单独的 error_class —— 唯一确定一个退出码。
- 命名规范:新增场景必须先进 FAILURE_SCENARIOS,再在本段取空闲个位。
  插件 i18n key = `err.<error_class 小写>`。

## 2. 产生方分层(/)

退出码表**全表共享**,但谁能产生哪些码是分层的:

- 阻断 / 预检语义码 **60 / 61 / 62 / 63 / 64 / 66 仅由代理层产生**
  (`bag doctor` / `bag restore`)。逃生舱 `restore.sh` 无预检分级,不产生。
- `restore.sh` 的 S0 只做磁盘算术,**唯一可退出的 S0 码是 65**(空间不足;
  P1 附录 A 两次实战先例,不在之列)。
- 兼容类比对(袋内声明 vs 本机 `nvidia-smi` 等):`restore.sh` 打单行**告知**
  `RESTORE_NOTICE`(见 §5),不占退出码、恢复照常继续。遥测/编排器解析
  NOTICE 行**不算失败**。

产生方分层是消费纪律,不改码值语义;故本文件的码表对所有产生方是同一张表。

## 3. 前置码(pre-gate)

| code | name | meaning |
|---|---|---|
| 0 | OK | 成功;恢复五段全绿,或命令正常完成 |
| 2 | USAGE | 参数 / 用法错误 |
| 3 | CONFIG_OR_CREDENTIAL | 配置非法、密钥写进了配置文件、凭据缺失 |

前置码无 `stage` / `error_class`,不参与 §4 的 (段, error_class) 映射。
旧 CLI 草案的单数字预检码 6 / 7 已**废除**(),不映射到任何东西。
退出码 **1 永不使用**(2026-07-24 裁,:shell 惯例 1=泛错误,
赋专门语义必与外部工具默认冲突;本表之外的码一律"表外即抛异常,无 fallback"(A1 现状)。

## 4. 段内码表(S0 预检 + S1..S5 五段闸)

逐码:段位、error_class、retryable、产生方、语义。retryable 语义 = 该失败
是否值得原样重试(瞬时网络 / 存储 → true;确定性失败 → false)。

| code | stage | error_class | retryable | producer | meaning |
|---|---|---|---|---|---|
| 60 | S0 | UNKNOWN | no | agent | 预检未分类失败 |
| 61 | S0 | WARNING_UNCONFIRMED | no | agent | doctor 判警告且未确认 / 未 `--force` |
| 62 | S0 | PYTHON_BLOCK | no | agent | Python 主版本阻断 |
| 63 | S0 | CUDA_BLOCK | no | agent | CUDA 大版本阻断 |
| 64 | S0 | ARCH_UNSUPPORTED | no | agent | 目标 sm 超出 torch 编译档(Blackwell 案) |
| 65 | S0 | DISK_INSUFFICIENT | no | agent+restore.sh | 目标盘空间预检不足(唯一 restore.sh 可产生的 S0 码) |
| 66 | S0 | FINGERPRINT_MISSING | no | agent | 包无指纹但用户要求强制预检 |
| 10 | S1 | UNKNOWN | no | agent+restore.sh | 传输获取未分类失败 |
| 11 | S1 | NETWORK_INTERRUPTED | yes | agent+restore.sh | 网络中断;断点续传,已下载不重来 |
| 12 | S1 | RANGE_THROTTLED | yes | agent+restore.sh | Range 请求被限流 / 节流 |
| 13 | S1 | CREDENTIAL_EXPIRED | no | agent+restore.sh | 预签名 / 清单过期,需重新签发 |
| 14 | S1 | STORAGE_UNAVAILABLE | yes | agent+restore.sh | 存储后端不可用(源全挂) |
| 15 | S1 | MANIFEST_UNSUPPORTED | no | agent+restore.sh | manifest 版本不支持 |
| 16 | S1 | OBJECT_MISSING | no | agent+restore.sh | 存储明确回答"没有这个对象":桶里真没有(半发布的包)/ 指错了桶或前缀 / 该钥匙无权看见它 |
| 20 | S2 | UNKNOWN | no | agent+restore.sh | 解包放置未分类失败 |
| 21 | S2 | PATH_CONFLICT | no | agent+restore.sh | 目标路径冲突且未指定模式 |
| 22 | S2 | PERMISSION_DENIED | no | agent+restore.sh | 写权限不足 |
| 23 | S2 | HASH_MISMATCH | no | agent+restore.sh | 文件校验不符(lint / verify 字节层复用此码) |
| 24 | S2 | SYMLINK_BROKEN | no | agent+restore.sh | 硬链接 / 符号链接摆放失败 |
| 25 | S2 | DISK_FULL | no | agent+restore.sh | 中途写满(预检拦下的走 65) |
| 26 | S2 | UNTRUSTED_SETUP | no | agent | **别人递来的包**想跑 `post_install`(manifest 里唯一的自由文本 shell 命令)而收包人未点名发送人;`--trust-sender "<名字>"` 放行,`--no-setup` 跳过。自己打的包不受此闸(只打印原文照跑)。**逃生舱不实现此码**——阻断归代理层,逃生舱只告知(/ 既有红线) |
| 30 | S3 | UNKNOWN | no | agent+restore.sh | 依赖安装未分类失败 |
| 31 | S3 | TORCH_CUDA_CONFLICT | no | agent+restore.sh | torch 与本机 CUDA 不匹配 |
| 32 | S3 | NODE_REQUIREMENTS_FAILED | no | agent+restore.sh | 节点 requirements 安装失败 |
| 33 | S3 | NODE_VERSION_CONFLICT | no | agent+restore.sh | 节点版本冲突 |
| 34 | S3 | PYTHON_MISMATCH | no | agent+restore.sh | Python 版本不匹配 |
| 35 | S3 | SYSLIB_MISSING | no | agent+restore.sh | 系统库缺失 |
| 36 | S3 | MANAGER_INCOMPATIBLE | no | agent+restore.sh | ComfyUI-Manager 不兼容 |
| 37 | S3 | UNTRUSTED_SOURCE | no | agent+restore.sh | 依赖锁里有非白名单主机的下载源(授递包投毒面);`--trust-unsafe-urls` / `TRUST_UNSAFE_URLS=1` 显式越过 |
| 38 | S3 | UPSTREAM_UNREACHABLE | yes | agent | 装依赖时**取不到上游**:包站 / 代码站连不上(断网、代理挡住、镜像源挂了、上游下架)。**这是格式的诚实边界**——模型与源码在包里,Python 依赖是重建时现取的。报错须**指名说出是哪几个域名连不上**;网络恢复后重跑从断点接着装。**逃生舱不产生此码**(它不分类,统一 `exit 1`,守既有红线)。**2026-08-03 断网实测新增**:在此之前这种失败被误判成 31(torch/CUDA 冲突),因为归因只看报错里有没有 `torch` 三个字,而 uv 的网络报错天然带着 `https://pypi.org/simple/torch/` 这样的网址 |
| 40 | S4 | UNKNOWN | no | agent+restore.sh | 启动加载未分类失败 |
| 41 | S4 | NODE_IMPORT_FAILED | no | agent+restore.sh | 节点 import 失败(失败节点单列入日志) |
| 42 | S4 | NODE_NOT_REGISTERED | no | agent+restore.sh | 节点未注册 |
| 43 | S4 | WORKFLOW_PATH_STALE | no | agent+restore.sh | workflow 引用的路径失效 |
| 44 | S4 | STARTUP_CRASH | no | agent+restore.sh | ComfyUI 进程启动即崩(附启动日志尾) |
| 45 | S4 | NEED_USER_DATA | no | agent | 环境重建正确,但这次跑要的**用户数据不在**(:用户数据永不进包)。与"崩了"分开报——环境是好的,缺的是用户自己的东西 |
| 50 | S5 | UNKNOWN | no | agent+restore.sh | 出图验证未分类失败 |
| 51 | S5 | NODE_RUNTIME_ERROR | no | agent+restore.sh | 节点运行时报错 |
| 52 | S5 | OOM_OR_SLOW | no | agent+restore.sh | 显存不足 / 慢到不可用 |
| 53 | S5 | ARCH_UNSUPPORTED_RUNTIME | no | agent+restore.sh | 运行时架构不支持(no kernel image 实锤;与 64 呼应) |
| 54 | S5 | IMAGE_MISMATCH | no | agent+restore.sh | 出图成功但 SSIM 未达阈(默认 0.98,可配) |

五段闸语义:S1 传输获取 → S2 解包放置 → S3 依赖安装 → S4 启动加载 →
S5 出图验证。S0 预检在五段之前,只属代理层(65 除外)。

### 4.9 私有桶为什么总绕不开预签名

13 `CREDENTIAL_EXPIRED` 与 16 `OBJECT_MISSING` 在 BYOS 场景里高频,成因是结构性的:
**逃生舱的依赖清单里没有 openssl(既有红线),所以它算不出 SigV4 签名、不可能自己签链接。**
私有桶的字节只能靠别处签好的预签名 URL —— 有账号的由服务端签(restore-grant),
不注册的用 `renest presign` 在自己有钥匙的机器上签。详见 `specs/restore-grant.md` §4.9。

实测补注(2026-07-26,真 Cloudflare R2):**R2 对缺签名/签名不对的请求回 HTTP 400**,
不是 401/403。归因实现必须把 400 也算进"钥匙/签名不行"这一类(见
`renest.download.classify_source_failures`),否则它会掉进未分类、被当成可重试,
让重试对着一个永远不会成功的签名错反复撞。

## 4.10 `--json` 的两种形状(命令行输出契约)

`--json` 是**全局参数,但两个位置都收** —— `renest --json pack …` 与
`renest pack … --json` 等价。理由很土:后者是任何人都会先敲的那一种。

输出**有两种形状,按命令分**,写脚本的人必须知道是哪一种:

| 命令 | 形状 | 怎么解 |
|---|---|---|
| `doctor` / `lint` / `verify` / `presign` / `list` / `export` | **一个 JSON 文档** | `… --json \| jq .` |
| `pack` / `restore` | **每行一个 JSON 事件**(NDJSON) | 逐行解;**最后一行永远是最终报告** |

为什么不统一:`doctor` 是一次性判定,吐流会让 `jq` 一行命令变麻烦;
`restore` 是长过程,必须边跑边报进度,做不成单文档。两种都有理由,
**没有理由的是"不写清楚"** —— 所以钉在这里,并由
`oss/tests/consistency/test_json_output_shapes.py` 逐命令锁死。

**唯一跨形状的保证**:NDJSON 流的**最后一行**一定是那份最终报告(含 `ok` / `exit_code`)。
脚本要拿结论,取最后一行即可,不必理解中间的事件类型。

## 5. 单行契约(RESTORE_FAIL / RESTORE_NOTICE)

失败裁决行(stderr 最后一行,单行、key=value、无 traceback;完整日志始终
落 `$RESTORE_ROOT/restore.log`):

```
RESTORE_FAIL stage=S3 code=32 reason=node-requirements detail="..."
```

- `stage` ∈ {S0..S5};`code` = 本表退出码;进程退出码 = `code`。
- `reason` = 短横线短语(机器分类用);`detail` = 人读补充,双引号包裹。
- `bag restore` 与 `restore.sh` 用**同一行格式、同一码表**;`bag` 可多报信息
  (NDJSON 事件流、error 对象),但不得改语义。

告知行(不占退出码,恢复继续;兼容类预测由 restore.sh 打出):

```
RESTORE_NOTICE stage=S0 class=ARCH_UNSUPPORTED detail="..."
```

- `class` = 本表 error_class 词汇表中的值(复用同一词汇,不新造)。
- NOTICE 与 FAIL 同款 key=value;遥测 / 编排器解析 NOTICE **不算失败**。

## 6. error 对象(NDJSON / serve job / broker / 遥测四方消费)

`bag --json` 与 serve job 的 error 字段结构(contract 1.3;`type`/`ts` 由
发射器补;实现见 `errors.py` 的 `BagFailure.to_error_object`):

```json
{"type":"error","ts":"…","stage":"S3","error_class":"TORCH_CUDA_CONFLICT",
 "exit_code":31,"retryable":false,"detail":"…","human":"…","context":{"log_file":"…"}}
```

`error_class` 与 `exit_code` 必须是本表中互相对应的一对;`retryable` 由本表
retryable 列决定(即 error_class 属于 {NETWORK_INTERRUPTED, RANGE_THROTTLED,
STORAGE_UNAVAILABLE} 时为 true,其余 false)。
