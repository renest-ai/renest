# serve-api · 本机 HTTP 接口面(插件生态的唯一契约)

> 状态:**v1 成文**(2026-07-18,依 与既有实现固化;实现权威 `oss/src/renest/serve.py`,
> 行为测试 `oss/tests/unit/test_serve.py`)。
> 2026-07-23 改名批次(命名空间铁规:工具面=renest、资产面=nest;,
> 不留旧名兼容):env `BAG_TOKEN_FILE`→`RENEST_TOKEN_FILE`、token 路径 `bag`→`renest`、
> `GET /bags`→`GET /nests`、restore 参数 `bag_ref`→`nest_ref`。本文件已按新名全文更新。
> 本文件是 `renest serve` HTTP 面的**唯一权威文档**。任何消费者——桌面客户端、
> ComfyUI 插件、工作流工具——必须以本表为准,不以源码内部结构为准。
> 格式纪律(既有红线 精神):任何字段/路径/语义变更 = 契约变更,必须在本文件留痕;
> 破坏性变更必须升 `/api/v2` 并保留 v1 到弃用期结束。

---

## 1. 定位与边界

- **只回环**:监听 `127.0.0.1:7799`(`DEFAULT_HOST` 永不绑可路由地址)。
- **职责**:本机的落袋/复活作业队列 + 本地资产包登记簿。`GET /nests` 绝不查桶——
  serve 是"本机的手",云端事实归 SaaS API。
- **凭证红线**(既有红线):任何云凭证/桶密钥不过 HTTP,即便回环。凭证由宿主
  (桌面端/CLI 配置)持有,serve 只见 job 参数里的引用(路径/授递文件)。
- **GPL 隔离**(既有红线):插件跑在 ComfyUI 进程内,只准隔着本接口调用;
  进程边界即协议边界,严禁 import 本包代码进 GPL 侧。

## 2. 鉴权:token 文件契约

- 除 `GET /health` 外一律 `Authorization: Bearer <token>`;失败 `401`。
- **token 路径契约**:`~/.config/renest/serve.token`(0600),env `RENEST_TOKEN_FILE` 覆盖。
  serve 写、桥读;每请求惰性重读——轮换 token 不必重启 ComfyUI。
  勘误(2026-07-19 真机验收发现;Windows 落点经读 platformdirs 源核实):
  实现用 platformdirs,**macOS 实际落点 `~/Library/Application Support/renest/serve.token`**;
  **Windows 实际落点 `%LOCALAPPDATA%\renest\renest\serve.token`**——注意双层 `renest\renest`
  (platformdirs 无 appauthor 时以 appname 兼任 author 目录)。消费者应按
  env → `~/.config/renest/` → 平台目录逐级探测(comfyui-renest 参考实现);
  Windows 未实机验证,标 [待验证]。
  (2026-07-23 改名批次已落地此更名;,旧名 `BAG_TOKEN_FILE`/
  `~/.config/bag/` 不保留弃用期,消费者与 CLI 同批切换。)
- token 比对恒时(`hmac.compare_digest`);`/health` 永不因凭证探测而崩。

## 3. CORS(2026-07-18 加入)

浏览器侧插件(ComfyUI 前端 JS)需要跨端口调用,故:

- **白名单 = 本机回环源**:`Origin` 匹配 `^https?://(127.0.0.1|localhost)(:端口)?$`
  时逐源回显 `Access-Control-Allow-Origin`(带 `Vary: Origin`);其余源不回任何
  CORS 头(浏览器自行拦截)。**绝不通配 `*`**——本接口带 Authorization。
- 预检:`OPTIONS <任意路径>` → `204`,允许 `GET, POST, DELETE, OPTIONS` 与
  `Authorization, Content-Type`,`Max-Age 600`。预检不鉴权(浏览器预检不带凭证)。
- 注意:CORS 不是安全边界(本机任意进程本就可直连回环);安全边界是 Bearer token。
  插件的 JS 侧 token 由其 Python 侧读 token 文件后注入,JS 不落盘。

## 4. 端点(六个,前缀 `/api/v1`)

| 方法/路径 | 鉴权 | 语义 | 主要响应 |
|---|---|---|---|
| `GET /health` | 无 | 存活/版本/存储配置形态 | `200` 健康对象 |
| `POST /pack` | 有 | 落袋作业;body 收 `spec` **或** `workflow` 二选一(`workflow`=target-only 反推;插件桥 B2 消费,2026-07-24 收编进契约文本);可选 `out`=包落在本机哪个文件夹(见 §4.1);`{"dry_run":true}` 时**同步**回清单预览(确认单数据源) | `202 {job_id}` / dry-run `200` / 参数错 `400` / 队满 `429` |
| `POST /restore` | 有 | 复活作业(`nest_ref`+`target` 必填) | 同上 |
| `GET /jobs/{id}` | 有 | 作业状态:`state` + FC-3 口径 `progress` + `logs_tail` | `200` / `404` |
| `DELETE /jobs/{id}` | 有 | 协作取消(排队即撤;运行中置取消旗,五段闸在段界响应) | `200 state=cancelled` / `404` |
| `GET /nests` | 有 | 本地登记簿(本机产/收过的资产包;**绝不查桶**) | `200 {nests:[…]}` |

### 4.1 落袋的落点与确认单(2026-08-02 补,只加字段不改旧字段)

来历:同日按面板的真实请求顺序跑了一次真引擎回归(测试
`oss/tests/consistency/test_comfyui_plugin_contract.py`),抓出四处消费者用得着、
而契约面此前不给的东西。四处都是**新增字段**,v1 兼容承诺不破。

- **`POST /pack` 的 `out`**:包落在本机哪个文件夹,与命令行 `--out` 同义。
  留空时的默认落点 = **被打包的那套环境旁边**,即 `<环境目录>/renest-nests/`;
  目标看着就是 ComfyUI 本体(里面有 `main.py` 与 `custom_nodes/`)时取它的上一层;
  该处写不进去就退到本用户数据目录。**旧行为是每次现开一个系统临时目录**
  (`/tmp` 或 `/var/folders`),包会被系统清掉且无处可查 —— 已废止。
  (`dest` 是同义的老名字,与命令行 `--dest`「传去哪个云」重名易混,不再新用,仍认。)
- **`POST /pack` 的 `env_python` 与 `comfyui_dir`**(2026-08-03 补):环境的真实形状由
  **跑在应用进程里的消费者**告知,引擎不猜。`env_python` = 正在跑这套环境的解释器
  (环境里没有锁文件时,依赖清单向它现读 —— ComfyUI 桌面版就没有任何锁文件,
  实测从中读到 135 个包);`comfyui_dir` = 应用本体源码目录(与数据目录不是一处时才需要送)。
  两者都可选,不送则维持旧行为。**注意**:`comfyui_dir` 会连带决定去哪棵树里找
  自定义节点与模型 —— 桌面版那种"程序与数据分家"的布局现在**先别送**,
  两棵树一起搬见 内部欠账清单。
- **dry-run 预览新增 `warnings`**:capture 抓不住的东西(最常见:装的时候直接解压、
  没有来路的自定义节点,按纪律不猜、不进包)的原话清单。消费者**必须**把它显示出来 ——
  确认单只报好消息,等于让用户拿着一份看着齐全的清单去重建。
- **dry-run 预览新增 `out_dir`**:这次落袋会把包放在哪(同上默认规则),
  让人在按下确认之前就知道东西会去哪儿。预览不写任何字节,也不建这个目录。
- **清单条目自带身份**:`items.nodes[]` 每条带 `dep_role`(`host` = 应用本体 /
  `extension` = 装进去的节点 / `user_code` = 用户自己的代码)与 `path`;
  `items.deps[]` 每条带 `path`。旧版这两类条目只有名字或只有哈希,
  消费者要么显示成问号,要么把 ComfyUI 本体也数进"自定义节点"。
- **`GET /nests` 每条新增 `path`**:包在本机的落点(目录)。
  本机登记簿此前答不上"我的包在哪"这个最基本的问题。
- **打包作业现在发分段与进度**:`stage_start`(P1 搬字节 → P2 写清单 →
  P3 传云(有传才发) → P4 对账)与 `progress`(FC-3 五字段,分母来自开工前
  stat 一遍要搬的文件)。此前打包**一个进度事件都不发**,`stage` 恒为 P1、
  `percent` 恒为 0,界面上是一根一动不动的进度条。恢复(restore)侧本就在发,不受影响。

作业事件与进度字段 = **FC-3 冻结契约**(六种事件/进度五字段/错误七字段),
正典见 `specs/restore-protocol.md` 与 `oss/src/renest/events.py`;`state` 机:
`queued → running → succeeded | failed | cancelled | interrupted`(serve 重启时
在飞作业标 `interrupted`,可重投)。队列上限 `MAX_QUEUE`,超出 `429`。

## 5. 兼容承诺(生态押注的底)

1. `/api/v1` 内**只加不改不删**:新增端点/新增可选字段随时;改语义/删字段/改必填 = 破坏性,升 v2。
2. 错误码与事件契约随 restore-protocol 冻结纪律走,serve 不自造词汇。
3. 弃用节奏:v2 上线后 v1 至少并行两个发布周期,`/health` 里会同时报两版可用性。
4. 本文件与实现漂移视为 bug:发现即修文档或修代码,不允许"以实现为准"含糊过去。

## 6. 插件作者最小接入(参考)

```
TOKEN=$(cat "${RENEST_TOKEN_FILE:-$HOME/.config/renest/serve.token}")
curl -s http://127.0.0.1:7799/api/v1/health                      # 探活(无鉴权)
curl -s -H "Authorization: Bearer $TOKEN" \
     -X POST http://127.0.0.1:7799/api/v1/pack \
     -H 'Content-Type: application/json' \
     -d '{"dry_run": true, "spec": {…}}'                          # 落袋预览(同步)
```

浏览器 JS 同语义(fetch + Bearer 头),CORS 见 §3。官方 ComfyUI 节点(规划中,
独立仓 renest-comfyui,GPL 兼容协议)将以本文件为唯一依赖面。
