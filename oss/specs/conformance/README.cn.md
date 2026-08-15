# conformance · 一致性 fixtures(占位,后续工作 填充)

> 状态:**占位骨架**。本目录的 fixtures 后续工作
> 填充。后续工作 只建目录结构与本说明。

conformance/ 是规范的**一部分**,不是测试的附属品。早期真机实测 教训:"往返测试全绿
是虚假安全感,假环境测试结构性测不到真 bug"。故坏样本必须是"在旧代码上
真能失败"的**实包**,不是 mock。

## 目录

```
conformance/
├── README.md      # 本文件
├── golden/        # 合法样例:mini golden bag(数 MB 假模型,结构与真包同构)
└── invalid/       # 坏样本:每条 lint error 规则至少一个"必须红"的包
```

## 后续工作 将交付什么

- **`golden/`**:mini golden bag(结构同构真包,数 MB 假模型),过 `bag_lint`
  L2 全量校验全绿;可由生成脚本确定性重建(字节稳定)。
- **`invalid/`**:每条现有 `bag_lint` error 规则一个必红坏样本,使 lint 红且
  **规则号匹配预期**。规则 ↔ 坏样本 ↔ specs 里的 MUST 三者同 PR 维护
  (specs 里每条 MUST 至少对应一条 lint 规则 + 一个 conformance 坏样本)。
- **`README.md`(后续工作 覆盖本文件)**:样本清单 + 每个样本考核哪条规则。

## 权威引用

fixtures 的形状权威 = [`../manifest.schema.json`](../manifest.schema.json);
退出码 / 校验语义权威 = [`../restore-protocol.md`](../restore-protocol.md)。
样例参考 = [`../examples/`](../examples/)(早期真机实测 实战 bag)。
