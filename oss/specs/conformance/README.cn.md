# conformance · 一致性 fixtures

> 状态:**占位骨架。** 本目录的 fixtures 还没填,今天有的只是目录结构与本说明。

`conformance/` 是规范的**一部分**,不是测试套的附属品。早期真机实测换来的一条
教训:往返测试全绿是虚假安全感,因为假环境在结构上就够不到真正的 bug。
所以坏样本必须是**一个在旧代码上真会失败的实包**,绝不能是 mock。

## 目录布局

```
conformance/
├── README.md      # 本文件
├── golden/        # 合法样例:一个迷你 golden 资产包(数 MB 的替身模型,结构与真包同构)
└── invalid/       # 坏样本:每条 lint error 规则至少一个"必须失败"的资产包
```

## 还没交付什么

- **`golden/`**:一个迷你 golden 资产包 —— 结构与真包同构,替身模型只有几 MB ——
  过 `renest lint` 全量校验全绿,且能由生成脚本确定性重建(逐字节稳定)。
- **`invalid/`**:每条现有的 `renest lint` error 规则配一个必红坏样本,使 lint 变红
  **且规则号与预期一致**。规则 ↔ 坏样本 ↔ specs 里的 MUST 三者在同一次改动里维护:
  specs 里每条 MUST 都至少对应一条 lint 规则和一个 conformance 坏样本。
- **`README.md`(将来替换掉本文件)**:样本清单,以及每个样本考核的是哪条规则。

## 权威引用

fixtures 的形状:[`../manifest.schema.json`](../manifest.schema.json)。
退出码与校验语义:[`../restore-protocol.md`](../restore-protocol.md)。
已跑通的样例:[`../examples/`](../examples/)。
