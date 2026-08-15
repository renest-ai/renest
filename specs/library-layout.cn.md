# 本地资产库布局规范 v2(P3 客户端的主本;与盘内格式无损互转)

> v2(2026-07-23,改名批次 bag→nest):资产包目录层由 bag 复数旧名改为 `nests/`,与盘内格式 v1.2 同步;结构不变,纯改名。

    MyRenestLibrary/
    ├── nests/<nest-id>/manifest.json    # 与盘内 nests/ 完全同构
    ├── blobs/sha256/<前2位>/<hash>      # 内容寻址,与盘内 blobs/ 完全同构
    ├── workspace/                        # 未落袋的散装区
    │   ├── workflows/   素材workflow草稿
    │   ├── inputs/      垫图参考图
    │   └── prompts/     提示词库
    └── outputs/<nest-id>/                # 成品回流区,按来源 nest 归档

规则:nests+blobs 两层与云端盘同构 ⇒ 上传/下载是纯拷贝,无格式转换,无同步引擎。
