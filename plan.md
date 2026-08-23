# AegisIR v2.0 实施计划

依据 design.md，任务分解（每项含验证方式）：

| # | 任务 | 文件 | 验证 |
|---|---|---|---|
| 1 | netutils：网卡列表/按网卡网关网段/系统 ping/create_connection 探测/nbtstat 主机名/ARP 表解析纯函数化 | netutils.py | 单测 T1 |
| 2 | discovery：双引擎重构（raw=现有 scapy；compat=ping+arp差分+tcp辅助），discover(engine, iface) 编排 | discovery.py | 单测 T2 + 本机实测扫出主机 |
| 3 | isolation：prepare_isolation/Isolator 支持 iface 上下文 | isolation.py | 单测 T3 |
| 4 | server：/api/interfaces、/api/probe、scan/isolate 透传 iface/engine、doctor 增 engine | server.py | curl 验证 |
| 5 | CLI：scan --engine/--iface、isolate --iface、interfaces 增强 | cli.py | --help 与 dry-run |
| 6 | 单元测试套件（免权限可跑） | tests/ | python -m unittest 全绿 |
| 7 | 本机实测：compat 引擎扫 /26 真实发现主机 | - | 命中数 > 0 |
| 8 | Web UI 重写：侧边栏四视图 + 新视觉 + 弹窗可达性预检 | web/ | Playwright 截图四视图 |
| 9 | review.md、重打包 exe、README 更新 | - | exe doctor 通过 |

执行顺序 1→9，1-5 为后端串行（接口互相依赖），8 依赖 4 的 API 定型。
