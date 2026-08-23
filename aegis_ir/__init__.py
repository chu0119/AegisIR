"""AegisIR - 应急响应网络隔离工具（仅限授权内网使用）。"""

import logging

# 抑制 scapy 运行时告警（如 L3 发包回退广播 MAC 的提示），
# 环境问题由 doctor 子命令集中呈现
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

__version__ = "2.3.0"
