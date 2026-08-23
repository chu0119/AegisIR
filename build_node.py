"""构建跨平台节点包 aegis-node.pyz。

zipapp（Python 标准库）把 aegis_ir + scapy 打成单个自包含文件：
- 任何装有 Python 3.9+ 的机器零安装直接运行（Linux/macOS/Windows）
- Linux 下带 shebang，chmod +x 后可直接 ./aegis-node.pyz
- scapy 纯 Python，Linux root 即完整 raw 引擎（无需 Npcap）

用法: python build_node.py [--out dist/aegis-node.pyz]
"""

import argparse
import os
import shutil
import sys
import tempfile
import zipapp


def build(out_path):
    import scapy

    here = os.path.dirname(os.path.abspath(__file__))
    scapy_dir = os.path.dirname(scapy.__file__)
    stage = tempfile.mkdtemp(prefix="aegis-node-")
    try:
        # 1) 拷贝 aegis_ir 与 scapy（剔除缓存）
        for src, dst in ((os.path.join(here, "aegis_ir"), os.path.join(stage, "aegis_ir")),
                         (scapy_dir, os.path.join(stage, "scapy"))):
            shutil.copytree(src, dst, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "tests"))

        # 2) 入口：无参数默认桌面窗口；也支持子命令透传
        main = os.path.join(stage, "__main__.py")
        with open(main, "w", encoding="utf-8") as f:
            f.write("from aegis_ir.cli import main\n\nif __name__ == '__main__':\n    main()\n")

        os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
        zipapp.create_archive(
            stage, out_path,
            interpreter="/usr/bin/env python3",  # Unix shebang；Windows 用 python xx.pyz
            compressed=True,
        )
        size_mb = os.path.getsize(out_path) / 1048576
        print(f"[+] 已生成 {out_path}（{size_mb:.1f} MB）")
        print("[*] Linux 节点运行:  python3 aegis-node.pyz gui --listen any --token <令牌>")
        print("[*] Windows 节点运行: python aegis-node.pyz gui --listen any --token <令牌>")
        return out_path
    finally:
        shutil.rmtree(stage, ignore_errors=True)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join("dist", "aegis-node.pyz"))
    build(ap.parse_args().out)
