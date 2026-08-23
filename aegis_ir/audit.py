"""审计日志：所有关键动作追加写入 JSONL，留档以备应急响应复盘。"""

import json
import os
import time

AUDIT_DIR = os.path.join("var", "logs")
AUDIT_FILE = os.path.join(AUDIT_DIR, "audit.jsonl")


def audit_event(event: str, **fields) -> None:
    try:
        os.makedirs(AUDIT_DIR, exist_ok=True)
        rec = {"ts": time.strftime("%Y-%m-%d %H:%M:%S"), "event": event}
        rec.update(fields)
        with open(AUDIT_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception:
        pass  # 审计失败不阻断主流程
