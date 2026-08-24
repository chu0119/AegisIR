"""内置 Web 控制台服务。

- 纯 Python 标准库实现（http.server），无第三方依赖，适合 U 盘应急部署
- 默认只监听 127.0.0.1；作为跨网段节点远程使用时 --listen any 并强制 --token
- 前端为 aegis_ir/web/ 下的静态文件，轮询 JSON API 刷新状态
"""

import json
import os
import platform
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import discovery
from .audit import AUDIT_FILE, audit_event
from .isolation import (DEFAULT_FAKE_MAC, IsolationError, IsolationManager,
                        Isolator, find_session, list_sessions,
                        prepare_isolation, restore_from_file)
from .netutils import get_route, is_admin, onlink_network, resolve_mac

WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")
TOKEN = None  # 对外监听时必须设置
_BIND_HOST = "127.0.0.1"

manager = IsolationManager()
_scan_state = {
    "running": False, "stage": "", "progress": [0, 0],
    "error": None, "finished": None, "result": None,
}
_scan_lock = threading.Lock()


# ---------------------------------------------------------------- 部署下发
def _find_artifact(name):
    """定位待下发的构建产物（node.pyz / AegisIR.exe）。"""
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = []
    try:
        candidates.append(os.path.dirname(os.path.abspath(sys.executable)))  # 打包后 exe 旁
    except Exception:
        pass
    candidates += [os.getcwd(), here, os.path.dirname(here)]
    dirs = []
    for base in candidates:
        dirs += [base, os.path.join(base, "dist")]
    for d in dirs:
        p = os.path.join(d, name)
        if os.path.isfile(p):
            return p
    return None


def _gen_install_sh(token, host, port):
    return f"""#!/bin/sh
# AegisIR 节点一键部署（Linux，由控制台生成）
set -e
TOKEN="{token}"
BASE="http://{host}:{port}"
echo "==> AegisIR 节点部署开始"
if ! command -v python3 >/dev/null 2>&1; then
  echo "==> 未找到 python3，尝试通过包管理器安装"
  (apt-get update -qq && apt-get install -y -qq python3) 2>/dev/null \\
    || (yum install -y -q python3) 2>/dev/null \\
    || (apk add --no-cache python3) 2>/dev/null || true
fi
command -v python3 >/dev/null 2>&1 || {{ echo "[x] 需要 python3，请手动安装后重试"; exit 1; }}
TMP="$(mktemp -d)"
curl -fsSL "$BASE/deploy/node.pyz" -o "$TMP/aegis-node.pyz" 2>/dev/null \\
  || wget -q "$BASE/deploy/node.pyz" -O "$TMP/aegis-node.pyz"
[ -s "$TMP/aegis-node.pyz" ] || {{ echo "[x] 下载节点包失败，请确认控制台对本机可达"; exit 1; }}
echo "==> 节点启动中（保持本窗口运行；Ctrl+C 退出）"
echo "==> 控制台接入地址: http://{host}:{port}  令牌: {token}"
exec python3 "$TMP/aegis-node.pyz" gui --listen any --token "$TOKEN" --no-browser
"""


def _gen_install_ps1(token, host, port):
    return f"""# AegisIR 节点一键部署（Windows，需管理员 PowerShell，由控制台生成）
$ErrorActionPreference = 'Stop'
$token = '{token}'; $base = 'http://{host}:{port}'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('Administrator')) {{
  Write-Host '[x] 请以管理员身份运行 PowerShell 后重试' -ForegroundColor Red; exit 1
}}
$exe = Join-Path $PWD 'AegisIR.exe'
Write-Host '==> 下载 AegisIR.exe ...'
Invoke-WebRequest -UseBasicParsing "$base/deploy/AegisIR.exe" -OutFile $exe
if (-not (Test-Path "$env:SystemRoot\\System32\\Npcap\\wpcap.dll")) {{
  Write-Warning '未检测到 Npcap：探测将使用免权限兼容引擎；隔离/恢复需安装 Npcap (https://npcap.com)'
}}
Write-Host "==> 节点启动（保持本窗口运行）  控制台: http://{host}:{port}  令牌: {token}"
& $exe gui --listen any --token $token
"""


def _console_ip():
    """控制台对外可达的本机 IP（用于烘焙部署命令）。"""
    try:
        from .netutils import get_route

        return get_route()[1] or ""
    except Exception:
        return ""


def restore_stale_sessions():
    """启动时自动恢复上次异常退出遗留的隔离会话（断电/崩溃安全网）。"""
    from .isolation import SESSIONS_DIR

    if not os.path.isdir(SESSIONS_DIR):
        return
    for fn in os.listdir(SESSIONS_DIR):
        if not fn.endswith(".json"):
            continue
        path = os.path.join(SESSIONS_DIR, fn)
        try:
            with open(path, encoding="utf-8") as f:
                d = json.load(f)
            if not d.get("active"):
                continue
            print(f"[*] 发现未恢复的隔离会话: {d.get('victim_ip')}，正在恢复 ...")
            restore_from_file(path)
        except Exception as e:
            print(f"[!] 会话 {fn} 恢复失败: {e}")


def _load_hosts_file():
    try:
        with open(discovery.HOSTS_FILE, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _start_scan(net, ports, methods, engine="auto", iface=None):
    with _scan_lock:
        if _scan_state["running"]:
            return {"error": "已有探测任务在进行中，请等待完成"}
        _scan_state.update(running=True, stage="启动", progress=[0, 0],
                           error=None, result=None)

    def worker():
        try:
            def progress(stage, done, total):
                with _scan_lock:
                    _scan_state["stage"] = stage
                    _scan_state["progress"] = [done, total]
            data = discovery.discover(net, methods=methods, ports=ports,
                                      engine=engine, iface=iface,
                                      log=lambda *a, **k: None, progress=progress)
            with _scan_lock:
                _scan_state.update(running=False, finished=time.time(), result=data)
        except SystemExit as e:
            with _scan_lock:
                _scan_state.update(running=False, error=str(e))
        except Exception as e:
            with _scan_lock:
                _scan_state.update(running=False, error=f"{type(e).__name__}: {e}")

    threading.Thread(target=worker, daemon=True).start()
    return {"ok": True}


def _do_isolate(body):
    ip = str(body.get("ip") or "").strip()
    mode = body.get("mode") or "offnet"
    dry_run = bool(body.get("dry_run"))
    duration = int(float(body.get("duration_min") or 0) * 60)
    excludes = body.get("exclude") or []
    iface = body.get("iface") or None
    scan_data = _load_hosts_file()

    if not is_admin() and not dry_run:
        return {"error": "节点未以管理员运行，无法实际隔离（可勾选演练模式）"}

    try:
        prepared = prepare_isolation(
            ip, mode=mode, scan_data=scan_data, excludes=excludes,
            provided_mac=body.get("victim_mac"), dry_run=dry_run,
            iface=iface, log=lambda *a, **k: None)
    except IsolationError as e:
        return {"error": str(e)}

    iso = Isolator(
        prepared["victim_ip"], prepared["victim_mac"],
        prepared["gateway_ip"], prepared["gateway_mac"],
        mode=mode, peers=prepared["peers"],
        interval=float(body.get("interval") or 1.0),
        fake_mac=(body.get("fake_mac") or "").lower() or None,  # None=自动随机
        iface=prepared["iface"], dry_run=dry_run,
        no_restore=bool(body.get("no_restore")),
        mac_rotate=int(body.get("mac_rotate") or 0),
    )
    if dry_run:
        return {"ok": True, "dry_run": True,
                "preview": [p.summary() for p in iso.build_poison()]}
    try:
        manager.start(iso, duration=duration)
    except IsolationError as e:
        return {"error": str(e)}
    return {"ok": True, "victim_ip": ip, "mode": iso.mode}


def _do_verify(body):
    """主动验证目标隔离状态：ping 可达性 + 流量分析 + 综合判定。"""
    ip = str(body.get("ip") or "").strip()
    if not ip:
        return {"error": "缺少 IP"}

    # 查找在线隔离
    active = None
    for item in manager.snapshot():
        if item["victim_ip"] == ip:
            active = item
            break

    if not active:
        return {"error": f"{ip} 不在隔离中"}

    # 主动 ping 测试
    from .netutils import sys_ping, tcp_connect_probe
    ping_ok = sys_ping(ip, timeout_ms=1000)
    tcp_hits = tcp_connect_probe(ip, (445, 80, 22), 0.8) if not ping_ok else []

    now = time.time()
    status = active.get("status", "uncertain")
    verdict_map = {
        "confirmed": "✅ 确认已断网 — 目标反复广播 ARP 找网关，且无出站流量",
        "likely": "🟡 大概率已断网 — 有 ARP 广播迹象，但可能有残余流量",
        "uncertain": "⚪ 状态不确定 — 未观察到明确信号（目标可能空闲）",
        "failed": "❌ 隔离未生效 — 目标仍在主动访问外部网络",
        "drill": "🔧 演练模式 — 未实际发送数据包",
    }

    return {
        "ip": ip,
        "status": status,
        "verdict": verdict_map.get(status, status),
        "ping_reachable": ping_ok,
        "tcp_ports": [{"port": p, "state": s} for p, s in tcp_hits],
        "arp_broadcasts": active.get("arp_requests", 0),
        "outbound_packets": active.get("outbound_pkts", 0),
        "seconds_since_arp": active.get("seconds_since_arp", -1),
        "seconds_since_outbound": active.get("seconds_since_outbound", -1),
        "isolated_seconds": active.get("elapsed", 0),
        "mode": active.get("mode", "offnet"),
        "timestamp": time.strftime("%H:%M:%S"),
    }


def _do_restore(body):
    ip = str(body.get("ip") or "").strip()
    if not ip:
        return {"error": "缺少目标 IP"}
    if not is_admin():
        return {"error": "节点未以管理员运行，无法发送恢复 ARP"}
    via = None
    if manager.stop(ip):  # 在线隔离：停线程即自动恢复
        via = "active"
    else:
        try:
            path = find_session(victim_ip=ip)
        except IsolationError as e:
            return {"error": str(e)}
        try:
            restore_from_file(path, log=lambda *a, **k: None)
        except Exception as e:
            return {"error": f"恢复失败: {e}"}
        via = "session"
    # 恢复后自动回探，确认目标重新在线（等待恢复 ARP 生效）
    time.sleep(1.5)
    from .netutils import sys_ping, tcp_connect_probe

    ping = sys_ping(ip, timeout_ms=800)
    tcp = tcp_connect_probe(ip, (445, 80), 0.8) if not ping else []
    return {"ok": True, "via": via, "online": ping or bool(tcp)}


def _doctor():
    import scapy
    from scapy.all import conf, get_if_hwaddr, get_if_list

    from .netutils import pcap_ok as _pcap_ok
    from .netutils import raw_engine_ok

    pcap = _pcap_ok()
    iface_name, own_ip, gw_ip = get_route()
    net = onlink_network()
    return {
        "node": platform.node(),
        "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
        "admin": is_admin(),
        "pcap_ok": pcap,
        "raw_ok": raw_engine_ok(),
        "engine": "raw" if raw_engine_ok() else "compat",
        "listen": _BIND_HOST,
        "scapy": scapy.VERSION,
        "iface": str(iface_name) if iface_name else "",
        "ip": own_ip or "",
        "mac": str(get_if_hwaddr(conf.iface)) if pcap else "",
        "gateway_ip": gw_ip or "",
        "gateway_mac": resolve_mac(gw_ip) if gw_ip else "",
        "onlink": str(net) if net else "",
        "onlink_prefixlen": net.prefixlen if net else 0,
        "if_count": len(get_if_list()),
        "ok": pcap and bool(gw_ip),
    }


def _interfaces():
    from .netutils import list_interfaces

    return {"interfaces": list_interfaces()}


def _probe(body):
    """单目标探测。deep=true 时附加全端口扫描 + 主机名 + MAC + 厂商（研判用）。"""
    from concurrent.futures import ThreadPoolExecutor

    from .netutils import lookup_vendor, resolve_mac, sys_ping, tcp_connect_probe

    ip = str(body.get("ip") or "").strip()
    if not ip:
        return {"error": "缺少 IP"}
    deep = bool(body.get("deep"))
    with ThreadPoolExecutor(max_workers=2) as ex:
        ping_f = ex.submit(sys_ping, ip, 700)
        tcp_f = ex.submit(tcp_connect_probe, ip, (445, 80), 0.8)
        ping = ping_f.result()
        tcp = tcp_f.result()
    out = {
        "ip": ip,
        "ping": ping,
        "tcp": [{"port": p, "state": s} for p, s in tcp],
        "alive": ping or bool(tcp),
    }
    if deep:
        from .discovery import port_scan

        ports = port_scan(ip)
        mac = resolve_mac(ip)
        out.update({
            "ports": [{"port": p, "service": s} for p, s in ports],
            "mac": mac or "",
            "vendor": lookup_vendor(mac) if mac else "",
        })
        try:
            import socket as _socket

            out["hostname"] = _socket.gethostbyaddr(ip)[0]
        except Exception:
            out["hostname"] = ""
    return out


def _tail_audit(n=100):
    out = []
    try:
        with open(AUDIT_FILE, encoding="utf-8") as f:
            lines = f.readlines()
        for line in lines[-n:]:
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except Exception:
                    pass
    except Exception:
        pass
    return out


class Handler(BaseHTTPRequestHandler):
    server_version = "AegisIR"

    # ---------- 基础 ----------
    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Aegis-Token")

    def _json(self, obj, code=200):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._cors()
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self):
        # token 保护远程访问；本机回环免鉴权（本机操作者本可从进程参数看到令牌）
        if not TOKEN:
            return True
        if self.client_address[0] in ("127.0.0.1", "::1", "localhost"):
            return True
        return self.headers.get("X-Aegis-Token") == TOKEN

    def log_message(self, fmt, *args):
        pass

    # ---------- 路由 ----------
    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_GET(self):
        path, _, query = self.path.partition("?")
        if path.startswith("/api/"):
            if not self._authorized():
                return self._json({"error": "token 校验失败"}, 401)
            return self._api_get(path)
        if path.startswith("/deploy/"):
            return self._deploy(path, query)
        return self._static(path)

    def _deploy(self, path, query):
        """下发部署产物与一键脚本（公开资源，令牌由脚本参数携带）。"""
        from urllib.parse import parse_qs

        q = parse_qs(query or "")
        port = self.server.server_address[1]
        host = (q.get("host") or [""])[0] or (
            _console_ip() or self.headers.get("Host", "").split(":")[0] or "127.0.0.1")

        def _send_text(text, ctype="text/plain; charset=utf-8"):
            body = text.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self._cors()
            self.end_headers()
            self.wfile.write(body)

        name = path.split("/")[-1]
        if name in ("install.sh", "install.ps1"):
            token = (q.get("token") or [""])[0]
            if not token:
                return self._json({"error": "缺少 token 参数"}, 400)
            if name == "install.sh":
                _send_text(_gen_install_sh(token, host, port), "text/x-sh; charset=utf-8")
            else:
                _send_text(_gen_install_ps1(token, host, port), "text/plain; charset=utf-8")
            return
        art = _find_artifact({"node.pyz": "aegis-node.pyz"}.get(name, name))
        if not art:
            return self._json({
                "error": f"产物 {name} 不存在。请在控制台机器上先构建："
                         f"Windows 运行 build_exe.bat / Python 运行 build_node.py"}, 404)
        ctype = {"pyz": "application/octet-stream", "exe": "application/octet-stream"}.get(
            name.split(".")[-1], "application/octet-stream")
        with open(art, "rb") as f:
            body = f.read()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self._cors()
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        path = self.path.split("?")[0]
        if not self._authorized():
            return self._json({"error": "token 校验失败"}, 401)
        try:
            length = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            body = {}
        if path == "/api/scan":
            return self._json(_start_scan(str(body.get("net") or "").strip(),
                                          bool(body.get("ports")),
                                          body.get("methods"),
                                          engine=body.get("engine") or "auto",
                                          iface=body.get("iface") or None))
        if path == "/api/isolate":
            return self._json(_do_isolate(body))
        if path == "/api/restore":
            return self._json(_do_restore(body))
        if path == "/api/verify":
            return self._json(_do_verify(body))
        if path == "/api/probe":
            return self._json(_probe(body))
        return self._json({"error": "未知接口"}, 404)

    def _api_get(self, path):
        if path == "/api/doctor":
            try:
                return self._json(_doctor())
            except Exception as e:
                return self._json({"error": f"{type(e).__name__}: {e}"})
        if path == "/api/interfaces":
            try:
                return self._json(_interfaces())
            except Exception as e:
                return self._json({"error": f"{type(e).__name__}: {e}"})
        if path == "/api/scan":
            with _scan_lock:
                state = dict(_scan_state)
            state.pop("result", None)
            state["last"] = _load_hosts_file()
            return self._json(state)
        if path == "/api/isolate":
            return self._json({"active": manager.snapshot()})
        if path == "/api/sessions":
            return self._json({"sessions": list_sessions()})
        if path == "/api/events":
            return self._json({"events": _tail_audit()})
        return self._json({"error": "未知接口"}, 404)

    # ---------- 静态文件 ----------
    def _static(self, path):
        if path == "/":
            path = "/index.html"
        fname = os.path.normpath(os.path.join(WEB_DIR, path.lstrip("/")))
        if not fname.startswith(WEB_DIR) or not os.path.isfile(fname):
            return self._json({"error": "not found"}, 404)
        ctype = {
            ".html": "text/html; charset=utf-8",
            ".js": "application/javascript; charset=utf-8",
            ".css": "text/css; charset=utf-8",
            ".svg": "image/svg+xml",
        }.get(os.path.splitext(fname)[1], "application/octet-stream")
        with open(fname, "rb") as f:
            body = f.read()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def make_server(host, port):
    global _BIND_HOST
    _BIND_HOST = host
    return ThreadingHTTPServer((host, port), Handler)


def shutdown_all(httpd):
    """停止服务前先恢复所有隔离中的目标（隔离线程收到停止事件后会自动发纠正 ARP）。"""
    print("[*] 正在停止：恢复所有隔离中的目标 ...")
    for item in manager.snapshot():
        manager.stop(item["victim_ip"])
    time.sleep(1.5)  # 给恢复线程留出发包时间
    httpd.server_close()


def serve(port=8765, listen="loopback", token=None, open_browser=True):
    global TOKEN
    host = "127.0.0.1" if listen == "loopback" else "0.0.0.0"
    if not token:
        from .netutils import generate_token
        token = generate_token()
    TOKEN = token
    restore_stale_sessions()  # 断电/崩溃遗留的隔离先恢复再服务

    # 端口自适应：目标端口被占用时自动递增找下一个
    from .netutils import find_free_port
    actual_port = port
    while True:
        try:
            httpd = make_server(host, actual_port)
            break
        except OSError:
            old = actual_port
            actual_port = find_free_port(actual_port + 1)
            if actual_port == old:
                raise SystemExit(f"[!] 端口 {port}-{old} 全部被占用，请用 --port 指定其他端口")
            print(f"[!] ⚠ 端口 {old} 被占用，自动切换到 {actual_port}")
            print(f"[!] ⚠ 请注意：8765 被其他进程占用可能是残留的调试实例，建议关闭后重试")
            print(f"[!] ⚠ 当前实际端口: {actual_port}（浏览器请访问此端口）")

    audit_event("gui_start", host=host, port=actual_port)
    print("=" * 60)
    print(f"  AegisIR 控制台已启动: http://127.0.0.1:{actual_port}/")
    print(f"  本机访问令牌: {token}")
    if host == "0.0.0.0":
        ip = _console_ip() or "127.0.0.1"
        print(f"  外部访问地址: http://{ip}:{actual_port}/")
        print(f"  令牌: {token}")
        print("  (外部节点/浏览器均可用此令牌接入)")
    print("  Ctrl+C 停止服务（进行中的隔离会自动恢复）")
    print("=" * 60)
    if open_browser:
        try:
            webbrowser.open(f"http://127.0.0.1:{port}/")
        except Exception:
            pass
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print()
        shutdown_all(httpd)
