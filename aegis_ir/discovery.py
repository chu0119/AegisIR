"""多引擎主机发现。

- raw 引擎（scapy 原始报文，需管理员 + Npcap）：
    ARP sweep + ICMP + TCP SYN + UDP，手段可自选
- compat 引擎（免权限，任何环境可用）：
    被动 ARP 表快照 + 并发系统 ping + ARP 表差分取 MAC + TCP connect 辅助
    + DNS / nbtstat 主机名富化；支持纯被动模式（零流量）
- 扫描目标支持 CIDR（192.168.1.0/24）与 IP 范围（192.168.1.10-192.168.1.60）

engine=auto 按权限自动选择；raw 不可用时自动降级 compat 并提示。
"""

import ipaddress
import json
import os
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from .audit import audit_event
from .netutils import (get_route, is_onlink, lookup_vendor, nbns_hostname,
                       parse_arp_table, parse_scan_spec, raw_engine_ok,
                       resolve_if)

VAR_DIR = "var"
HOSTS_FILE = os.path.join(VAR_DIR, "hosts.json")

COMMON_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 135: "msrpc", 139: "netbios-ssn", 143: "imap", 443: "https",
    445: "smb", 1433: "mssql", 1521: "oracle", 3306: "mysql", 3389: "rdp",
    5432: "postgresql", 5900: "vnc", 6379: "redis", 8080: "http-alt",
    8443: "https-alt", 9200: "elasticsearch", 11211: "memcached", 27017: "mongodb",
}
TCP_PING_PORTS = (80, 443, 22, 445, 3389)
COMPAT_TCP_PORTS = (445, 3389, 22, 80)
COMPAT_DEEP_PORTS = (22, 80, 135, 139, 445, 3389, 8080)
RAW_METHODS = ("arp", "icmp", "tcp", "udp")


def _chunks(seq, size):
    for i in range(0, len(seq), size):
        yield seq[i : i + size]


# ---------------------------------------------------------------- 主机名富化
def resolve_hostnames(ips, workers=32, timeout=8):
    """并发反向 DNS 解析，超时放弃只返回已拿到的部分。"""
    result = {}

    def _one(ip):
        try:
            return ip, socket.gethostbyaddr(ip)[0]
        except Exception:
            return ip, None

    try:
        with ThreadPoolExecutor(max_workers=min(workers, max(1, len(ips)))) as ex:
            futs = [ex.submit(_one, ip) for ip in ips]
            for fut in as_completed(futs, timeout=timeout):
                ip, name = fut.result()
                if name:
                    result[ip] = name
    except Exception:
        pass
    return result


def nbns_hostnames(ips, workers=24, timeout=10):
    """并发 nbtstat 取 NetBIOS 主机名（Windows、免权限）。"""
    result = {}

    def _one(ip):
        return ip, nbns_hostname(ip)

    try:
        with ThreadPoolExecutor(max_workers=min(workers, max(1, len(ips)))) as ex:
            futs = [ex.submit(_one, ip) for ip in ips]
            for fut in as_completed(futs, timeout=timeout):
                try:
                    ip, name = fut.result()
                    if name:
                        result[ip] = name
                except Exception:
                    pass
    except Exception:
        pass
    return result


# ---------------------------------------------------------------- raw 引擎（scapy）
def _next_hop_macs(ips, iface=None):
    """为 L3 探测包确定二层封装目的 MAC（直连→广播，跨网段→网关 MAC）。"""
    from scapy.all import conf

    from .netutils import resolve_mac

    gw_cache = {}
    out = {}
    for ip in ips:
        try:
            gw = conf.route.route(ip)[2]
        except Exception:
            gw = "0.0.0.0"
        if gw in ("0.0.0.0", "", None):
            out[ip] = "ff:ff:ff:ff:ff:ff"
            continue
        if gw not in gw_cache:
            gw_cache[gw] = resolve_mac(gw) or "ff:ff:ff:ff:ff:ff"
        out[ip] = gw_cache[gw]
    return out


def arp_sweep(ips, iface=None, log=print, progress=None):
    """二层 ARP 存活探测（仅直连网段），返回 {ip: mac}。"""
    from scapy.all import ARP, Ether, srp

    ifc = resolve_if(iface)
    found = {}
    done = 0
    for chunk in _chunks(ips, 64):
        try:
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=chunk),
                         timeout=2, retry=1, iface=ifc, verbose=0)
        except PermissionError:
            raise SystemExit("[!] 无原始链路层收发权限：Windows 请以管理员运行并安装 Npcap；Linux 请用 root")
        for _s, rcv in ans:
            mac = str(rcv.hwsrc).lower()
            if rcv.psrc and mac:
                found[str(rcv.psrc)] = mac
        done += len(chunk)
        log(f"\r    ARP {done}/{len(ips)}", end="")
        if progress:
            progress("ARP", done, len(ips))
    log("")
    return found


def icmp_sweep(ips, iface=None, log=print):
    """ICMP ping 探测（raw），可跨网段。返回 {ip: ['ICMP']}。"""
    from scapy.all import ICMP, IP, Ether, srp

    hits = {}
    pkts = [Ether(dst=mac) / IP(dst=ip) / ICMP()
            for ip, mac in _next_hop_macs(ips, iface).items()]
    try:
        ans, _ = srp(pkts, timeout=2, verbose=0, inter=0.004)
    except Exception as e:
        log(f"[!] ICMP 探测失败: {e}")
        return hits
    for _s, rcv in ans:
        try:
            if rcv.haslayer(ICMP):
                hits.setdefault(rcv[IP].src, []).append("ICMP")
        except Exception:
            pass
    log(f"    ICMP 命中 {len(hits)}")
    return hits


def tcp_sweep(ips, ports=TCP_PING_PORTS, iface=None, log=print):
    """TCP SYN 探测（raw）：SYN+ACK / RST+ACK 均算存活。"""
    from scapy.all import IP, TCP, Ether, srp

    hits = {}
    open_ports = {}
    macs = _next_hop_macs(ips, iface)
    pkts = [Ether(dst=macs[ip]) / IP(dst=ip) / TCP(dport=p, flags="S")
            for ip in ips for p in ports]
    try:
        ans, _ = srp(pkts, timeout=2, verbose=0, inter=0.003)
    except Exception as e:
        log(f"[!] TCP 探测失败: {e}")
        return hits, open_ports
    for snd, rcv in ans:
        try:
            src = rcv[IP].src
            f = int(rcv[TCP].flags)
            dp = int(snd[TCP].dport)
        except Exception:
            continue
        if (f & 0x12) == 0x12:
            hits.setdefault(src, []).append("TCP")
            open_ports.setdefault(src, set()).add(dp)
        elif (f & 0x14) == 0x14:
            hits.setdefault(src, []).append("TCP")
    log(f"    TCP 命中 {len(hits)}")
    return hits, open_ports


def udp_sweep(ips, iface=None, log=print):
    """UDP 探测（raw）：依据 ICMP 端口不可达回包判断存活。"""
    from scapy.all import ICMP, IP, UDP, Ether, srp

    hits = {}
    macs = _next_hop_macs(ips, iface)
    pkts = [Ether(dst=macs[ip]) / IP(dst=ip) / UDP(dport=53) for ip in ips]
    try:
        ans, _ = srp(pkts, timeout=2, verbose=0, inter=0.003)
    except Exception as e:
        log(f"[!] UDP 探测失败: {e}")
        return hits
    for _s, rcv in ans:
        try:
            if rcv.haslayer(ICMP) and rcv[ICMP].type == 3:
                hits.setdefault(rcv[IP].src, []).append("UDP")
        except Exception:
            pass
    log(f"    UDP 命中 {len(hits)}")
    return hits


def raw_port_scan(ip, iface=None, timeout=1.0):
    """raw 引擎常见端口 SYN 探测，返回 [(端口, 服务名)]。"""
    from scapy.all import IP, TCP, Ether, srp

    mac = _next_hop_macs([ip], iface).get(ip, "ff:ff:ff:ff:ff:ff")
    pkts = [Ether(dst=mac) / IP(dst=ip) / TCP(dport=p, flags="S")
            for p in COMMON_PORTS]
    try:
        ans, _ = srp(pkts, timeout=timeout, verbose=0)
    except Exception:
        return []
    opened = []
    for snd, rcv in ans:
        if rcv.haslayer(TCP) and (int(rcv[TCP].flags) & 0x12) == 0x12:
            dport = snd[TCP].dport
            opened.append((dport, COMMON_PORTS.get(dport, "?")))
    return sorted(opened)


# ---------------------------------------------------------------- compat 引擎（免权限）
def compat_sweep(ips, in_scope, passive=False, log=print, progress=None):
    """免权限引擎。返回 (hits:{ip:[标签]}, macs:{ip:mac}, open_ports:{ip:[port]})。

    passive=True 时仅读取 ARP 表快照（零流量、完全静默）。
    """
    from .netutils import sys_ping, tcp_connect_probe

    hits, open_ports = {}, {}
    baseline = {ip: mac for ip, mac in parse_arp_table().items() if in_scope(ip)}
    if baseline:
        log(f"    被动 ARP 表快照命中 {len(baseline)}")
        for ip in baseline:
            hits[ip] = ["ARP表"]
    macs = dict(baseline)

    if passive:
        log("    纯被动模式：不发送任何探测流量")
        return hits, macs, open_ports

    todo = [ip for ip in ips if ip not in baseline]
    if todo:
        done = 0
        with ThreadPoolExecutor(max_workers=64) as ex:
            futs = {ex.submit(sys_ping, ip): ip for ip in todo}
            for fut in as_completed(futs):
                ip = futs[fut]
                done += 1
                try:
                    if fut.result():
                        hits.setdefault(ip, []).append("PING")
                except Exception:
                    pass
                if progress and done % 16 == 0:
                    progress("PING", done, len(todo))
        log(f"    系统 ping 命中 {sum(1 for v in hits.values() if 'PING' in v)}")

        after = {ip: mac for ip, mac in parse_arp_table().items() if in_scope(ip)}
        for ip, mac in after.items():
            if ip not in baseline:
                hits.setdefault(ip, []).append("ARP表")
            macs.setdefault(ip, mac)
        macs.update(after)

    rest = [ip for ip in ips if ip not in hits]
    if rest:
        def _probe(ip):
            return ip, tcp_connect_probe(ip, COMPAT_TCP_PORTS, 0.7)

        with ThreadPoolExecutor(max_workers=96) as ex:
            for ip, r in ex.map(_probe, rest):
                if r:
                    hits.setdefault(ip, []).append("TCP")
                    open_ports[ip] = [p for p, s in r if s == "open"]
        log(f"    TCP connect 补充命中 {sum(1 for v in hits.values() if 'TCP' in v)}")
    return hits, macs, open_ports


def compat_port_scan(ip):
    """compat 引擎深度端口探测（免权限，socket 连接）。"""
    from .netutils import tcp_connect_probe

    r = tcp_connect_probe(ip, COMPAT_DEEP_PORTS, 0.6)
    return [(p, COMMON_PORTS.get(p, "?")) for p, s in r if s == "open"]


def port_scan(ip, iface=None):
    """通用端口探测入口：按引擎可用性自动选择 raw / compat。"""
    if raw_engine_ok():
        return raw_port_scan(ip, iface=iface)
    return compat_port_scan(ip)


# ---------------------------------------------------------------- 主流程
def discover(spec, methods=None, ports=False, iface=None, force=False,
             engine="auto", log=print, progress=None):
    """探测网段/IP 范围。engine: auto/raw/compat；methods 可含 passive。"""
    try:
        range_ips, label, is_range = parse_scan_spec(spec, force=force)
    except ValueError as e:
        raise SystemExit(f"[!] {e}")

    if range_ips is not None:  # IP 范围
        ips = range_ips
        net = None
        lo, hi = int(ipaddress.ip_address(ips[0])), int(ipaddress.ip_address(ips[-1]))
        in_scope = lambda ip: lo <= int(ipaddress.ip_address(ip)) <= hi  # noqa: E731
    else:  # CIDR
        net = ipaddress.ip_network(label)
        ips = [str(h) for h in net.hosts()]
        in_scope = lambda ip: ipaddress.ip_address(ip) in net  # noqa: E731

    ifc = resolve_if(iface)
    local = is_onlink(ips[0], iface)
    _, own_ip, default_gw = get_route()

    engine = (engine or "auto").lower()
    if engine == "auto":
        engine = "raw" if raw_engine_ok() else "compat"
    if engine == "raw" and not raw_engine_ok():
        log("[!] raw 引擎不可用（需管理员 + Npcap），自动降级 compat 引擎")
        engine = "compat"

    methods = [str(m).lower() for m in (methods or []) if str(m).strip()]
    passive = "passive" in methods
    methods = [m for m in methods if m != "passive"]

    eng_label = "raw(scapy)" if engine == "raw" else ("compat(被动)" if passive else "compat(免权限)")
    log(f"[*] 探测 {label}（{len(ips)} 地址 | {'直连网段' if local else '跨网段(经路由)'} | "
        f"网卡 {getattr(ifc, 'name', ifc)} | 引擎 {eng_label}）")
    t0 = time.time()

    hits, macs, tcp_open, deep_fn = {}, {}, {}, None
    if engine == "raw":
        if not methods:
            methods = list(RAW_METHODS[:3] if local else ("icmp", "tcp", "udp"))
        bad = [m for m in methods if m not in RAW_METHODS]
        if bad:
            raise SystemExit(f"[!] 未知 raw 手段: {bad}（可选 {RAW_METHODS}）")
        if "arp" in methods and not local:
            log("[!] 目标非本机直连（经路由），ARP 自动跳过")
            methods = [m for m in methods if m != "arp"]
        log(f"    手段: {'+'.join(methods) if methods else '无'}")
        if "arp" in methods:
            for ip, mac in arp_sweep(ips, iface=ifc, log=log, progress=progress).items():
                hits.setdefault(ip, []).append("ARP")
                macs[ip] = mac
        if "icmp" in methods:
            for ip, v in icmp_sweep(ips, iface=ifc, log=log).items():
                hits.setdefault(ip, []).extend(v)
        if "tcp" in methods:
            th, tops = tcp_sweep(ips, iface=ifc, log=log)
            for ip, v in th.items():
                hits.setdefault(ip, []).extend(v)
            for ip, ps in tops.items():
                tcp_open[ip] = sorted(ps)
        if "udp" in methods:
            for ip, v in udp_sweep(ips, iface=ifc, log=log).items():
                hits.setdefault(ip, []).extend(v)
        deep_fn = raw_port_scan
    else:
        if methods:
            log(f"[!] compat 引擎不支持指定 raw 手段（{methods}），使用内置策略")
        hits, macs, tcp_open = compat_sweep(ips, in_scope, passive=passive,
                                            log=log, progress=progress)
        deep_fn = compat_port_scan

    alive = set(hits)
    if not alive:
        log("[!] 未发现存活主机（目标可能确实不在线，或防火墙全部丢弃）")
    else:
        log(f"[*] 共存活 {len(alive)} 台，富化信息（厂商 / 主机名）...")
    names = resolve_hostnames(list(alive)) if alive else {}
    if alive and not passive and os.name == "nt":
        missing = [ip for ip in alive if ip not in names][:80]
        for ip, n in nbns_hostnames(missing).items():
            names.setdefault(ip, n)
    ports_map = {}
    if ports and alive:
        log("[*] 端口探测中 ...")

        def _deep(ip):
            return ip, deep_fn(ip)

        with ThreadPoolExecutor(max_workers=16) as ex:
            for ip, opened in ex.map(_deep, sorted(alive, key=lambda s: ipaddress.ip_address(s))):
                ports_map[ip] = opened

    hosts = {}
    for ip in sorted(alive, key=lambda s: ipaddress.ip_address(s)):
        mac = (macs.get(ip) or "").lower()
        hosts[ip] = {
            "mac": mac,
            "vendor": lookup_vendor(mac),
            "hostname": names.get(ip, ""),
            "is_gateway": ip == default_gw,
            "is_self": ip == own_ip,
            "hits": sorted(set(hits.get(ip, []))),
            "tcp_ping_ports": sorted(tcp_open.get(ip, [])),
            "ports": [{"port": p, "service": s} for p, s in ports_map.get(ip, [])],
        }
    data = {
        "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "cidr": label,
        "segment": "local" if local else "routed",
        "engine": engine + ("-passive" if passive else ""),
        "iface": str(ifc),
        "gateway_ip": default_gw,
        "self_ip": own_ip,
        "hosts": hosts,
    }
    os.makedirs(VAR_DIR, exist_ok=True)
    with open(HOSTS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    audit_event("scan_done", cidr=label, hosts=len(hosts), engine=data["engine"],
                segment=data["segment"], seconds=round(time.time() - t0, 1))

    print_table(data, log=log)
    log(f"[*] 发现 {len(hosts)} 台存活主机，已保存到 {HOSTS_FILE}")
    return data


def print_table(data, log=print):
    header = ("#", "IP", "MAC", "厂商", "主机名", "命中", "开放端口", "备注")
    rows = []
    for i, (ip, h) in enumerate(data["hosts"].items(), 1):
        note = []
        if h.get("is_gateway"):
            note.append("网关")
        if h.get("is_self"):
            note.append("本机")
        if data.get("segment") == "routed":
            note.append("跨网段")
        rows.append((
            str(i), ip, h.get("mac") or "-", (h.get("vendor") or "-")[:18],
            (h.get("hostname") or "-")[:24], "/".join(h.get("hits") or []) or "-",
            ",".join(f"{x['port']}/{x['service']}" for x in h.get("ports") or [])[:30] or "-",
            ",".join(note) or "-",
        ))
    if not rows:
        return
    all_rows = [header] + rows
    widths = [max(len(str(r[i])) for r in all_rows) for i in range(len(header))]

    def fmt(r):
        return "  ".join(str(c).ljust(w) for c, w in zip(r, widths))

    log(fmt(header))
    log("-" * (sum(widths) + 2 * (len(widths) - 1)))
    for r in rows:
        log(fmt(r))
