"""网络环境探测与基础工具。

包含三类能力：
- 环境识别：权限、路由、网关、网卡列表、直连网段
- 免权限原语：系统 ping、ARP 表读取、socket connect 探测、nbtstat 主机名
- 富化：IEEE OUI 厂商查询

免权限原语保证在无管理员/受限环境下探测引擎仍可工作（compat 引擎）。
"""

import ctypes
import ipaddress
import os
import re
import socket
import subprocess


# ---------------------------------------------------------------- 权限与环境
def is_admin() -> bool:
    """当前进程是否具有管理员/root 权限（原始收发与隔离所必需）。"""
    try:
        if os.name == "nt":
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        return os.geteuid() == 0
    except Exception:
        return False


def pcap_ok() -> bool:
    """Npcap/WinPcap 抓包驱动是否可用。"""
    from scapy.all import conf, get_if_hwaddr

    try:
        get_if_hwaddr(conf.iface)
        return True
    except Exception:
        return False


def raw_engine_ok() -> bool:
    """raw(scapy) 引擎可用性 = 管理员 + 抓包驱动。"""
    return is_admin() and pcap_ok()


def get_route(target: str = "1.1.1.1"):
    """返回 (出口接口, 本机IP, 网关IP)。网关为 '0.0.0.0' 表示目标直连。"""
    from scapy.all import conf

    try:
        iface, own_ip, gw_ip = conf.route.route(target)
        return iface, own_ip, gw_ip
    except Exception:
        return None, None, None


def resolve_if(iface=None):
    """把网卡 ID 解析为 scapy 接口对象；None 用默认接口。"""
    from scapy.all import conf

    if iface is None:
        return conf.iface
    try:
        from scapy.interfaces import resolve_iface

        ifc = resolve_iface(iface)
        if ifc is not None:
            return ifc
    except Exception:
        pass
    return conf.iface


# ---------------------------------------------------------------- 网卡列表
def list_interfaces():
    """列出可用网卡（过滤无 IP 的虚拟/蓝牙接口），供 GUI 手动选择。

    返回 [{id, name, ip, mac, is_default, network, gateway}]，默认网卡排最前。
    """
    from scapy.all import conf

    out = []
    try:
        items = list(conf.ifaces.values())
    except Exception:
        items = [conf.iface]
    for ifc in items:
        try:
            ip = str(getattr(ifc, "ip", "") or "")
            if not ip or ip.startswith("169.254."):
                continue  # 无 IP 或链路本地地址的接口对探测无意义
            network_name = str(getattr(ifc, "network_name", "") or ifc)
            friendly = str(getattr(ifc, "name", "") or getattr(ifc, "description", "") or network_name)
            out.append({
                "id": network_name,
                "name": friendly,
                "ip": ip,
                "mac": str(getattr(ifc, "mac", "") or ""),
                "is_default": network_name == str(conf.iface),
                "network": str(onlink_network(network_name) or ""),
                "gateway": iface_gateway(network_name) or "",
            })
        except Exception:
            continue
    out.sort(key=lambda x: (not x["is_default"], x["name"]))
    return out


def iface_gateway(iface_id):
    """该网卡的默认网关（从 scapy 路由表推导），无则 None。"""
    from scapy.all import conf

    try:
        for r in conf.route.routes:
            dst, mask, gw, ifc = r[0], r[1], r[2], r[3]
            if dst == 0 and mask == 0 and gw not in ("0.0.0.0", "", None):
                if str(ifc) == str(iface_id):
                    return gw
    except Exception:
        pass
    return None


# ---------------------------------------------------------------- 直连网段
def onlink_network(iface=None):
    """推导指定网卡（默认当前出口）的直连网段，失败返回 None。"""
    import struct

    from scapy.all import conf

    ifc = resolve_if(iface)
    own_ip = getattr(ifc, "ip", None)

    def _to_int(v):
        if isinstance(v, int):
            return v
        try:
            return struct.unpack("!I", socket.inet_aton(str(v)))[0]
        except Exception:
            return None

    try:
        mask = getattr(ifc, "netmask", None)
        if own_ip and mask:
            return ipaddress.ip_interface(f"{own_ip}/{mask}").network
    except Exception:
        pass

    try:
        if own_ip:
            own_i = _to_int(own_ip)
            best = None
            for r in conf.route.routes:
                dst, netmask, ifc_name = r[0], r[1], r[3]
                mi = _to_int(netmask)
                di = _to_int(dst)
                if not mi or di is None or own_i is None:
                    continue
                if str(ifc_name) != str(ifc):
                    continue
                if (own_i & mi) == (di & mi):
                    # 取掩码最小的直连路由（即接口网段），/32 是主机路由
                    if best is None or mi < best[1]:
                        best = (di & mi, mi)
            if best:
                prefix = bin(best[1]).count("1")
                return ipaddress.ip_network(f"{ipaddress.ip_address(best[0])}/{prefix}")
    except Exception:
        pass

    def _parse_ipconfig(out):
        ip = mask = None
        for line in out.splitlines():
            if ip is None and "IPv4" in line:
                m = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                if m:
                    ip = m.group(1)
            elif ip is not None and mask is None and (
                "子网掩码" in line or "Subnet Mask" in line
            ):
                m = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                if m:
                    mask = m.group(1)
            if ip and mask:
                return ip, mask
        return None

    if os.name == "nt":
        pair = _parse_ipconfig(_run_cmd(["ipconfig"]))
        if pair:
            try:
                return ipaddress.ip_interface(f"{pair[0]}/{pair[1]}").network
            except Exception:
                pass
    else:
        out = _run_cmd(["ip", "-4", "-o", "addr"])
        for line in out.splitlines():
            m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)", line)
            if m and not m.group(1).startswith(("127.", "169.254.")):
                return ipaddress.ip_interface(f"{m.group(1)}/{m.group(2)}").network
    return None


def is_onlink(ip: str, iface=None) -> bool:
    """目标 IP 是否与指定网卡通处一个二层网段（ARP 手段可达的必要条件）。"""
    from scapy.all import conf

    ifc = resolve_if(iface)
    try:
        dev, _own, gw = conf.route.route(ip)
        return gw == "0.0.0.0" and str(dev) == str(ifc)
    except Exception:
        return False


def is_unicast_mac(mac: str) -> bool:
    """假 MAC 必须是单播地址（首字节最低位为 0），否则会被部分网卡丢弃。"""
    try:
        return (int(mac.split(":")[0], 16) & 0x01) == 0
    except Exception:
        return False


# 常见真实厂商 OUI 前缀（用于生成不易被监控识别的假 MAC）
REALISTIC_OUIS = [
    "00:1a:2b",  # Ayecom
    "00:50:56",  # VMware
    "00:0c:29",  # VMware
    "00:15:5d",  # Microsoft Hyper-V
    "00:1b:21",  # Intel
    "00:1f:16",  # Dell
    "3c:2c:30",  # Hikvision
    "b8:27:eb",  # Raspberry Pi
    "d4:3d:7e",  # Dell
    "f0:9f:c2",  # HP
    "52:54:00",  # QEMU
    "00:e0:4c",  # Realtek
    "d4:ca:6d",  # Routerboard
    "c8:3a:35",  # Tenda
]


def random_fake_mac() -> str:
    """生成随机单播假 MAC（使用真实厂商 OUI 前缀，不易被 ARP 监控识别）。"""
    import random as _random

    oui = _random.choice(REALISTIC_OUIS)
    nic = ":".join(f"{_random.randint(0, 255):02x}" for _ in range(3))
    mac = f"{oui}:{nic}"
    if is_unicast_mac(mac):
        return mac
    # 如果恰好是组播地址（概率极低），翻转最后一位
    first = int(oui[:2], 16) & 0xFE
    return f"{first:02x}{oui[2:]}:{nic}"


# ---------------------------------------------------------------- 免权限原语
def find_free_port(start: int = 8765) -> int:
    """从 start 起找到第一个可用端口（用于端口自适应）。"""
    import socket

    for p in range(start, start + 100):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("0.0.0.0", p))
                return p
            except OSError:
                continue
    return start  # fallback


def generate_token(nbytes: int = 9) -> str:
    """生成部署令牌（加密随机，18 位十六进制）。"""
    import secrets

    return secrets.token_hex(nbytes)


def parse_scan_spec(spec: str, force: bool = False):
    """解析扫描目标：CIDR 或 IP 范围（a.b.c.d-e.f.g.h）。

    返回 (ips 或 None, label, is_range)。ips 为 None 表示是 CIDR，
    由调用方用网络对象枚举；IP 范围直接给出列表。超 1024 个地址抛错
    （force=True 时跳过上限校验）。
    """
    spec = str(spec).strip()
    if not spec:
        raise ValueError("目标不能为空")
    if "-" in spec and "/" not in spec:
        try:
            a, b = spec.split("-", 1)
            ipa = ipaddress.ip_address(a.strip())
            ipb = ipaddress.ip_address(b.strip())
        except ValueError:
            raise ValueError(f"IP 范围格式错误: {spec}（正确示例 192.168.1.10-192.168.1.60）")
        if ipa.version != ipb.version:
            raise ValueError("范围两端协议版本不一致")
        count = int(ipb) - int(ipa) + 1
        if count <= 0:
            raise ValueError("范围终点必须大于等于起点")
        if not force and count > 1024:
            raise ValueError(f"范围含 {count} 个地址，超过 1024 上限（--force 跳过）")
        ips = [str(ipaddress.ip_address(int(ipa) + i)) for i in range(count)]
        return ips, spec, True
    net = ipaddress.ip_network(spec, strict=False)
    if not force and net.num_addresses > 1024:
        raise ValueError(f"网段含 {net.num_addresses} 个地址，超过 1024 上限（--force 跳过）")
    return None, str(net), False


def _run_cmd(cmd) -> str:
    """执行系统命令并解码输出；中文 Windows 控制台为 GBK，需做编码回退。"""
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=8)
        out = p.stdout or b""
        for enc in ("utf-8", "gbk"):
            try:
                return out.decode(enc)
            except UnicodeDecodeError:
                continue
        return out.decode("utf-8", errors="replace")
    except Exception:
        return ""


def _parse_arp_lines(text: str) -> dict:
    """解析 arp -a 输出文本为 {ip: mac}（纯函数，供测试）。

    兼容 Windows（IP MAC 直排）、Linux（IP ether MAC）、macOS（IP at MAC）格式。
    """
    table = {}
    for line in text.splitlines():
        m = re.search(
            r"(\d{1,3}(?:\.\d{1,3}){3})\s+(?:[a-zA-Z]+\s+)?"
            r"([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})", line
        )
        if m:
            table[m.group(1)] = m.group(2).lower().replace("-", ":")
    return table


def parse_arp_table() -> dict:
    """读取系统 ARP 缓存表（免权限），返回 {ip: mac}。"""
    return _parse_arp_lines(_run_cmd(["arp", "-a"]))


def arp_table_in_network(cidr) -> dict:
    """ARP 表中落在指定网段内的表项 {ip: mac}。"""
    try:
        net = ipaddress.ip_network(str(cidr), strict=False)
    except ValueError:
        return {}
    return {ip: mac for ip, mac in parse_arp_table().items()
            if ipaddress.ip_address(ip) in net}


def sys_ping(ip: str, timeout_ms: int = 600) -> bool:
    """系统 ping 单次探测（无需管理员权限）。True=有回包。"""
    if os.name == "nt":
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), ip]
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout_ms / 1000 + 2)
        out = (p.stdout or b"") + (p.stderr or b"")
        if p.returncode == 0:
            return True
        return b"TTL=" in out or b"ttl=" in out
    except Exception:
        return False


def tcp_connect_probe(ip: str, ports, timeout: float = 0.8):
    """普通 socket 连接探测（无需权限）。返回 [(port, 'open'|'refused')]，
    refused（收到 RST）同样证明主机存活。超时/不可达不返回。"""
    hits = []
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((ip, int(port)))
            hits.append((int(port), "open"))
        except ConnectionRefusedError:
            hits.append((int(port), "refused"))
        except Exception:
            pass
        finally:
            try:
                s.close()
            except Exception:
                pass
    return hits


def nbns_hostname(ip: str, timeout: float = 2.0) -> str:
    """Windows nbtstat 查询 NetBIOS 主机名（免权限），失败返回空。"""
    if os.name != "nt":
        return ""
    try:
        p = subprocess.run(["nbtstat", "-A", ip], capture_output=True,
                           timeout=timeout)
        out = (p.stdout or b"").decode("gbk", errors="replace")
    except Exception:
        return ""
    for line in out.splitlines():
        m = re.match(r"\s*(\S{1,15})\s+<[0-9A-Fa-f]{2}>\s+UNIQUE", line)
        if m and m.group(1).upper() not in ("IS~", "MAC", "IOS"):
            return m.group(1)
    return ""


# ---------------------------------------------------------------- MAC 解析与富化
def resolve_mac(ip: str):
    """解析 IP 对应 MAC：优先系统 ARP 缓存（免权限），主动 ping 落表，
    最后 scapy ARP 请求。失败返回 None。"""
    from scapy.all import getmacbyip

    mac = parse_arp_table().get(ip)
    if mac:
        return mac
    if sys_ping(ip, timeout_ms=400):
        mac = parse_arp_table().get(ip)
        if mac:
            return mac
    try:
        mac = getmacbyip(ip, timeout=2)
    except Exception:
        mac = None
    return mac.lower() if mac else None


def lookup_vendor(mac: str) -> str:
    """通过 scapy 内置 IEEE OUI 数据库查询网卡厂商，失败返回空串。"""
    if not mac:
        return ""
    db = None
    try:
        from scapy.data import MANUFDB

        db = MANUFDB
    except Exception:
        try:
            from scapy.config import conf

            db = conf.manufdb
        except Exception:
            db = None
    if db is None:
        return ""
    try:
        r = db.lookup(mac)
    except Exception:
        return ""
    if not r:
        return ""
    if isinstance(r, (tuple, list)):
        best = ""
        for part in r:
            if part and len(str(part)) > len(best):
                best = str(part)
        return best
    return str(r)
