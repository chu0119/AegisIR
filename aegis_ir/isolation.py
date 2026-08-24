"""隔离核心。

两种模式（ARP 不穿越路由，均要求目标与本节点同二层网段；跨网段请在
目标网段部署 AegisIR 节点，由控制台统一管理）：

- offnet  断外网：污染目标 ARP 缓存中"网关 -> 假MAC"，目标无法访问
          网关及以外网络；同网段邻居间通信不受影响，影响面最小。
- island  完全断网：offnet 基础上，目标与同网段所有邻居双向互相污染，
          目标彻底成为孤岛。需要先 scan 获取邻居清单。

恢复三层保障：正常停止自动发真实 ARP 纠正（秒级）；进程被杀可凭
var/sessions/ 会话手动恢复；极端无人善后时各主机 ARP 缓存到期自愈。
"""

import ipaddress
import json
import os
import threading
import time

from .audit import audit_event

SESSIONS_DIR = os.path.join("var", "sessions")
DEFAULT_FAKE_MAC = "de:ad:be:ef:00:01"  # 单播 + 本地管理位
MODE_ALIASES = {"gateway": "offnet", "full": "island"}  # v1 兼容
MODES = ("offnet", "island")


class IsolationError(Exception):
    pass


def normalize_mode(m):
    return MODE_ALIASES.get(str(m).lower(), str(m).lower())


def _arp_reply(dst_mac, psrc, hwsrc, pdst, hwdst):
    from scapy.all import ARP, Ether

    return Ether(dst=dst_mac) / ARP(op=2, psrc=psrc, hwsrc=hwsrc, pdst=pdst, hwdst=hwdst)


class Isolator:
    def __init__(self, victim_ip, victim_mac, gateway_ip, gateway_mac,
                 mode="offnet", peers=None, interval=1.0,
                 fake_mac=DEFAULT_FAKE_MAC, iface=None, dry_run=False,
                 no_restore=False):
        mode = normalize_mode(mode)
        if mode not in MODES:
            raise IsolationError(f"未知隔离模式: {mode}（可选 {MODES}）")
        if not victim_mac:
            raise IsolationError("隔离需要目标真实 MAC（目标不在线或未扫描）")
        self.mode = mode
        self.victim_ip = victim_ip
        self.victim_mac = victim_mac.lower()
        self.gateway_ip = gateway_ip
        self.gateway_mac = (gateway_mac or "").lower()
        self.peers = dict(peers or {})
        self.interval = max(0.2, float(interval))
        self.fake_mac = fake_mac.lower()
        self.iface = iface
        self.dry_run = dry_run
        self.no_restore = no_restore
        self.stats = {
            "sent": 0, "rounds": 0,
            "arp_requests": 0,       # 目标对网关的 who-has 广播次数
            "outbound_pkts": 0,      # 目标发往非本网段的数据包数（>0 = 还能上网）
            "outbound_bytes": 0,     # 出站总字节
            "last_arp_req": 0,       # 最近一次 ARP 广播时间戳
            "last_outbound": 0,      # 最近一次出站数据时间戳
        }
        self.session_file = None
        self.started_ts = None
        self._sniffer = None

    def _start_verifier(self):
        """三维验证嗅探器：ARP 广播 + 出站流量 + 综合判定。

        - 目标反复广播 who-has 网关 → 丢了网关（隔离生效迹象）
        - 目标仍有 TCP/UDP/ICMP 发往非本网段 → 还能上网（隔离失败）
        - 两者结合可准确判定隔离状态
        """
        from scapy.all import ARP, AsyncSniffer, IP

        from .netutils import raw_engine_ok

        if self.dry_run or not raw_engine_ok():
            return
        victim_mac = self.victim_mac
        victim_ip = self.victim_ip
        gw_ip = self.gateway_ip

        # 获取本机直连网段（用于判断目标包是否发往"外部"）
        own_ip = None
        try:
            from scapy.all import conf
            own_ip = getattr(conf.iface, "ip", None) or "127.0.0.1"
        except Exception:
            own_ip = "127.0.0.1"

        def _on_pkt(pkt):
            try:
                # 维度 1：ARP 广播（目标找网关 = 丢了网关）
                if ARP in pkt:
                    arp = pkt[ARP]
                    if (arp.op == 1 and str(arp.hwsrc).lower() == victim_mac
                            and arp.pdst == gw_ip):
                        self.stats["arp_requests"] += 1
                        self.stats["last_arp_req"] = time.time()

                # 维度 2：出站流量（目标还在发数据到外部 = 未断网）
                if IP in pkt:
                    ip = pkt[IP]
                    if ip.src == victim_ip and ip.dst != own_ip:
                        # 排除 ARP（非 IP 层）、排除发给网关本身的包
                        if ip.dst != gw_ip and not ip.dst.startswith("224.") \
                                and not ip.dst.startswith("239.") \
                                and not ip.dst.endswith("255"):
                            self.stats["outbound_pkts"] += 1
                            self.stats["outbound_bytes"] += len(pkt)
                            self.stats["last_outbound"] = time.time()
            except Exception:
                pass

        try:
            self._sniffer = AsyncSniffer(prn=_on_pkt, iface=self.iface, store=False)
            self._sniffer.start()
        except Exception:
            self._sniffer = None

    def _stop_verifier(self):
        if self._sniffer is not None:
            try:
                self._sniffer.stop(timeout=2)
            except Exception:
                pass
            self._sniffer = None

    @property
    def isolation_status(self) -> str:
        """多维度综合判定隔离状态。

        返回值：
        - "confirmed"  确认断网（ARP 广播活跃 + 无出站流量）
        - "likely"     大概率断网（有 ARP 广播，但可能有少量出站）
        - "uncertain"  不确定（无信号，目标可能空闲）
        - "failed"     隔离失败（目标仍有持续出站流量）
        - "drill"      演练模式
        """
        if self.dry_run:
            return "drill"

        now = time.time()
        arp_count = self.stats.get("arp_requests", 0)
        arp_recent = now - self.stats.get("last_arp_req", 0) < 60
        outbound_count = self.stats.get("outbound_pkts", 0)
        outbound_recent = now - self.stats.get("last_outbound", 0) < 15

        # 目标仍在持续发外部流量 → 隔离失败
        if outbound_recent and outbound_count > 5:
            return "failed"

        # ARP 广播活跃 + 无近期出站 → 确认断网
        if arp_count >= 1 and arp_recent and not outbound_recent:
            return "confirmed"

        # 有 ARP 广播但可能有残余流量 → 大概率断网
        if arp_count >= 1:
            return "likely"

        # 无信号 → 不确定
        return "uncertain"

    # ---------------- 数据包构造 ----------------
    def build_poison(self):
        pkts = [_arp_reply(self.victim_mac, self.gateway_ip, self.fake_mac,
                           self.victim_ip, self.victim_mac)]
        if self.mode == "island":
            for ip, mac in self.peers.items():
                pkts.append(_arp_reply(self.victim_mac, ip, self.fake_mac,
                                       self.victim_ip, self.victim_mac))
                pkts.append(_arp_reply(mac, self.victim_ip, self.fake_mac, ip, mac))
        return pkts

    def build_restore(self):
        from scapy.all import ARP, Ether

        pkts = [_arp_reply(self.victim_mac, self.gateway_ip, self.gateway_mac,
                           self.victim_ip, self.victim_mac)]
        if self.mode == "island":
            for ip, mac in self.peers.items():
                pkts.append(_arp_reply(self.victim_mac, ip, mac,
                                       self.victim_ip, self.victim_mac))
                pkts.append(_arp_reply(mac, self.victim_ip, self.victim_mac, ip, mac))
        # 免费 ARP 广播，加速全网对目标真实 MAC 的恢复
        pkts.append(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
            op=2, psrc=self.victim_ip, hwsrc=self.victim_mac,
            pdst=self.victim_ip, hwdst="ff:ff:ff:ff:ff:ff"))
        return pkts

    # ---------------- 主流程 ----------------
    def run(self, duration=0, log=print, stop_event=None):
        from scapy.all import sendp

        poison = self.build_poison()
        if self.dry_run:
            log(f"[dry-run] 以下 {len(poison)} 个数据包将每 {self.interval}s 发送一轮：")
            for p in poison:
                log("    " + p.summary())
            log("[dry-run] 未发送任何数据包")
            return

        self.started_ts = time.time()
        self._save_session(active=True)
        audit_event("isolate_start", victim=self.victim_ip, mac=self.victim_mac,
                    mode=self.mode, gateway=self.gateway_ip, peers=len(self.peers))
        start = time.time()
        last_report = start
        self._start_verifier()
        try:
            for _ in range(3):  # 首轮连发，快速覆盖目标缓存
                sendp(poison, iface=self.iface, verbose=0)
                self.stats["sent"] += len(poison)
            log("[+] 隔离已启动。保持本进程运行；Ctrl+C / 恢复按钮将停止并自动恢复")
            while True:
                if stop_event is not None and stop_event.is_set():
                    log("[*] 收到停止指令，开始恢复 ...")
                    break
                if duration and time.time() - start >= duration:
                    log(f"[*] 达到设定时长 {duration}s，自动停止并恢复")
                    break
                sendp(poison, iface=self.iface, verbose=0)
                self.stats["sent"] += len(poison)
                self.stats["rounds"] += 1
                now = time.time()
                if now - last_report >= 10:
                    extra = (f" | 目标ARP广播 {self.stats['arp_requests']} 次"
                             f"{'（生效确认）' if self.verified else ''}"
                             if self._sniffer is not None else "")
                    log(f"    已隔离 {int(now - start)}s | 累计发包 {self.stats['sent']}{extra}")
                    last_report = now
                time.sleep(self.interval)
        except KeyboardInterrupt:
            log("\n[!] 收到中断信号，开始恢复 ...")
        finally:
            self._stop_verifier()
            if not self.no_restore:
                self.restore(log=log)
            self._save_session(active=False)
            audit_event("isolate_stop", victim=self.victim_ip,
                        sent=self.stats["sent"], restored=not self.no_restore)
        msg = "（未执行恢复，目标缓存将自行过期自愈）" if self.no_restore else "，目标 ARP 缓存已恢复"
        log(f"[+] 结束：共发送 {self.stats['sent']} 个数据包{msg}")

    def restore(self, rounds=6, pause=0.3, log=print):
        if self.dry_run:
            log("[dry-run] 跳过恢复发包")
            return
        from scapy.all import sendp

        pkts = self.build_restore()
        try:
            for _ in range(rounds):
                sendp(pkts, iface=self.iface, verbose=0)
                time.sleep(pause)
            log(f"[+] 已发送 {rounds} 轮真实 ARP 映射，目标及邻居缓存将在数秒内恢复")
        except KeyboardInterrupt:
            log("[!] 恢复过程被中断；即便不完整，各主机缓存过期后也会自愈")

    # ---------------- 会话记录（崩溃后可手动恢复） ----------------
    def _save_session(self, active):
        os.makedirs(SESSIONS_DIR, exist_ok=True)
        if not self.session_file:
            name = (time.strftime("%Y%m%d_%H%M%S") + "_"
                    + self.victim_ip.replace(".", "_") + ".json")
            self.session_file = os.path.join(SESSIONS_DIR, name)
        data = {
            "victim_ip": self.victim_ip,
            "victim_mac": self.victim_mac,
            "gateway_ip": self.gateway_ip,
            "gateway_mac": self.gateway_mac,
            "mode": self.mode,
            "peers": self.peers,
            "fake_mac": self.fake_mac,
            "iface": str(self.iface) if self.iface else None,
            "started": time.strftime("%Y-%m-%d %H:%M:%S"),
            "active": active,
            "restored": (not active) and (not self.no_restore),
        }
        try:
            with open(self.session_file, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception:
            pass


# ---------------------------------------------------------------- 共享校验
def prepare_isolation(victim_ip, mode="offnet", scan_data=None, excludes=(),
                      provided_mac=None, dry_run=False, iface=None, log=print):
    """CLI / GUI 共用的隔离前置校验。返回构造 Isolator 所需的参数 dict。

    iface 为网卡 ID（None=默认出口）。抛出 IsolationError 时给出一线人员
    可读懂的中文原因。
    """
    from .netutils import (get_route, iface_gateway, is_onlink, resolve_if,
                           resolve_mac)

    try:
        ipaddress.ip_address(victim_ip)
    except ValueError:
        raise IsolationError(f"目标 IP 格式错误: {victim_ip}")
    mode = normalize_mode(mode)
    if mode not in MODES:
        raise IsolationError(f"未知隔离模式: {mode}")

    ifc = resolve_if(iface)
    _, route_own_ip, default_gw = get_route()
    own_ip = getattr(ifc, "ip", None) or route_own_ip
    gw_ip = iface_gateway(ifc) or default_gw
    if not gw_ip or gw_ip == "0.0.0.0":
        raise IsolationError("未能识别网关，无法执行 ARP 隔离")
    if victim_ip == gw_ip:
        raise IsolationError("目标是网关：隔离网关会瘫痪整个网段，已拒绝")
    if victim_ip == own_ip:
        raise IsolationError("目标是本机，已拒绝")
    if not is_onlink(victim_ip, ifc):
        raise IsolationError(
            f"目标 {victim_ip} 不在所选网卡（{getattr(ifc, 'name', ifc)}）的直连网段，"
            "ARP 无法穿越路由。请改选正确的网卡，或在目标网段部署 AegisIR 节点"
            "（python -m aegis_ir gui --listen any --token 令牌）后从控制台切换节点执行。")

    hosts = (scan_data or {}).get("hosts", {})
    victim_mac = provided_mac or resolve_mac(victim_ip) or hosts.get(victim_ip, {}).get("mac")
    if not victim_mac:
        if dry_run:
            victim_mac = "00:00:00:00:00:00"
            log("[!] 无法解析目标 MAC（主机可能不在线），dry-run 使用占位 MAC 继续")
        else:
            raise IsolationError(f"无法解析 {victim_ip} 的 MAC（主机可能不在线），拒绝执行")

    gw_mac = resolve_mac(gw_ip)
    if not gw_mac:
        if dry_run:
            gw_mac = "00:00:00:00:00:00"
        else:
            raise IsolationError("无法解析网关真实 MAC，无法保证安全恢复，拒绝执行")

    peers = {}
    if mode == "island":
        if not hosts:
            raise IsolationError("island 模式需要同网段主机清单，请先 scan")
        for ip, h in hosts.items():
            if ip in (victim_ip, own_ip, gw_ip) or ip in set(excludes):
                continue
            if h.get("mac"):
                peers[ip] = h["mac"]
        if not peers:
            log("[!] 未发现其他可污染邻居，island 将退化为仅切断网关方向")
    return {
        "victim_ip": victim_ip, "victim_mac": victim_mac,
        "gateway_ip": gw_ip, "gateway_mac": gw_mac,
        "peers": peers, "iface": ifc,
    }


# ---------------------------------------------------------------- 会话查询/恢复
def find_session(victim_ip=None, session_file=None):
    if session_file:
        if not os.path.exists(session_file):
            raise IsolationError(f"会话文件不存在: {session_file}")
        return session_file
    if not os.path.isdir(SESSIONS_DIR):
        raise IsolationError("没有任何隔离会话记录")
    cands = []
    for fn in os.listdir(SESSIONS_DIR):
        if not fn.endswith(".json"):
            continue
        path = os.path.join(SESSIONS_DIR, fn)
        try:
            with open(path, encoding="utf-8") as f:
                d = json.load(f)
        except Exception:
            continue
        if victim_ip and d.get("victim_ip") != victim_ip:
            continue
        cands.append((os.path.getmtime(path), path))
    if not cands:
        raise IsolationError("未找到匹配的隔离会话" + (f"（{victim_ip}）" if victim_ip else ""))
    cands.sort()
    return cands[-1][1]


def restore_from_file(path, log=print, rounds=8):
    """依据会话文件重建隔离器并执行恢复（用于崩溃/强杀后的善后）。"""
    from scapy.all import conf

    with open(path, encoding="utf-8") as f:
        d = json.load(f)
    iso = Isolator(
        d["victim_ip"], d["victim_mac"], d["gateway_ip"], d.get("gateway_mac"),
        mode=normalize_mode(d.get("mode", "offnet")), peers=d.get("peers") or {},
        fake_mac=d.get("fake_mac", DEFAULT_FAKE_MAC),
        iface=d.get("iface") or conf.iface,
    )
    log(f"[*] 从会话恢复：目标 {iso.victim_ip}（{iso.victim_mac}）模式 {iso.mode} "
        f"网关 {iso.gateway_ip}（{iso.gateway_mac or '未知'}）")
    iso.restore(rounds=rounds, log=log)
    d["restored"] = True
    d["active"] = False
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(d, f, ensure_ascii=False, indent=2)
    except Exception:
        pass
    audit_event("restore_done", victim=iso.victim_ip, session=os.path.basename(path))
    return iso


def list_sessions(limit=50):
    """列出隔离会话，新->旧。"""
    out = []
    if not os.path.isdir(SESSIONS_DIR):
        return out
    items = []
    for fn in os.listdir(SESSIONS_DIR):
        if not fn.endswith(".json"):
            continue
        path = os.path.join(SESSIONS_DIR, fn)
        try:
            with open(path, encoding="utf-8") as f:
                d = json.load(f)
        except Exception:
            continue
        items.append((os.path.getmtime(path), d))
    items.sort(reverse=True)
    for _mt, d in items[:limit]:
        state = "运行中" if d.get("active") else ("已恢复" if d.get("restored") else "已结束")
        out.append({
            "victim_ip": d.get("victim_ip", "?"),
            "mode": normalize_mode(d.get("mode", "offnet")),
            "started": d.get("started", "?"),
            "state": state,
        })
    return out


# ---------------------------------------------------------------- GUI 用隔离管理器
class IsolationManager:
    """线程安全地管理多个后台隔离任务（Web 控制台使用）。"""

    def __init__(self):
        self._active = {}
        self._lock = threading.Lock()

    def start(self, iso, duration=0):
        ip = iso.victim_ip
        with self._lock:
            if ip in self._active:
                raise IsolationError(f"{ip} 已在隔离中")
            ev = threading.Event()
            entry = {"iso": iso, "stop": ev, "started": time.time()}
            self._active[ip] = entry
        t = threading.Thread(target=self._runner, args=(iso, ev, duration), daemon=True)
        with self._lock:
            self._active[ip]["thread"] = t
        t.start()

    def _runner(self, iso, ev, duration):
        try:
            iso.run(duration=duration, stop_event=ev)
        finally:
            with self._lock:
                self._active.pop(iso.victim_ip, None)

    def stop(self, ip):
        with self._lock:
            entry = self._active.get(ip)
        if not entry:
            return False
        entry["stop"].set()
        return True

    def snapshot(self):
        with self._lock:
            items = list(self._active.values())
        out = []
        now = time.time()
        for e in items:
            iso = e["iso"]
            out.append({
                "victim_ip": iso.victim_ip,
                "victim_mac": iso.victim_mac,
                "mode": iso.mode,
                "started_ts": e["started"],
                "elapsed": int(now - e["started"]),
                "sent": iso.stats["sent"],
                "arp_requests": iso.stats.get("arp_requests", 0),
                "outbound_pkts": iso.stats.get("outbound_pkts", 0),
                "status": iso.isolation_status,
                "seconds_since_arp": int(now - iso.stats.get("last_arp_req", 0)) if iso.stats.get("last_arp_req") else -1,
                "seconds_since_outbound": int(now - iso.stats.get("last_outbound", 0)) if iso.stats.get("last_outbound") else -1,
                "dry_run": iso.dry_run,
            })
        return out
