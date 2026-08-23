"""AegisIR 命令行入口。

子命令: doctor / interfaces / gateway / scan / isolate / restore / status / gui
"""

import argparse
import ipaddress
import json
import os
import sys

from .audit import audit_event

BANNER = """
========================================================
  AegisIR v%s - 应急响应网络隔离工具
  仅供授权应急响应 / 内网安全测试使用，禁止用于未授权场景
  (c) 2026 星川网络 XingChuan Network
========================================================
"""


def _print(s="", end="\n"):
    print(s, end=end, flush=True)


def _version():
    from . import __version__

    return __version__


# ---------------------------------------------------------------- doctor
def cmd_doctor(args):
    import platform

    import scapy
    from scapy.all import conf, get_if_hwaddr, get_if_list

    from .netutils import get_route, is_admin, onlink_network, resolve_mac

    _print(BANNER % _version())
    _print(f"[*] Python     : {platform.python_version()} ({sys.platform})")
    _print(f"[*] 管理员权限 : {'是' if is_admin() else '否（隔离/恢复需管理员，Windows 请右键管理员运行）'}")
    _print(f"[*] Scapy      : {scapy.VERSION}")
    try:
        get_if_hwaddr(conf.iface)
        _print(f"[*] 抓包驱动   : 正常（Npcap/WinPcap，共 {len(get_if_list())} 个接口）")
        pcap_ok = True
    except Exception as e:
        _print(f"[!] 抓包驱动   : 不可用（{e}）。Windows 请安装 Npcap 并勾选 raw packet 支持")
        pcap_ok = False

    iface, own_ip, gw_ip = get_route()
    if iface:
        _print(f"[*] 出口接口   : {iface}")
        _print(f"[*] 本机 IP/MAC: {own_ip} / {get_if_hwaddr(conf.iface)}")
        _print(f"[*] 默认网关   : {gw_ip}")
        gw_mac = resolve_mac(gw_ip)
        _print(f"[*] 网关 MAC   : {gw_mac or '未解析到（可稍后用 gateway 子命令重试）'}")
    net = onlink_network()
    if net:
        _print(f"[*] 本地直连网段: {net} （scan --net 可直接使用）")
    _print("-" * 56)
    if not pcap_ok:
        _print("[x] 环境不完整，请先安装 Npcap: https://npcap.com/")
    elif not is_admin():
        _print("[!] 驱动正常但缺少管理员权限；scan 可能失败，isolate 将被拒绝")
    else:
        _print("[+] 环境就绪")


def cmd_interfaces(args):
    from .netutils import list_interfaces

    _print("[*] 网卡列表（--iface 参数使用 id 列）:")
    rows = [("#", "名称", "IP", "MAC", "网段", "网关", "默认", "id")]
    for i, ifc in enumerate(list_interfaces(), 1):
        rows.append((str(i), ifc["name"][:28], ifc["ip"], ifc["mac"],
                     ifc["network"] or "-", ifc["gateway"] or "-",
                     "√" if ifc["is_default"] else "", ifc["id"]))
    widths = [max(len(r[c]) for r in rows) for c in range(len(rows[0]))]
    for r in rows[:1]:
        _print("  ".join(h.ljust(w) for h, w in zip(r, widths)))
    _print("-" * (sum(widths) + 2 * (len(widths) - 1)))
    for r in rows[1:]:
        _print("  ".join(str(c).ljust(w) for c, w in zip(r, widths)))


def cmd_token(args):
    from .netutils import generate_token

    tok = generate_token()
    _print(f"[*] 已生成部署令牌: {tok}")
    _print("[*] 在目标网段任一台机器上执行（拷贝整行）：")
    _print(f"    AegisIR.exe gui --listen any --token {tok}")
    _print("[*] 然后在控制台「节点管理」→「＋节点」填入 http://节点IP:8765 与该令牌即可接入")


def cmd_gateway(args):
    from scapy.all import conf, get_if_hwaddr

    from .netutils import get_route, onlink_network, resolve_mac

    iface, own_ip, gw_ip = get_route()
    if not iface:
        _print("[!] 未识别到默认路由")
        return
    _print(f"[*] 出口接口 : {iface}")
    _print(f"[*] 本机     : {own_ip} / {get_if_hwaddr(conf.iface)}")
    _print(f"[*] 网关     : {gw_ip} / {resolve_mac(gw_ip) or '未知'}")
    net = onlink_network()
    if net:
        _print(f"[*] 本地网段 : {net}")


# ---------------------------------------------------------------- scan
def cmd_scan(args):
    from .discovery import discover
    from .netutils import is_admin

    if not is_admin():
        _print("[*] 无管理员权限：自动使用 compat 引擎（系统 ping + ARP 表，免权限可用）")
    methods = [m for m in (args.methods or "").split(",") if m] or None
    audit_event("scan_start", cidr=args.net, ports=bool(args.ports), engine=args.engine)
    discover(args.net, methods=methods, ports=args.ports, iface=args.iface,
             force=args.force, engine=args.engine, log=_print)


# ---------------------------------------------------------------- isolate
def _load_scan():
    from .discovery import HOSTS_FILE

    if not os.path.exists(HOSTS_FILE):
        return None
    try:
        with open(HOSTS_FILE, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _pick_target(scan_data):
    if not scan_data or not scan_data.get("hosts"):
        raise SystemExit("[!] 没有扫描结果，请先运行: python -m aegis_ir scan --net <网段>")
    hosts = scan_data["hosts"]
    _print(f"[*] 最近扫描（{scan_data.get('scan_time', '?')}，网段 {scan_data.get('cidr', '?')}）:")
    for i, (ip, h) in enumerate(hosts.items(), 1):
        note = []
        if h.get("is_gateway"):
            note.append("网关")
        if h.get("is_self"):
            note.append("本机")
        _print(f"    {i:3d}. {ip:<16} {(h.get('mac') or '-'):<19} "
                f"{(h.get('vendor') or '')[:20]:<20} {','.join(note)}")
    try:
        n = input("选择目标序号（回车取消）: ").strip()
    except EOFError:
        n = ""
    if not n.isdigit() or not (1 <= int(n) <= len(hosts)):
        raise SystemExit("[*] 已取消")
    return list(hosts)[int(n) - 1]


def cmd_isolate(args):
    from .discovery import port_scan
    from .isolation import (DEFAULT_FAKE_MAC, IsolationError, Isolator,
                            prepare_isolation)
    from .netutils import is_admin, is_unicast_mac, lookup_vendor

    if not args.dry_run and not is_admin():
        raise SystemExit("[!] 需要管理员/root 权限；如仅演练请加 --dry-run")

    victim_ip = args.ip
    scan_data = _load_scan()
    if args.pick or not victim_ip:
        victim_ip = _pick_target(scan_data)

    excludes = [x.strip() for x in (args.exclude or "").split(",") if x.strip()]
    fake_mac = (args.fake_mac or DEFAULT_FAKE_MAC).lower()
    if not is_unicast_mac(fake_mac):
        raise SystemExit(f"[!] 假 MAC {fake_mac} 不是单播地址，会被部分网卡丢弃")

    try:
        prepared = prepare_isolation(
            victim_ip, mode=args.mode, scan_data=scan_data, excludes=excludes,
            dry_run=args.dry_run, iface=args.iface, log=_print)
    except IsolationError as e:
        raise SystemExit(f"[!] {e}")

    iso = Isolator(
        prepared["victim_ip"], prepared["victim_mac"],
        prepared["gateway_ip"], prepared["gateway_mac"],
        mode=args.mode, peers=prepared["peers"], interval=args.interval,
        fake_mac=fake_mac, iface=prepared["iface"], dry_run=args.dry_run,
        no_restore=args.no_restore,
    )

    mode_desc = ("offnet：切断目标 <-> 网关（断外网，同网段邻居不受影响，影响面最小）"
                 if iso.mode == "offnet" else
                 f"island：目标与网关及同网段 {len(prepared['peers'])} 台主机双向全断（彻底断网）")
    _print("=" * 60)
    _print("  即将隔离以下目标（仅供授权应急响应使用）")
    _print(f"    目标   : {iso.victim_ip}（{iso.victim_mac}）")
    if not iso.victim_mac.startswith("00:00:00"):
        _print(f"    厂商   : {lookup_vendor(iso.victim_mac) or '-'}")
        if args.show_ports:
            opened = port_scan(iso.victim_ip, iface=prepared["iface"])
            if opened:
                _print("    开放端口: " + ", ".join(f"{p}/{s}" for p, s in opened))
    _print(f"    网关   : {iso.gateway_ip}（{iso.gateway_mac or '?'}）")
    _print(f"    模式   : {mode_desc}")
    _print(f"    周期   : 每 {args.interval}s 一轮 | 时长: "
           f"{'不限（Ctrl+C 停止）' if not args.duration else f'{args.duration}s 自动停止并恢复'}")
    _print("=" * 60)
    if not args.yes:
        try:
            ans = input("确认隔离请输入 yes: ").strip().lower()
        except EOFError:
            ans = ""
        if ans != "yes":
            _print("[*] 已取消")
            return
    iso.run(duration=args.duration, log=_print)


# ---------------------------------------------------------------- restore / status / gui
def cmd_restore(args):
    from .isolation import IsolationError, find_session, restore_from_file
    from .netutils import is_admin

    if not is_admin():
        raise SystemExit("[!] 恢复也需要发送原始 ARP，需要管理员/root 权限")
    try:
        if args.all:
            from .isolation import SESSIONS_DIR

            files = sorted(
                os.path.join(SESSIONS_DIR, fn)
                for fn in os.listdir(SESSIONS_DIR) if fn.endswith(".json")
            ) if os.path.isdir(SESSIONS_DIR) else []
            if not files:
                raise SystemExit("[*] 没有任何隔离会话记录")
            for p in files:
                restore_from_file(p, log=_print)
        else:
            path = find_session(victim_ip=args.ip, session_file=args.session)
            restore_from_file(path, log=_print)
    except IsolationError as e:
        raise SystemExit(f"[!] {e}")


def cmd_status(args):
    from .isolation import list_sessions

    rows = list_sessions()
    if not rows:
        _print("[*] 暂无隔离会话")
        return
    _print(f"{'开始时间':<20}  {'目标':<16}  {'模式':<8}  状态")
    for r in rows:
        _print(f"{r['started']:<20}  {r['victim_ip']:<16}  {r['mode']:<8}  {r['state']}")


def cmd_gui(args):
    from .netutils import is_admin, generate_token
    from .server import serve

    if not is_admin():
        _print("[!] 未以管理员运行：控制台仍可打开，但探测/隔离将受限，建议管理员身份重启")
    token = args.token or generate_token()
    serve(port=args.port, listen=args.listen, token=token,
          open_browser=not args.no_browser)


def cmd_app(args):
    from .netutils import is_admin
    from .app import run_app

    if not is_admin():
        _print("[!] 未以管理员运行：窗口仍可打开，但探测/隔离将受限，建议管理员身份重启")
    run_app(port=args.port, listen=args.listen, token=args.token)


# ---------------------------------------------------------------- main
EPILOG = """示例:
  AegisIR.exe / python run.py            # 双击/无参数：桌面窗口模式
  python -m aegis_ir doctor              # 环境自检
  python -m aegis_ir scan --net 192.168.1.0/24 --ports   # 多手段探测网段设备
  python -m aegis_ir scan --net 192.168.1.10-60 --methods passive  # 零流量被动探测
  python -m aegis_ir token               # 生成跨网段节点部署令牌
  python -m aegis_ir isolate 192.168.1.50    # 断外网（影响最小，推荐首选）
  python -m aegis_ir isolate --pick --mode island  # 交互选目标，彻底断网
  python -m aegis_ir isolate 192.168.1.50 --dry-run # 演练，不实际发包
  python -m aegis_ir restore 192.168.1.50    # 恢复目标网络
  python -m aegis_ir gui               # 浏览器版控制台
  python -m aegis_ir app --listen any --token SEC123  # 桌面窗口形态的跨网段节点
"""


def build_parser():
    p = argparse.ArgumentParser(
        prog="aegis_ir",
        description="AegisIR 应急响应网络隔离工具（仅限授权内网使用）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=EPILOG,
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("doctor", help="环境自检（权限 / Npcap / 网关 / 网段）").set_defaults(func=cmd_doctor)
    sub.add_parser("interfaces", help="列出网络接口").set_defaults(func=cmd_interfaces)
    sub.add_parser("gateway", help="显示本机 / 网关 / 直连网段信息").set_defaults(func=cmd_gateway)

    sp = sub.add_parser("scan", help="多引擎探测网段内存活主机")
    sp.add_argument("--net", required=True,
                    help="目标网段 CIDR 或 IP 范围，如 192.168.1.0/24 或 192.168.1.10-192.168.1.60")
    sp.add_argument("--iface", default=None, help="指定网卡（interfaces 子命令查看 id）")
    sp.add_argument("--engine", choices=["auto", "raw", "compat"], default="auto",
                    help="auto=按权限自动(默认)；raw=scapy原始报文(需管理员)；compat=免权限(ping+ARP表)")
    sp.add_argument("--methods", default="",
                    help="手段：arp,icmp,tcp,udp（raw 引擎）；passive=compat 纯被动零流量")
    sp.add_argument("--ports", action="store_true", help="附加常见 TCP 端口探测")
    sp.add_argument("--force", action="store_true", help="允许超过 1024 地址的大网段")
    sp.set_defaults(func=cmd_scan)

    tp = sub.add_parser("token", help="生成跨网段节点部署令牌及完整命令").set_defaults(func=cmd_token)

    ip_ = sub.add_parser("isolate", help="隔离目标（ARP 污染断网）")
    ip_.add_argument("ip", nargs="?", default=None, help="目标 IP（或改用 --pick 交互选择）")
    ip_.add_argument("--pick", action="store_true", help="从最近扫描结果中交互选择")
    ip_.add_argument("--mode", choices=["offnet", "island", "gateway", "full"],
                     default="offnet",
                     help="offnet=断外网(默认,推荐)；island=彻底断网(同网段全断)。"
                          "gateway/full 为旧名称别名")
    ip_.add_argument("--interval", type=float, default=1.0, help="发包轮询间隔秒数（默认 1.0）")
    ip_.add_argument("--duration", type=int, default=0, help="隔离时长秒，0 表示不限直到 Ctrl+C")
    ip_.add_argument("--fake-mac", default=None, help="用于污染的假 MAC（需为单播）")
    ip_.add_argument("--exclude", default="", help="island 模式不参与污染的 IP 列表，逗号分隔")
    ip_.add_argument("--iface", default=None, help="指定网卡（interfaces 子命令查看 id）")
    ip_.add_argument("--show-ports", action="store_true", help="确认前快速探测目标开放端口")
    ip_.add_argument("--dry-run", action="store_true", help="演练模式：只打印将发送的包，不实际发送")
    ip_.add_argument("--no-restore", action="store_true",
                     help="结束时不做恢复（目标缓存将随 ARP 超时自愈，一般不用）")
    ip_.add_argument("--yes", action="store_true", help="跳过交互确认（用于脚本）")
    ip_.set_defaults(func=cmd_isolate)

    rp = sub.add_parser("restore", help="恢复目标网络（发送真实 ARP 映射）")
    rp.add_argument("ip", nargs="?", default=None, help="目标 IP")
    rp.add_argument("--session", default=None, help="指定会话文件路径")
    rp.add_argument("--all", action="store_true", help="恢复所有历史会话目标")
    rp.set_defaults(func=cmd_restore)

    sub.add_parser("status", help="查看隔离会话历史").set_defaults(func=cmd_status)

    gp = sub.add_parser("gui", help="启动 Web 控制台（浏览器访问）")
    gp.add_argument("--port", type=int, default=8765, help="监听端口（默认 8765）")
    gp.add_argument("--listen", choices=["loopback", "any"], default="any",
                    help="any=对外监听(默认)；loopback=仅本机访问")
    gp.add_argument("--token", default=None, help="访问令牌（默认自动生成）")
    gp.add_argument("--no-browser", action="store_true", help="不自动打开浏览器")
    gp.set_defaults(func=cmd_gui)

    ap = sub.add_parser("app", help="桌面窗口模式（原生应用窗口，双击 exe 即此模式）")
    ap.add_argument("--port", type=int, default=None, help="监听端口（默认自动分配）")
    ap.add_argument("--listen", choices=["loopback", "any"], default="any",
                    help="any=对外监听(默认)；loopback=仅本机访问")
    ap.add_argument("--token", default=None, help="对外监听时必须设置的访问令牌")
    ap.set_defaults(func=cmd_app)
    return p


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    if len(sys.argv) == 1:
        sys.argv = [sys.argv[0], "app"]  # 无参数直接打开桌面窗口
    args = build_parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
