"""discovery / isolation 单元测试（免权限可运行，不发真实隔离包）。"""

import ipaddress
import json
import os
import tempfile
import unittest
from unittest import mock

from scapy.all import ARP

from aegis_ir import discovery
from aegis_ir.isolation import (DEFAULT_FAKE_MAC, IsolationError, Isolator,
                                find_session, normalize_mode,
                                prepare_isolation)


class TestCompatEngine(unittest.TestCase):
    def test_compat_sweep_loopback(self):
        net = ipaddress.ip_network("127.0.0.0/29")
        ips = [str(h) for h in net.hosts()] + ["127.0.0.1"]
        in_scope = lambda ip: ipaddress.ip_address(ip) in net  # noqa: E731
        hits, macs, open_ports = discovery.compat_sweep(ips, in_scope, log=lambda *a, **k: None)
        self.assertIn("127.0.0.1", hits)
        self.assertIsInstance(macs, dict)

    def test_discover_compat_full_flow(self):
        tmp = tempfile.mkdtemp()
        hosts_file = os.path.join(tmp, "hosts.json")
        with mock.patch.object(discovery, "HOSTS_FILE", hosts_file), \
             mock.patch.object(discovery, "VAR_DIR", tmp, create=True):
            data = discovery.discover("127.0.0.0/29", engine="compat",
                                      log=lambda *a, **k: None)
        self.assertEqual(data["engine"], "compat")
        self.assertIn("127.0.0.1", data["hosts"])
        with open(hosts_file, encoding="utf-8") as f:
            saved = json.load(f)
        self.assertEqual(saved["cidr"], "127.0.0.0/29")


class TestIsolationLogic(unittest.TestCase):
    def test_normalize_mode_aliases(self):
        self.assertEqual(normalize_mode("gateway"), "offnet")
        self.assertEqual(normalize_mode("full"), "island")
        self.assertEqual(normalize_mode("offnet"), "offnet")

    def test_isolator_validation(self):
        with self.assertRaises(IsolationError):
            Isolator("1.2.3.4", None, "10.0.0.1", "aa:bb:cc:dd:ee:01")  # 缺目标 MAC
        with self.assertRaises(IsolationError):
            Isolator("1.2.3.4", "aa:bb:cc:dd:ee:02", "10.0.0.1", "aa:bb:cc:dd:ee:01",
                     mode="bogus")

    def test_packet_shapes(self):
        fake = "11:22:33:44:55:66"
        iso = Isolator("10.0.0.50", "aa:bb:cc:dd:ee:50", "10.0.0.1", "aa:bb:cc:dd:ee:01",
                       fake_mac=fake)
        self.assertEqual(len(iso.build_poison()), 1)   # offnet：仅目标→网关
        self.assertEqual(len(iso.build_restore()), 2)  # 网关纠正 + 免费 ARP

        peers = {"10.0.0.2": "aa:bb:cc:dd:ee:02", "10.0.0.3": "aa:bb:cc:dd:ee:03"}
        iso2 = Isolator("10.0.0.50", "aa:bb:cc:dd:ee:50", "10.0.0.1",
                        "aa:bb:cc:dd:ee:01", mode="island", peers=peers, fake_mac=fake)
        self.assertEqual(len(iso2.build_poison()), 1 + 2 * len(peers))
        self.assertEqual(len(iso2.build_restore()), 1 + 2 * len(peers) + 1)
        # 假 MAC 必须出现在毒包中、真实网关 MAC 必须出现在恢复包中
        poison = iso.build_poison()[0]
        self.assertEqual(str(poison[ARP].hwsrc).lower(), fake)
        restore = iso.build_restore()[0]
        self.assertEqual(str(restore[ARP].hwsrc).lower(), "aa:bb:cc:dd:ee:01")

    def test_random_fake_mac(self):
        """未指定假 MAC 时应自动生成随机单播 MAC。"""
        from aegis_ir.netutils import is_unicast_mac

        iso = Isolator("10.0.0.50", "aa:bb:cc:dd:ee:50", "10.0.0.1", "aa:bb:cc:dd:ee:01")
        self.assertTrue(is_unicast_mac(iso.fake_mac))
        self.assertNotEqual(iso.fake_mac, "de:ad:be:ef:00:01")  # 不再是固定值
        # 两次生成的应不同
        iso2 = Isolator("10.0.0.50", "aa:bb:cc:dd:ee:50", "10.0.0.1", "aa:bb:cc:dd:ee:01")
        self.assertNotEqual(iso.fake_mac, iso2.fake_mac)

    def test_prepare_isolation_guardrails(self):
        from aegis_ir.netutils import get_route

        _, own_ip, gw_ip = get_route()
        if gw_ip and gw_ip != "0.0.0.0":
            with self.assertRaisesRegex(IsolationError, "网关"):
                prepare_isolation(gw_ip)
        if own_ip:
            with self.assertRaisesRegex(IsolationError, "本机"):
                prepare_isolation(own_ip)
        with self.assertRaisesRegex(IsolationError, "格式"):
            prepare_isolation("not-an-ip")
        with self.assertRaisesRegex(IsolationError, "直连网段|不在"):
            prepare_isolation("8.8.8.8")  # 经路由，跨网段（网络环境可能变化）

    def test_session_roundtrip(self):
        iso = Isolator("10.99.99.99", "aa:bb:cc:dd:ee:99", "10.99.99.1",
                       "aa:bb:cc:dd:ee:01")
        with mock.patch.object(discovery, "VAR_DIR", tempfile.mkdtemp()), \
             mock.patch("aegis_ir.isolation.SESSIONS_DIR",
                        os.path.join(tempfile.mkdtemp(), "sessions")):
            iso._save_session(active=True)
            path = find_session(victim_ip="10.99.99.99")
            with open(path, encoding="utf-8") as f:
                d = json.load(f)
            self.assertEqual(d["victim_ip"], "10.99.99.99")
            self.assertTrue(d["active"])


if __name__ == "__main__":
    unittest.main()
