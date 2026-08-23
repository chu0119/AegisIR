"""v2.1 新增功能的单元测试。"""

import unittest
from unittest import mock

from aegis_ir import discovery
from aegis_ir.netutils import generate_token, parse_scan_spec


class TestScanSpec(unittest.TestCase):
    def test_cidr(self):
        ips, label, is_range = parse_scan_spec("192.168.1.0/24")
        self.assertIsNone(ips)
        self.assertEqual(label, "192.168.1.0/24")
        self.assertFalse(is_range)

    def test_range(self):
        ips, label, is_range = parse_scan_spec("10.0.0.10-10.0.0.13")
        self.assertEqual(ips, ["10.0.0.10", "10.0.0.11", "10.0.0.12", "10.0.0.13"])
        self.assertTrue(is_range)
        self.assertEqual(label, "10.0.0.10-10.0.0.13")

    def test_range_errors(self):
        with self.assertRaises(ValueError):
            parse_scan_spec("10.0.0.5-10.0.0.1")      # 终点小于起点
        with self.assertRaises(ValueError):
            parse_scan_spec("10.0.0.1-10.0.9.999")    # 非法 IP
        with self.assertRaises(ValueError):
            parse_scan_spec("10.0.0.1-10.4.0.1")      # 超 1024 上限
        with self.assertRaises(ValueError):
            parse_scan_spec("192.168.0.0/8")          # 网段超上限

    def test_force_bypass_limit(self):
        ips, _, _ = parse_scan_spec("10.0.0.1-10.0.8.255", force=True)
        self.assertEqual(len(ips), 2303)  # 255 + 8*256，端点闭区间


class TestToken(unittest.TestCase):
    def test_token_shape_and_uniqueness(self):
        t1, t2 = generate_token(), generate_token()
        self.assertEqual(len(t1), 18)
        self.assertNotEqual(t1, t2)
        int(t1, 16)  # 合法十六进制


class TestPassiveMode(unittest.TestCase):
    def test_passive_sends_nothing(self):
        """纯被动模式不得触发任何主动探测（ping/TCP 均不应被调用）。"""
        fake_table = {"10.0.0.1": "aa:bb:cc:00:00:01"}
        with mock.patch.object(discovery, "parse_arp_table", return_value=fake_table), \
             mock.patch("aegis_ir.netutils.sys_ping",
                        side_effect=AssertionError("被动模式不应发送 ping")), \
             mock.patch("aegis_ir.netutils.tcp_connect_probe",
                        side_effect=AssertionError("被动模式不应发起 TCP 连接")):
            hits, macs, _ = discovery.compat_sweep(
                ["10.0.0.1", "10.0.0.2"],
                lambda ip: ip == "10.0.0.1",
                passive=True, log=lambda *a, **k: None)
        self.assertEqual(hits, {"10.0.0.1": ["ARP表"]})
        self.assertEqual(macs, fake_table)


if __name__ == "__main__":
    unittest.main()
