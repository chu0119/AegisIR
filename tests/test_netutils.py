"""netutils 单元测试（全部免权限可运行）。"""

import socket
import threading
import unittest

from aegis_ir.netutils import (_parse_arp_lines, is_onlink, is_unicast_mac,
                               list_interfaces, lookup_vendor, onlink_network,
                               sys_ping, tcp_connect_probe)


class TestArpParse(unittest.TestCase):
    def test_windows_format(self):
        text = """
接口: 10.113.34.64 --- 0x14
  Internet 地址          物理地址          类型
  10.113.32.1          00-00-5e-00-01-05     动态
  10.113.34.65         aa-bb-cc-dd-ee-ff     静态
"""
        table = _parse_arp_lines(text)
        self.assertEqual(table["10.113.32.1"], "00:00:5e:00:01:05")
        self.assertEqual(table["10.113.34.65"], "aa:bb:cc:dd:ee:ff")

    def test_linux_format(self):
        text = "10.0.0.1 ether 52:54:00:ab:cd:ef C reachable"
        table = _parse_arp_lines(text)
        self.assertEqual(table["10.0.0.1"], "52:54:00:ab:cd:ef")

    def test_garbage_ignored(self):
        self.assertEqual(_parse_arp_lines("no useful line\n1234"), {})


class TestPrivilegedFreeProbes(unittest.TestCase):
    def test_sys_ping_loopback(self):
        self.assertTrue(sys_ping("127.0.0.1", timeout_ms=800))

    def test_tcp_connect_probe_open_and_dead(self):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        try:
            hits = tcp_connect_probe("127.0.0.1", [port], timeout=1.0)
            self.assertIn((port, "open"), hits)
        finally:
            srv.close()
        # 关闭后的端口：拒绝（存活）或超时（不可判定），绝不能报 open
        hits = tcp_connect_probe("127.0.0.1", [port], timeout=0.5)
        self.assertNotIn((port, "open"), hits)


class TestEnvironment(unittest.TestCase):
    def test_list_interfaces_shape(self):
        ifaces = list_interfaces()
        self.assertGreaterEqual(len(ifaces), 1)
        for ifc in ifaces:
            self.assertTrue(ifc["ip"])
            self.assertTrue(ifc["id"])
            self.assertIsInstance(ifc["is_default"], bool)
            self.assertIn("network", ifc)
            self.assertIn("gateway", ifc)
        self.assertTrue(any(i["is_default"] for i in ifaces))

    def test_onlink_network_no_crash(self):
        net = onlink_network()
        self.assertTrue(net is None or net.num_addresses > 0)

    def test_is_onlink_routed_false(self):
        self.assertFalse(is_onlink("8.8.8.8"))

    def test_vendor_lookup(self):
        self.assertTrue(lookup_vendor("00:00:5E:00:01:05"))
        self.assertEqual(lookup_vendor(""), "")

    def test_unicast_mac(self):
        self.assertTrue(is_unicast_mac("de:ad:be:ef:00:01"))
        self.assertFalse(is_unicast_mac("01:00:5e:00:00:01"))  # 组播位


if __name__ == "__main__":
    unittest.main()
