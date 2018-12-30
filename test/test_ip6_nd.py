#!/usr/bin/env python
"""IPv6 ND functional tests"""

import unittest
from scapy.layers.inet6 import IPv6, Ether, IP, UDP, ICMPv6ND_RS, ICMPv6ND_RA
from framework import VppTestCase, VppTestRunner
from socket import AF_INET, AF_INET6, inet_pton
import cbor


class TestIPv6ND(VppTestCase):
    """ IPv6 ND Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestIPv6ND, cls).setUpClass()
        cls.create_pg_interfaces(range(2))
        cls.interfaces = list(cls.pg_interfaces)

    def setUp(self):
        super(TestIPv6ND, self).setUp()
        for i in self.interfaces:
            i.admin_up()
            i.config_ip6()
            i.disable_ipv6_ra()
            i.resolve_ndp()

    def tearDown(self):
        super(TestIPv6ND, self).tearDown()
        if not self.vpp_dead:
            for i in self.pg_interfaces:
                i.unconfig_ip6()
                i.admin_down()

    def test_universal_ra(self):
        """ IPv6 Universal RA option """

        self.pg0.ip6_ra_config(send_unicast=1)

        p_ether = Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
        p_ip6 = IPv6(dst=self.pg0.local_ip6, src=self.pg0.remote_ip6)
        p = p_ether / p_ip6 / ICMPv6ND_RS()

        reply = p_ip6 / ICMPv6ND_RA()
        d = {'ietf': {
            'dns': {'dnssl': ['example.com']},
            'ipv6-only': True,
            'nat64': {'prefix': inet_pton(AF_INET6, '64:ff9b::'),
                      'prefixlen': 96}
        }}
        cbor_data = cbor.dumps(d)

        self.vapi.papi.sw_interface_ip6nd_ra_universal_option(
            sw_if_index=self.pg0.sw_if_index, len=len(cbor_data),
            cbor_data=cbor_data)
        rx = self.send_and_expect(self.pg0, p * 1, self.pg0)
        # Universal RA option is last. Skip over TL in the TLV
        dr = cbor.loads(rx[0][2].lastlayer().load[2:])
        self.assertEqual(dr, d)

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
