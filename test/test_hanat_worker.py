#!/usr/bin/env python
"""HANAT Worker functional tests"""

import unittest
from scapy.layers.inet import Ether, IP, UDP, TCP
from scapy.all import fragment, RandShort, bind_layers, Packet
from framework import VppTestCase, VppTestRunner
from vpp_ip import DpoProto
from vpp_ip_route import VppIpRoute, VppRoutePath, VppIpTable
from util import reassemble4
from vpp_papi import VppEnum
from hanat import *

class TestHANAT(VppTestCase):
    """ HANAT Worker Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestHANAT, cls).setUpClass()
        cls.create_pg_interfaces(range(2))
        cls.interfaces = list(cls.pg_interfaces)

    def setUp(self):
        super(TestHANAT, self).setUp()
        for i in self.interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

    def tearDown(self):
        super(TestHANAT, self).tearDown()
        if not self.vpp_dead:
            for i in self.pg_interfaces:
                i.unconfig_ip4()
                i.admin_down()

    def validate(self, rx, expected):
        self.assertEqual(rx, expected.__class__(expected))

    def test_hanat(self):
        """ hanat_worker basic test """

        rv = self.vapi.papi.hanat_worker_enable(udp_port=1234)
        self.assertEqual(rv.retval, 0)

        # Configure the mapper for a pool
        rv = self.vapi.papi.hanat_worker_mapper_add_del(is_add=True,
                                                        pool_id=0,
                                                        pool='130.67.0.0/24',
                                                        src='1.1.1.1',
                                                        mapper='1.2.3.4',
                                                        udp_port=1234)


        print('RV', rv)
        rv = self.vapi.papi.hanat_worker_mapper_add_del(is_add=True,
                                                        pool_id=0,
                                                        pool='130.67.1.0/24',
                                                        src=self.pg1.remote_ip4,
                                                        mapper=self.pg1.local_ip4,
                                                        udp_port=1234)

        print('RV', rv)
        buckets = [1]*1024
        rv = self.vapi.papi.hanat_worker_mapper_buckets(mapper_index=buckets)
        print('RV', rv)

        # Enable hanat-worker input feature
        mode=VppEnum.vl_api_hanat_worker_if_mode_t.HANAT_WORKER_IF_INSIDE
        rv = self.vapi.papi.hanat_worker_interface_add_del(sw_if_index=self.pg0.sw_if_index,
                                                           is_add=True,
                                                           mode=mode)
        self.assertEqual(rv.retval, 0)

        route = VppIpRoute(self, "0.0.0.0", 0,
                           [VppRoutePath(self.pg1.remote_ip4,
                                         self.pg1.sw_if_index)])

        #route.add_vpp_config()

        key = {'sa': self.pg0.remote_ip4,
               'da': '8.8.8.8',
               'fib_index': 0,
               'sp': 1234,
               'dp': 80,
               'proto': 6}

        #instructions = (VppEnum.vl_api_hanat_instructions_t.HANAT_INSTR_SOURCE_ADDRESS +
        #                VppEnum.vl_api_hanat_instructions_t.HANAT_INSTR_SOURCE_PORT +
        #                VppEnum.vl_api_hanat_instructions_t.HANAT_INSTR_DESTINATION_PORT)
        instructions = (VppEnum.vl_api_hanat_instructions_t.HANAT_INSTR_SOURCE_ADDRESS)

        rv = self.vapi.papi.hanat_worker_cache_add(key=key, instructions=instructions, post_sa='1.1.1.1', post_sp=4002,
                                                   post_dp=5555)
        self.assertEqual(rv.retval, 0)

        '''
        # Send a v4 TCP SYN packet (cache hit)
        p_ether = Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
        p_ip4 = IP(src=self.pg0.remote_ip4, dst='8.8.8.8') / TCP(sport=1234, dport=80, flags="S")
        p4 = (p_ether / p_ip4)
        p_ip4_reply = IP(src='1.1.1.1', dst='8.8.8.8', ttl=63) / TCP(sport=4002, dport=5555, flags="S")
        rx = self.send_and_expect(self.pg0, p4*1, self.pg1)
        for p in rx:
            self.validate(p[1], p_ip4_reply)
        '''
        # Send a v4 TCP SYN packet (cache miss)
        p_ether = Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
        p_ip4 = IP(src=self.pg0.remote_ip4, dst='8.8.8.9') / TCP(sport=1234, dport=80, flags="S")
        p4 = (p_ether / p_ip4)
        p_ip4_reply = IP(src='1.1.1.1', dst='8.8.8.8', ttl=63) / TCP(sport=4002, dport=5555, flags="S")
        rx = self.send_and_expect(self.pg0, p4*1, self.pg1)
        for p in rx:
            p.show2()
            #self.validate(p[1], p_ip4_reply)

        p_ether = Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
        hb = HANATSessionBinding(src='5.5.5.5', dst='6.6.6.6', sport=11, dport=12, instr='SRC')
        p_ip4 = IP(src=self.pg1.remote_ip4, dst=self.pg1.local_ip4) / UDP(sport=1234, dport=1234) / HANAT() / hb
        p4 = (p_ether / p_ip4)
        p4.show2()
        self.send_and_assert_no_replies(self.pg1, p4 * 1)
        #for p in rx:
        #    p.show2()

        # Send session binding


        # Dump cache
        rv = self.vapi.papi.hanat_worker_cache_dump()
        print('RV', rv)
        self.assertEqual(2, len(rv))

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
