#!/usr/bin/env python
"""HANAT Worker functional tests"""

import unittest
from scapy.layers.inet import Ether, IP, UDP, TCP, GRE
from scapy.all import fragment, RandShort, bind_layers, Packet
from framework import VppTestCase, VppTestRunner
from vpp_ip import DpoProto
from vpp_ip_route import VppIpRoute, VppRoutePath, VppIpTable
from util import reassemble4
from vpp_papi import VppEnum
from hanat import *
import pprint

hanat_configured=False

def session_binding_reply(packet, interface):
    session_id = packet[HANATSessionRequest].session_id

    # Send session binding
    p_ether = Ether(dst=interface.local_mac, src=interface.remote_mac)
    p_ip4 = IP(src=interface.remote_ip4, dst=interface.local_ip4) / UDP(sport=1234, dport=1234)

    hb = (HANATSessionBinding(src='5.5.5.5', dst='6.6.6.6', sport=11, dport=12,
                              instr='SRC+SRC_PORT', session_id=session_id))

    p4 = (p_ether / p_ip4 / HANAT() / hb)
    return p4

def get_binding_reply(packet, post):
    session_id = packet[HANATSessionRequest].session_id
    sa = packet[HANATSessionRequest].src
    da = packet[HANATSessionRequest].dst
    sp = packet[HANATSessionRequest].sport
    dp = packet[HANATSessionRequest].dport
    instr = post['instr']

    if 'SRC' in instr:
        sa = post['post_sa']
    if 'SRC_PORT' in instr:
        sp = post['post_sp']
    if 'DST' in instr:
        da = post['post_da']
    if 'DST_PORT' in instr:
        dp = post['post_dp']

    i = '+'.join(instr)
    print('INSTRUCTION', i)
    # Send session binding
    udp = UDP(sport=1234, dport=1234)

    if 'gre' in post:
        hb = (HANATSessionBinding(src=sa, dst=da, sport=sp, dport=dp, instr=i, session_id=session_id,
                                  gre=post['gre'], VNI=post['vni'], len=30))
    else:
        vni = post['vni'] if 'vni' in post else 0
        hb = (HANATSessionBinding(src=sa, dst=da, sport=sp, dport=dp, instr=i, session_id=session_id, VNI=vni))

    return (udp / HANAT() / hb)

def get_reply(packet, post):
    reply = packet.copy()
    instr = post['instr']
    if 'SRC' in instr:
        reply[IP].src = post['post_sa']
    if 'DST' in instr:
        reply[IP].dst = post['post_da']

    if packet[IP].proto == 6:
        if 'SRC_PORT' in instr:
            reply[TCP].sport = post['post_sp']
        if 'DST_PORT' in instr:
            reply[TCP].dport = post['post_dp']
    elif packet[IP].proto == 17:
        if 'SRC_PORT' in instr:
            reply[UDP].sport = post['post_sp']
        if 'DST_PORT' in instr:
            reply[UDP].dport = post['post_dp']
    elif packet[IP].proto == 1:
        if 'SRC_PORT' in instr:
            reply[ICMP].id = post['post_sp']
        if 'DST_PORT' in instr:
            reply[ICMP].id = post['post_dp']
    else:
        raise NotImplemented

    return reply

def get_packet_layers(packet):
    counter = 0
    while True:
        layer = packet.getlayer(counter)
        if layer is None:
            break
        yield layer
        counter += 1

class TestHANAT(VppTestCase):
    """ HANAT Worker Test Case """


    def validate(self, rx, expected):
        for i, layer in enumerate(get_packet_layers(expected)):
            if layer.name == 'IP':
                expected[i].ttl = rx[i].ttl
                expected[i].id = rx[i].id
        self.assertEqual(rx, expected.__class__(expected))

    @classmethod
    def setUpClass(cls):
        super(TestHANAT, cls).setUpClass()
        # pg0 - inside interface
        # pg1 - outside interface
        # pg2 - worker - mapper interface
        cls.create_pg_interfaces(range(3))
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

    def hanat_configure(self):
        global hanat_configured

        # Route for "the Internet"
        route = VppIpRoute(self, "8.0.0.0", 8,
                           [VppRoutePath(self.pg1.remote_ip4,
                                         self.pg1.sw_if_index)])

        route.add_vpp_config()


        if hanat_configured:
            return
        hanat_configured=True
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
                                                        src=self.pg2.remote_ip4,
                                                        mapper=self.pg2.local_ip4,
                                                        udp_port=1234)

        print('RV', rv)
        buckets = [1]*1024
        rv = self.vapi.papi.hanat_worker_mapper_buckets(mapper_index=buckets)
        print('RV', rv)

        mode=VppEnum.vl_api_hanat_worker_if_mode_t.HANAT_WORKER_IF_OUTSIDE
        rv = self.vapi.papi.hanat_worker_interface_add_del(sw_if_index=self.pg1.sw_if_index,
                                                           is_add=True,
                                                           mode=mode)
        self.assertEqual(rv.retval, 0)


    def test_hanat_gre(self):
        """ hanat_worker GRE test """

        self.hanat_configure()
        rv = self.vapi.papi.hanat_worker_enable(udp_port=1234, gre_src=self.pg0.local_ip4)
        self.assertEqual(rv.retval, 0)
       
        rv = self.vapi.papi.hanat_worker_cache_clear()
        self.assertEqual(rv.retval, 0)

        print(self.vapi.cli("show ip fib"))
        tests = [
            {'name': 'Simple TCP SYN', 'in2out': True,
             'src': self.pg0.remote_ip4, 'dst': '8.8.8.9', 'protocol': 'TCP', 'sport': 40002, 'dport': 5555, 'vni': 123,
             'post': {'instr': ['SRC', 'SRC_PORT'], 'post_sa': '130.67.1.1', 'post_sp': 11, 'vni': 0}},
            {'name': 'Simple TCP SYN reverse', 'in2out': False,
             'src': '8.8.8.9', 'dst': '130.67.1.1', 'protocol': 'TCP', 'sport': 5555, 'dport': 11,
             'post': {'instr': ['DST','DST_PORT'], 'post_da': self.pg0.remote_ip4, 'post_dp': 40002,
                      'gre': self.pg0.remote_ip4, 'vni': 123}},
        ]

        p_ether_pg0 = Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
        p_ether_pg1 = Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac)
        p_ether_pg2 = Ether(dst=self.pg2.local_mac, src=self.pg2.remote_mac)
        p_ip_pg0 = IP(src=self.pg0.remote_ip4, dst=self.pg0.local_ip4)
        p_ip_pg0_return = IP(src=self.pg0.local_ip4, dst=self.pg0.remote_ip4)
        p_ip_pg1 = IP(src=self.pg1.remote_ip4, dst=self.pg1.local_ip4)
        p_ip_pg2 = IP(src=self.pg2.remote_ip4, dst=self.pg2.local_ip4)
        
        for t in tests:
            print('Running: ' + t['name'])
            ip = IP(src=t['src'], dst=t['dst'])
            if t['protocol'] == 'TCP':
                l4 = TCP(sport=t['sport'], dport=t['dport'])
            elif t['protocol'] == 'UDP':
                l4 = UDP(sport=t['sport'], dport=t['dport'])
            elif t['protocol'] == 'ICMP':
                l4 = ICMP(id=t['identifier'])
            else:
                raise NotImplemented()

            # Send packet in inside interface, expect session request
            if t['in2out']:
                tx_interface = self.pg0
                rx_interface = self.pg1
                p = p_ether_pg0 / p_ip_pg0 / GRE(key_present=1,key=t['vni']) / ip / l4
            else:
                tx_interface = self.pg1
                rx_interface = self.pg0
                p = p_ether_pg1 / ip / l4

            print('SENDING PACKET')
            p.show2()
            rx = self.send_and_expect(tx_interface, p*1, self.pg2)[0] # Or rx_interface
            if rx.getlayer(HANAT):
                print("SESSION")
                rx.show2()
                udp_binding_reply = get_binding_reply(rx, post=t['post'])
                binding_reply = p_ether_pg2 / p_ip_pg2 / udp_binding_reply
                binding_reply.show2()

                # Send binding reply and expect data packet
                rx = self.send_and_expect(self.pg2, binding_reply*1, rx_interface)[0]
            print("HERE SHOULD BE THE DATA PACKET")
            rx.show2()
            if t['in2out']:
                reply = get_reply(p[3], t['post'])
            else:
                r = get_reply(p[1], t['post'])
                reply = p_ip_pg0_return / GRE(key_present=1,key=t['post']['vni']) / r

            self.validate(rx[1], reply)

            # Send packet through cached entry
            print("TRYING TO SEND THROUGH CACHE")
            p.show2()
            rx = self.send_and_expect(tx_interface, p*1, rx_interface)[0] # Or rx_interface
            print('RECEIVED AFTER FORWARDING')
            rx.show2()
            self.validate(rx[1], reply)

        rv = self.vapi.papi.hanat_worker_cache_dump()
        self.assertEqual(len(rv), len(tests))
        pp = pprint.PrettyPrinter()
        pp.pprint(rv)


    def test_hanat(self):
        """ hanat_worker basic test """

        self.hanat_configure()

        rv = self.vapi.papi.hanat_worker_enable(udp_port=1234)
        self.assertEqual(rv.retval, 0)

        rv = self.vapi.papi.hanat_worker_cache_clear()
        self.assertEqual(rv.retval, 0)

        # Enable hanat-worker input feature
        mode=VppEnum.vl_api_hanat_worker_if_mode_t.HANAT_WORKER_IF_INSIDE
        rv = self.vapi.papi.hanat_worker_interface_add_del(sw_if_index=self.pg0.sw_if_index,
                                                           is_add=True, mode=mode)
        self.assertEqual(rv.retval, 0)

        # key = {'sa': self.pg0.remote_ip4,
        #        'da': '8.8.8.8',
        #        'fib_index': 0,
        #        'sp': 1234,
        #        'dp': 80,
        #        'proto': 6}

        #instructions = (VppEnum.vl_api_hanat_instructions_t.HANAT_INSTR_SOURCE_ADDRESS +
        #                VppEnum.vl_api_hanat_instructions_t.HANAT_INSTR_SOURCE_PORT +
        #                VppEnum.vl_api_hanat_instructions_t.HANAT_INSTR_DESTINATION_PORT)


        #instructions = (VppEnum.vl_api_hanat_instructions_t.HANAT_INSTR_SOURCE_ADDRESS)

        #rv = self.vapi.papi.hanat_worker_cache_add(key=key, instructions=instructions, post_sa='1.1.1.1', post_sp=4002,
        #                                           post_dp=5555)
        #self.assertEqual(rv.retval, 0)


        # Table of input packets
        # Generate input packet, send input packet
        # Respond to session requests
        # Verify output packets
        tests = [
            {'name': 'Simple TCP SYN', 'in2out': True,
             'src': self.pg0.remote_ip4, 'dst': '8.8.8.9', 'protocol': 'TCP', 'sport': 40002, 'dport': 5555,
             'post': {'instr': ['SRC', 'SRC_PORT'], 'post_sa': '130.67.1.1', 'post_sp': 11}},
            {'name': 'Simple TCP SYN reverse', 'in2out': False,
             'src': '8.8.8.9', 'dst': '130.67.1.1', 'protocol': 'TCP', 'sport': 5555, 'dport': 11,
             'post': {'instr': ['DST','DST_PORT'], 'post_da': self.pg0.remote_ip4, 'post_dp': 40002}},

            {'name': 'Simple UDP', 'in2out': True,
             'src': self.pg0.remote_ip4, 'dst': '8.8.8.9', 'protocol': 'UDP', 'sport': 40002, 'dport': 5555,
             'post': {'instr': ['SRC', 'SRC_PORT'], 'post_sa': '130.67.1.1', 'post_sp': 11}},
            {'name': 'Simple UDP reverse', 'in2out': False,
             'src': '8.8.8.9', 'dst': '130.67.1.1', 'protocol': 'UDP', 'sport': 5555, 'dport': 11,
             'post': {'instr': ['DST','DST_PORT'], 'post_da': self.pg0.remote_ip4, 'post_dp': 40002}},

            {'name': 'Simple ICMP', 'in2out': True,
             'src': self.pg0.remote_ip4, 'dst': '8.8.8.9', 'protocol': 'ICMP', 'identifier': 40002,
             'post': {'instr': ['SRC', 'SRC_PORT'], 'post_sa': '130.67.1.1', 'post_sp': 11, 'post_dp': 11}},
            {'name': 'Simple ICMP reverse', 'in2out': False,
             'src': '8.8.8.9', 'dst': '130.67.1.1', 'protocol': 'ICMP', 'identifier': 11,
             'post': {'instr': ['DST','DST_PORT'], 'post_da': self.pg0.remote_ip4, 'post_dp': 40002}},
        ]

        p_ether_pg0 = Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
        p_ether_pg1 = Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac)
        p_ether_pg2 = Ether(dst=self.pg2.local_mac, src=self.pg2.remote_mac)
        p_ip_pg1 = IP(src=self.pg1.remote_ip4, dst=self.pg1.local_ip4)
        p_ip_pg2 = IP(src=self.pg2.remote_ip4, dst=self.pg2.local_ip4)
        for t in tests:
            print('Running: ' + t['name'])
            ip = IP(src=t['src'], dst=t['dst'])
            if t['protocol'] == 'TCP':
                l4 = TCP(sport=t['sport'], dport=t['dport'])
            elif t['protocol'] == 'UDP':
                l4 = UDP(sport=t['sport'], dport=t['dport'])
            elif t['protocol'] == 'ICMP':
                l4 = ICMP(id=t['identifier'])
            else:
                raise NotImplemented()

            # Send packet in inside interface, expect session request
            if t['in2out']:
                tx_interface = self.pg0
                rx_interface = self.pg1
                p = p_ether_pg0 / ip / l4
            else:
                tx_interface = self.pg1
                rx_interface = self.pg0
                p = p_ether_pg1 / ip / l4

            rx = self.send_and_expect(tx_interface, p*1, self.pg2)[0] # Or rx_interface
            if rx.getlayer(HANAT):
                print("SESSION")
                p.show2()
                rx.show2()
                udp_binding_reply = get_binding_reply(rx, post=t['post'])
                binding_reply = p_ether_pg2 / p_ip_pg2 / udp_binding_reply
                binding_reply.show2()

                # Send binding reply and expect data packet
                rx = self.send_and_expect(self.pg2, binding_reply*1, rx_interface)[0]
            print("HERE SHOULD BE THE DATA PACKET")
            rx.show2()
            reply = get_reply(p[1], t['post'])
            self.validate(rx[1], reply)

            # Send packet through cached entry
            print("TRYING TO SEND THROUGH CACHE")
            p.show2()
            rx = self.send_and_expect(tx_interface, p*1, rx_interface)[0] # Or rx_interface
            self.validate(rx[1], reply)

        # Dump cache
        rv = self.vapi.papi.hanat_worker_cache_dump()
        self.assertEqual(len(rv), len(tests))
        pp = pprint.PrettyPrinter()
        pp.pprint(rv)
        rv = self.vapi.papi.hanat_worker_cache_clear()
        self.assertEqual(rv.retval, 0)
        rv = self.vapi.papi.hanat_worker_cache_dump()
        self.assertEqual(0, len(rv))

        mode=VppEnum.vl_api_hanat_worker_if_mode_t.HANAT_WORKER_IF_INSIDE
        rv = self.vapi.papi.hanat_worker_interface_add_del(sw_if_index=self.pg0.sw_if_index,
                                                           is_add=False, mode=mode)
        self.assertEqual(rv.retval, 0)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
