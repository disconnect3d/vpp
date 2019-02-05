#!/usr/bin/env python

from framework import VppTestCase, VppTestRunner
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.data import IP_PROTOS
from scapy.packet import bind_layers, Raw
from vpp_papi import VppEnum
from scapy.all import *
from util import ppp
from hanat import *


class TestHANAT(VppTestCase):
    """ HA NAT mapper & worker test cases """

    @classmethod
    def setUpClass(cls):
        super(TestHANAT, cls).setUpClass()

        try:
            cls.create_pg_interfaces(range(3))
            cls.interfaces = list(cls.pg_interfaces)
            cls.mapper_port = 1234
            cls.worker_port = 4321
            cls.pool_id = 0

            for i in cls.interfaces:
                i.admin_up()
                i.config_ip4()
                i.resolve_arp()

        except Exception:
            super(TestHANAT, cls).tearDownClass()
            raise

        bind_layers(UDP, HANAT, dport=cls.mapper_port)
        bind_layers(UDP, HANAT, dport=cls.worker_port)

    def test_mapper_and_worker(self):
        rv = self.vapi.hanat_mapper_enable(self.mapper_port)
        self.assertEqual(rv.retval, 0)
        rv = self.vapi.papi.hanat_mapper_add_del_ext_addr_pool(prefix='172.16.2.3/32',
                                                               pool_id=self.pool_id,
                                                               is_add=True)
        self.assertEqual(rv.retval, 0)

        rv = self.vapi.papi.hanat_worker_mapper_add_del(is_add=True,
                                                        pool_id=self.pool_id,
                                                        pool='172.16.2.3/32',
                                                        src=self.pg2.local_ip4,
                                                        mapper=self.pg2.remote_ip4,
                                                        udp_port=self.mapper_port)
        self.assertEqual(rv.retval, 0)

        buckets = [rv.mapper_index]*1024
        rv = self.vapi.papi.hanat_worker_mapper_buckets(mapper_index=buckets)
        self.assertEqual(rv.retval, 0)

        mode=VppEnum.vl_api_hanat_worker_if_mode_t.HANAT_WORKER_IF_INSIDE
        rv = self.vapi.papi.hanat_worker_interface_add_del(sw_if_index=self.pg0.sw_if_index,
                                                           mode=mode,
                                                           is_add=True)
        self.assertEqual(rv.retval, 0)

        mode=VppEnum.vl_api_hanat_worker_if_mode_t.HANAT_WORKER_IF_OUTSIDE
        rv = self.vapi.papi.hanat_worker_interface_add_del(sw_if_index=self.pg1.sw_if_index,
                                                           mode=mode,
                                                           is_add=True)
        self.assertEqual(rv.retval, 0)

        rv = self.vapi.papi.hanat_worker_enable(udp_port=self.worker_port)
        self.assertEqual(rv.retval, 0)

        rv = self.vapi.papi.hanat_worker_cache_clear()
        self.assertEqual(rv.retval, 0)

        # create packet that should be translated based on mapper config
        pkt = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
               IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) /
               TCP(sport=8000, dport=80))

        self.logger.error(pkt.show2())

        self.pg0.add_stream(pkt)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # HANAT Session Request packet
        # forward packet from worker to mapper
        pkt = self.swap_and_send(self.pg2)
        self.logger.error(pkt.show2())

        self.assertEqual(pkt[IP].src, self.pg2.remote_ip4)
        self.assertEqual(pkt[UDP].sport, self.worker_port)
        self.assertEqual(pkt[UDP].dport, self.mapper_port)

        self.assertEqual(pkt[HANATSessionRequest].src, self.pg0.remote_ip4)
        self.assertEqual(pkt[HANATSessionRequest].dst, self.pg1.remote_ip4)
        self.assertEqual(pkt[HANATSessionRequest].sport, 8000)
        self.assertEqual(pkt[HANATSessionRequest].dport, 80)

        # HANAT Session Binding packet
        # forward packet from mapper to worker
        pkt = self.swap_and_send(self.pg2)
        self.logger.error(pkt.show2())

        self.assertEqual(pkt[IP].src, self.pg2.remote_ip4)
        self.assertEqual(pkt[UDP].sport, self.mapper_port)
        self.assertEqual(pkt[UDP].dport, self.worker_port)

        self.assertEqual(pkt[HANATSessionBinding].src, '172.16.2.3')
        self.assertEqual(pkt[HANATSessionBinding].dst, self.pg1.remote_ip4)
        self.assertEqual(pkt[HANATSessionBinding].dport, 80)

        sport = pkt[HANATSessionBinding].sport

        # get packet after NAT translation
        pkt =  self.pg1.get_capture(1)[0]

        self.logger.error(pkt.show2())

        # test if the translation is correct
        self.assertEqual(pkt[IP].src, '172.16.2.3')
        self.assertEqual(pkt[IP].dst, self.pg1.remote_ip4)
        self.assertEqual(pkt[TCP].sport, sport)
        self.assertEqual(pkt[TCP].dport, 80)

        # TODO: now send out2in packet

    def swap_and_send(self, pg, idx=0):

        pkt = pg.get_capture(1)[idx]

        # swap ethernet header src&dst
        tmp = pkt.src
        pkt.src = pkt.dst
        pkt.dst = tmp

        # swap ip header src&dst
        tmp = pkt[IP].src
        pkt[IP].src = pkt[IP].dst
        pkt[IP].dst = tmp

        pg.add_stream(pkt)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        return pkt

