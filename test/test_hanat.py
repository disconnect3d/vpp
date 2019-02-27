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
            cls.configured = False
            cls.mapper_port = 1234
            cls.worker_port = 4321
            cls.pool_id = 1
            cls.tcp_port_in = 6303
            cls.tcp_external_port = 80

            for i in cls.interfaces:
                i.admin_up()
                i.config_ip4()
                i.resolve_arp()

        except Exception:
            super(TestHANAT, cls).tearDownClass()
            raise

        bind_layers(UDP, HANAT, dport=cls.mapper_port)
        bind_layers(UDP, HANAT, dport=cls.worker_port)

    def clear_plugins(self):
        pools = self.vapi.papi.hanat_mapper_ext_addr_pool_dump()
        for pool in pools:
            self.vapi.papi.hanat_mapper_add_del_ext_addr_pool(
                prefix=pool.prefix, pool_id=pool.pool_id, is_add=False)

        mappers = self.vapi.papi.hanat_worker_mapper_dump()
        for mapper in mappers:
            self.vapi.papi.hanat_worker_mapper_add_del(
                is_add=False, pool_id=mapper.pool_id, pool=mapper.pool,
                src=mapper.src, mapper=mapper.mapper, udp_port=mapper.udp_port)

        interfaces = self.vapi.papi.hanat_worker_interfaces()
        for interface in interfaces.ifs:
            self.vapi.papi.hanat_worker_interface_add_del(
                sw_if_index=interface.sw_if_index, mode=interface.mode,
                is_add=False)

    def simulate_hanat_proto(self):

        # HANAT Session Request packet
        # forward packet from worker to mapper
        pkt_1 = self.capture_swap_and_send(self.pg2)

        # HANAT Session Binding packet
        # forward packet from mapper to worker
        pkt_2 = self.capture_swap_and_send(self.pg2)

        return pkt_1, pkt_2

    def configure_plugins(self, prefix='172.16.2.4/30',
                          mapper_pool_id=0, worker_pool_id=None):

        if self.configured:
            return

        self.configured = True

        if not mapper_pool_id:
            mapper_pool_id = self.pool_id

        rv = self.vapi.papi.hanat_mapper_enable(port=self.mapper_port)
        self.assertEqual(rv.retval, 0)

        rv = self.vapi.papi.hanat_mapper_add_del_ext_addr_pool(
            prefix=prefix, pool_id=mapper_pool_id, is_add=True)
        self.assertEqual(rv.retval, 0)

        if not worker_pool_id:
            worker_pool_id = mapper_pool_id

        rv = self.vapi.papi.hanat_worker_mapper_add_del(
            is_add=True, pool_id=worker_pool_id, pool=prefix,
            src=self.pg2.local_ip4, mapper=self.pg2.remote_ip4,
            udp_port=self.mapper_port)
        self.assertEqual(rv.retval, 0)

        buckets = [rv.mapper_index]*1024
        rv = self.vapi.papi.hanat_worker_mapper_buckets(mapper_index=buckets)
        self.assertEqual(rv.retval, 0)

        mode = VppEnum.vl_api_hanat_worker_if_mode_t.HANAT_WORKER_IF_INSIDE
        rv = self.vapi.papi.hanat_worker_interface_add_del(
            sw_if_index=self.pg0.sw_if_index, mode=mode, is_add=True)
        self.assertEqual(rv.retval, 0)

        mode = VppEnum.vl_api_hanat_worker_if_mode_t.HANAT_WORKER_IF_OUTSIDE
        rv = self.vapi.papi.hanat_worker_interface_add_del(
            sw_if_index=self.pg1.sw_if_index, mode=mode, is_add=True)
        self.assertEqual(rv.retval, 0)

        rv = self.vapi.papi.hanat_worker_enable(udp_port=self.worker_port)
        self.assertEqual(rv.retval, 0)

        rv = self.vapi.papi.hanat_worker_cache_clear()
        self.assertEqual(rv.retval, 0)

    def test_decline(self):

        self.configure_plugins(worker_pool_id=self.pool_id + 1)

        self.logger.error(self.vapi.cli("clear counters"))

        pkt = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
               IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) /
               TCP(sport=8000, dport=80))
        self.pg0.add_stream(pkt)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # HANAT Session Request packet
        # forward packet from worker to mapper
        pkt = self.capture_swap_and_send(self.pg2)
        self.logger.error(pkt.show2())

        # HANAT Session Decline packet
        # forward packet from mapper to worker
        pkt = self.capture_swap_and_send(self.pg2)
        self.logger.error(pkt.show2())

        # TODO:
        # receive ICMP error message
        # pkt = self.pg0.get_capture(1)

    def test_in2out_icmp(self):

        self.configure_plugins()

        pkt = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
               IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) /
               ICMP(type=8, code=0, id=0, seq=0))

        self.pg0.add_stream(pkt)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # HANAT Session Request packet
        # forward packet from worker to mapper
        pkt = self.capture_swap_and_send(self.pg2)
        self.logger.error(pkt.show2())

        # HANAT Session Binding packet
        # forward packet from mapper to worker
        pkt = self.capture_swap_and_send(self.pg2)
        self.logger.error(pkt.show2())

        pkt = self.pg1.get_capture(1)

    def test_in2out_session(self):

        self.configure_plugins()

        # in2out packet
        # create packet that should be translated based on mapper config
        pkts = list()
        for sport, dport in ((9000, 90), (8000, 80)):
            pkts.append(
                Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
                IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) /
                TCP(sport=sport, dport=dport))
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # HANAT Session Request packet
        # forward packet from worker to mapper
        pkt = self.capture_swap_and_send(self.pg2)
        self.logger.error(pkt.show2())

        self.assertEqual(pkt[IP].src, self.pg2.remote_ip4)
        self.assertEqual(pkt[UDP].sport, self.worker_port)
        self.assertEqual(pkt[UDP].dport, self.mapper_port)

        self.assertEqual(pkt[HANATSessionRequest].src, self.pg0.remote_ip4)
        self.assertEqual(pkt[HANATSessionRequest].dst, self.pg1.remote_ip4)
        self.assertEqual(pkt[HANATSessionRequest].sport, 9000)
        self.assertEqual(pkt[HANATSessionRequest].dport, 90)

        # HANAT Session Binding packet
        # forward packet from mapper to worker
        pkt = self.capture_swap_and_send(self.pg2)
        self.logger.error(pkt.show2())

        self.assertEqual(pkt[IP].src, self.pg2.remote_ip4)
        self.assertEqual(pkt[UDP].sport, self.mapper_port)
        self.assertEqual(pkt[UDP].dport, self.worker_port)

        self.assertEqual(pkt[HANATSessionBinding].src, '172.16.2.4')
        self.assertEqual(pkt[HANATSessionBinding].dst, self.pg1.remote_ip4)
        self.assertEqual(pkt[HANATSessionBinding].dport, 90)

        # TODO: update HANAT protocol definition
        # ip4_1 = pkt[HANATSessionBinding][0].src
        # ip4_2 = pkt[HANATSessionBinding][1].src
        # sport_1 = pkt[HANATSessionBinding][0].sport
        # sport_2 = pkt[HANATSessionBinding][1].sport

        # get packet after NAT translation (in2out)
        pkt_1, pkt_2 = pkts = self.pg1.get_capture(2)

        # test if the translation is correct
        for pkt in pkts:
            self.logger.error(pkt.show2())
            self.assertEqual(pkt[IP].src, '172.16.2.4')
            self.assertEqual(pkt[IP].dst, self.pg1.remote_ip4)

        self.assertEqual(pkt_1[TCP].dport, 90)
        self.assertEqual(pkt_2[TCP].dport, 80)

        # out2in packet (aka reply)
        for pkt in self.swap_and_send(self.pg1, pkts, True):
            self.logger.error(pkt.show2())

        # HANAT Session Request packet
        # forward packet from worker to mapper
        pkt = self.capture_swap_and_send(self.pg2)
        self.logger.error(pkt.show2())

        # HANAT Session Binding packet
        # forward packet from mapper to worker
        pkt = self.capture_swap_and_send(self.pg2)
        self.logger.error(pkt.show2())

        # get the packet after NAT translation (out2in)
        pkt_1, pkt_2 = pkts = self.pg0.get_capture(2)

        for pkt in pkts:
            self.logger.error(pkt.show2())
            self.assertEqual(pkt[IP].src, self.pg1.remote_ip4)
            self.assertEqual(pkt[IP].dst, self.pg0.remote_ip4)

        self.assertEqual(pkt_1[TCP].sport, 90)
        self.assertEqual(pkt_1[TCP].dport, 9000)
        self.assertEqual(pkt_2[TCP].sport, 80)
        self.assertEqual(pkt_2[TCP].dport, 8000)

    def swap_packet(self, pkt, swap_ports=False):

        # swap ethernet header src&dst
        tmp = pkt.src
        pkt.src = pkt.dst
        pkt.dst = tmp

        # swap ip header src&dst
        tmp = pkt[IP].src
        pkt[IP].src = pkt[IP].dst
        pkt[IP].dst = tmp

        # swap tcp/udp header sport&dport
        if swap_ports and (TCP in pkt or UDP in pkt):
            proto = TCP if TCP in pkt else UDP
            tmp = pkt[proto].sport
            pkt[proto].sport = pkt[proto].dport
            pkt[proto].dport = tmp

        return pkt

    def swap_and_send(self, pg, pkts, swap_ports=False):

        if type(pkts) != list:
            pkts = list(pkts)

        swaped = list()
        for pkt in pkts:
            swaped.append(self.swap_packet(pkt, swap_ports))

        pg.add_stream(swaped)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        return swaped

    def capture_swap_and_send(self, pg, idx=0):

        pkt = pg.get_capture(1)[idx]

        return self.swap_and_send(pg, pkt)[0]

    def test_mss_clamping(self):
        """ TCP MSS clamping """

        self.configure_plugins()

        p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) /
             TCP(sport=self.tcp_port_in, dport=self.tcp_external_port,
                 flags="S", options=[('MSS', 1400)]))

        rv = self.vapi.papi.hanat_mapper_set_mss_clamping(mss_value=1000,
                                                          enable=1)
        self.assertEqual(rv.retval, 0)

        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # session is already cached no more communication required beteween
        # mapper and worker after this one
        self.simulate_hanat_proto()

        capture = self.pg1.get_capture(1)
        # Negotiated MSS value greater than configured - changed
        self.verify_mss_value(capture[0], 1000)

        rv = self.vapi.papi.hanat_worker_cache_clear()
        self.assertEqual(rv.retval, 0)

        rv = self.vapi.papi.hanat_mapper_set_mss_clamping(mss_value=1500,
                                                          enable=0)
        self.assertEqual(rv.retval, 0)

        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        self.simulate_hanat_proto()

        capture = self.pg1.get_capture(1)
        # MSS clamping disabled - negotiated MSS unchanged
        self.verify_mss_value(capture[0], 1400)

        rv = self.vapi.papi.hanat_worker_cache_clear()
        self.assertEqual(rv.retval, 0)

        rv = self.vapi.papi.hanat_mapper_set_mss_clamping(mss_value=1500,
                                                          enable=1)
        self.assertEqual(rv.retval, 0)

        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        self.simulate_hanat_proto()

        capture = self.pg1.get_capture(1)
        # Negotiated MSS value smaller than configured - unchanged
        self.verify_mss_value(capture[0], 1400)

    def test_icmp_error_msg(self):
        """ ICMP Error Messages """

        self.configure_plugins()

        # create session by sending TCP packet
        pkt = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
               IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) /
               TCP(sport=8000, dport=80))
        self.pg0.add_stream(pkt)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        self.simulate_hanat_proto()
        pkt = self.pg1.get_capture(1)[0]
        self.logger.error(pkt.show2())

        dyn_addr = pkt[IP].src
        dyn_port = pkt[TCP].sport

        # send out2in ICMP Error Message
        self.logger.error(self.send_icmp_error_msg(self.pg1,
            self.pg1.remote_ip4, self.pg1.local_ip4,
            pkt[1]).show2())

        self.simulate_hanat_proto()
        pkt = self.pg0.get_capture(1)[0]
        self.logger.error(pkt.show2())

        inner_ip = pkt[IPerror]
        inner_tcp = pkt[TCPerror]

        self.assertEqual(inner_ip.src, self.pg0.remote_ip4)
        self.assertEqual(inner_ip.dst, self.pg1.remote_ip4)
        self.assertEqual(inner_tcp.sport, 8000)
        self.assertEqual(inner_tcp.dport, 80)

        # send in2out ICMP Error Message
        self.logger.error(self.send_icmp_error_msg(self.pg0,
            self.pg0.remote_ip4, self.pg1.remote_ip4,
            IP(src=self.pg1.remote_ip4, dst=self.pg0.remote_ip4) /
            TCP(sport=80, dport=8000)).show2())

        pkt = self.pg1.get_capture(1)[0]
        self.logger.error(pkt.show2())

        inner_ip = pkt[IPerror]
        inner_tcp = pkt[TCPerror]

        self.assertEqual(inner_ip.src, self.pg1.remote_ip4)
        self.assertEqual(inner_ip.dst, dyn_addr)
        self.assertEqual(inner_tcp.sport, 80)
        self.assertEqual(inner_tcp.dport, dyn_port)

    def send_icmp_error_msg(self, pg, src, dst, tcp_udp):
        p = (Ether(src=pg.remote_mac, dst=pg.local_mac) /
             IP(src=src, dst=dst) /
             ICMP(type=3, code=3) / tcp_udp)
        pg.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        return p

    def verify_mss_value(self, pkt, mss):
        """
        Verify TCP MSS value

        :param pkt:
        :param mss:
        """
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            raise TypeError("Not a TCP/IP packet")

        for option in pkt[TCP].options:
            if option[0] == 'MSS':
                self.assertEqual(option[1], mss)
                self.assert_tcp_checksum_valid(pkt)


    def tearDown(self):
        super(TestHANAT, self).tearDown()
        if not self.vpp_dead:
            self.logger.info(self.vapi.cli("show hanat-mapper sessions"))
            self.clear_plugins()

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
