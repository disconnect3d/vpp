#!/usr/bin/env python

from framework import VppTestCase, VppTestRunner
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.data import IP_PROTOS
from scapy.packet import bind_layers, Raw
from scapy.all import *
from util import ppp


class Event(Packet):
    name = "Event"
    fields_desc = [ByteEnumField("event_type", None,
                                 {1: "add", 2: "del", 3: "keepalive"}),
                   ByteEnumField("protocol", None,
                                 {0: "udp", 1: "tcp", 2: "icmp"}),
                   ShortField("flags", 0),
                   IPField("in_l_addr", None),
                   IPField("in_r_addr", None),
                   ShortField("in_l_port", None),
                   ShortField("in_r_port", None),
                   IPField("out_l_addr", None),
                   IPField("out_r_addr", None),
                   ShortField("out_l_port", None),
                   ShortField("out_r_port", None),
                   IntField("pool_id", None),
                   IntField("tenant_id", None)]

    def extract_padding(self, s):
        return "", s


class HANATStateSync(Packet):
    name = "HA NAT state sync"
    fields_desc = [XByteField("version", 1),
                   XByteField("rsvd", None),
                   FieldLenField("count", None, count_of="events"),
                   PacketListField("events", [], Event,
                                   count_from=lambda pkt:pkt.count)]


class TestHANATmapper(VppTestCase):
    """ HA NAT mapper test cases """

    @classmethod
    def setUpClass(cls):
        super(TestHANATmapper, cls).setUpClass()

        try:
            cls.create_pg_interfaces(range(2))
            cls.interfaces = list(cls.pg_interfaces)
            cls.local_sync_port = 12345
            cls.remote_sync_port = 12346
            cls.mapper_port = 12347

            for i in cls.interfaces:
                i.admin_up()
                i.config_ip4()
                i.resolve_arp()

        except Exception:
            super(TestHANATmapper, cls).tearDownClass()
            raise

    def test_hanat_state_sync_recv(self):
        self.vapi.papi.hanat_mapper_add_del_ext_addr_pool(prefix='2.3.4.0/28',
                                                          pool_id=2,
                                                          is_add=True)

        self.vapi.hanat_mapper_set_state_sync(self.pg0.local_ip4n,
                                              self.local_sync_port,
                                              self.pg0.remote_ip4n,
                                              self.remote_sync_port)

        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg0.local_ip4) /
             UDP(sport=self.remote_sync_port, dport=self.local_sync_port) /
             HANATStateSync(events=[
                 Event(event_type='add', protocol='tcp', in_l_addr='1.2.3.4',
                       in_r_addr='1.2.3.5', in_l_port=12345, in_r_port=80,
                       out_l_addr='2.3.4.5', out_r_addr='1.2.3.5',
                       out_l_port=34567, out_r_port=80, tenant_id=1,
                       pool_id=2),
                 Event(event_type='add', protocol='tcp', in_l_addr='1.2.3.6',
                       in_r_addr='1.2.3.5', in_l_port=12345, in_r_port=80,
                       out_l_addr='2.3.4.5', out_r_addr='1.2.3.5',
                       out_l_port=34756, out_r_port=80, tenant_id=1,
                       pool_id=2)]))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        users = self.vapi.hanat_mapper_user_dump()
        self.assertEqual(len(users), 2)
        for user in users:
            sessions = self.vapi.hanat_mapper_user_session_dump(user.address,
                                                                user.tenant_id)
            self.assertEqual(len(sessions), 1)

        stats = self.statistics.get_counter('/hanat-mapper/add-event-recv')
        self.assertEqual(stats[0][0], 2)

        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg0.local_ip4) /
             UDP(sport=self.remote_sync_port, dport=self.local_sync_port) /
             HANATStateSync(events=[
                 Event(event_type='del', protocol='tcp', in_l_addr='1.2.3.4',
                       in_r_addr='1.2.3.5', in_l_port=12345, in_r_port=80,
                       out_l_addr='2.3.4.5', out_r_addr='1.2.3.5',
                       out_l_port=34567, out_r_port=80, tenant_id=1,
                       pool_id=2)]))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        users = self.vapi.hanat_mapper_user_dump()
        self.assertEqual(len(users), 1)
        sessions = self.vapi.hanat_mapper_user_session_dump(users[0].address,
                                                            users[0].tenant_id)
        self.assertEqual(len(sessions), 1)

        stats = self.statistics.get_counter('/hanat-mapper/del-event-recv')
        self.assertEqual(stats[0][0], 1)

        stats = self.statistics.get_counter(
            '/err/hanat-state-sync/pkts-processed')
        self.assertEqual(stats, 2)

    def test_hanat_state_sync_send(self):
        bind_layers(UDP, HANATStateSync, sport=self.local_sync_port)
        self.vapi.hanat_mapper_set_state_sync(self.pg0.local_ip4n,
                                              self.local_sync_port,
                                              self.pg0.remote_ip4n,
                                              self.remote_sync_port)
        self.pg_enable_capture(self.pg_interfaces)
        cli_str = "hanat-mapper add session "
        cli_str += "in-local 1.2.3.4:12345 "
        cli_str += "in-remote 1.2.3.5:80 "
        cli_str += "out-local 2.3.4.5:34567 "
        cli_str += "out-remote 1.2.3.5:80 tcp tenant-id 1 pool-id 2"
        self.vapi.cli(cli_str)
        cli_str = "hanat-mapper add session "
        cli_str += "in-local 1.2.3.4:12346 "
        cli_str += "in-remote 1.2.3.5:80 "
        cli_str += "out-local 2.3.4.5:3467 "
        cli_str += "out-remote 1.2.3.5:80 tcp tenant-id 1 pool-id 2"
        self.vapi.cli(cli_str)
        self.vapi.cli("hanat-mapper state sync flush")
        capture = self.pg0.get_capture(1)
        p = capture[0]
        self.assert_packet_checksums_valid(p)
        self.assertEqual(p[IP].src, self.pg0.local_ip4)
        self.assertEqual(p[IP].dst, self.pg0.remote_ip4)
        self.assertEqual(p[UDP].sport, self.local_sync_port)
        self.assertEqual(p[UDP].dport, self.remote_sync_port)
        self.assertEqual(p[HANATStateSync].version, 1)
        self.assertEqual(p[HANATStateSync].count, 2)
        for event in p[HANATStateSync].events:
            self.assertEqual(event.event_type, 1)
            self.assertEqual(event.protocol, 1)
            self.assertEqual(event.in_l_addr, '1.2.3.4')
            self.assertEqual(event.in_r_addr, '1.2.3.5')
            self.assertEqual(event.out_l_addr, '2.3.4.5')
            self.assertEqual(event.out_r_addr, '1.2.3.5')
            self.assertEqual(event.in_r_port, 80)
            self.assertEqual(event.out_r_port, 80)
            self.assertIn(event.in_l_port, [12345, 12346])
            self.assertIn(event.out_l_port, [34567, 3467])
            self.assertEqual(event.tenant_id, 1)
            self.assertEqual(event.pool_id, 2)

        stats = self.statistics.get_counter('/hanat-mapper/add-event-send')
        self.assertEqual(stats[0][0], 2)

    def test_hanat_mapper(self):
        self.vapi.hanat_mapper_enable(self.mapper_port)
        p = (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
             IP(src=self.pg1.remote_ip4, dst=self.pg1.local_ip4) /
             UDP(sport=11111, dport=self.mapper_port))
        self.pg1.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(1)
        p = capture[0]
        self.assertEqual(p[IP].src, self.pg1.local_ip4)
        self.assertEqual(p[IP].dst, self.pg1.remote_ip4)
        self.assertEqual(p[UDP].sport, self.mapper_port)
        self.assertEqual(p[UDP].dport, 11111)

        stats = self.statistics.get_counter('/err/hanat-mapper/pkts-processed')
        self.assertEqual(stats, 1)

    def tearDown(self):
        super(TestHANATmapper, self).tearDown()
        if not self.vpp_dead:
            self.logger.info(self.vapi.cli("show hanat-mapper sessions"))

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
