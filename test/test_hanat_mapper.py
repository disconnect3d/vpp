#!/usr/bin/env python

from framework import VppTestCase, VppTestRunner
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.data import IP_PROTOS
from scapy.packet import bind_layers, Raw
from scapy.all import *
from util import ppp
from hanat import *
from time import sleep


class Event(Packet):
    name = "Event"
    fields_desc = [ByteEnumField("event_type", None,
                                 {1: "add", 2: "del", 3: "keepalive"}),
                   ByteEnumField("protocol", None,
                                 {0: "udp", 1: "tcp", 2: "icmp"}),
                   ByteField("flags", 0),
                   FieldLenField("opaque_len", None, fmt='B',
                                 length_of="opaque_data"),
                   IPField("in_l_addr", None),
                   IPField("in_r_addr", None),
                   ShortField("in_l_port", None),
                   ShortField("in_r_port", None),
                   IPField("out_l_addr", None),
                   IPField("out_r_addr", None),
                   ShortField("out_l_port", None),
                   ShortField("out_r_port", None),
                   IntField("pool_id", None),
                   IntField("tenant_id", None),
                   LongField("total_pkts", 0),
                   LongField("total_bytes", 0),
                   StrLenField("opaque_data", "",
                               length_from=lambda pkt: pkt.opaque_len)]

    def extract_padding(self, s):
        return "", s


class HANATStateSync(Packet):
    name = "HA NAT state sync"
    fields_desc = [XByteField("version", 1),
                   FlagsField("flags", 0, 8, ['ACK']),
                   FieldLenField("count", None, count_of="events"),
                   IntField("sequence_number", 1),
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
            cls.mapper_port = 1234

            for i in cls.interfaces:
                i.admin_up()
                i.config_ip4()
                i.resolve_arp()

        except Exception:
            super(TestHANATmapper, cls).tearDownClass()
            raise

    def test_hanat_state_sync_recv(self):
        bind_layers(UDP, HANATStateSync, sport=self.local_sync_port)

        self.vapi.papi.hanat_mapper_add_del_ext_addr_pool(prefix='2.3.4.0/28',
                                                          pool_id=2,
                                                          is_add=True)

        self.vapi.papi.hanat_mapper_set_state_sync_listener(
            ip_address=self.pg0.local_ip4,
            port=self.local_sync_port,
            path_mtu=512)

        listener = self.vapi.papi.hanat_mapper_get_state_sync_listener()
        self.assertEqual(str(listener.ip_address), self.pg0.local_ip4)
        self.assertEqual(listener.port, self.local_sync_port)
        self.assertEqual(listener.path_mtu, 512)

        users = self.vapi.hanat_mapper_user_dump()
        users_before = len(users)
        stats = self.statistics.get_counter('/hanat/mapper/total-users')
        usersn = stats[0][0]
        stats = self.statistics.get_counter('/hanat/mapper/total-mappings')
        mappingsn = stats[0][0]
        stats = self.statistics.get_counter('/hanat/mapper/total-sessions')
        sessionsn = stats[0][0]

        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg0.local_ip4) /
             UDP(sport=self.remote_sync_port, dport=self.local_sync_port) /
             HANATStateSync(sequence_number=1, events=[
                 Event(event_type='add', protocol='tcp', in_l_addr='1.2.3.4',
                       in_r_addr='1.2.3.5', in_l_port=12345, in_r_port=80,
                       out_l_addr='2.3.4.5', out_r_addr='1.2.3.5',
                       out_l_port=34567, out_r_port=80, tenant_id=1,
                       pool_id=2, opaque_data='AAAA'),
                 Event(event_type='add', protocol='tcp', in_l_addr='1.2.3.6',
                       in_r_addr='1.2.3.5', in_l_port=12345, in_r_port=80,
                       out_l_addr='2.3.4.5', out_r_addr='1.2.3.5',
                       out_l_port=34756, out_r_port=80, tenant_id=1,
                       pool_id=2,)]))

        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(1)
        p = capture[0]
        self.assertEqual(p[HANATStateSync].sequence_number, 1)
        self.assertEqual(p[HANATStateSync].flags, 'ACK')
        stats = self.statistics.get_counter(
            '/hanat/mapper/state-sync/ack-send')
        self.assertEqual(stats[0][0], 1)

        users = self.vapi.hanat_mapper_user_dump()
        self.assertEqual(len(users) - users_before, 2)
        for user in users:
            sessions = self.vapi.hanat_mapper_user_session_dump(user.address,
                                                                user.tenant_id)
            self.assertEqual(len(sessions), 1)
            self.assertIn(sessions[0].opaque_data, ['AAAA', ''])

        stats = self.statistics.get_counter(
            '/hanat/mapper/state-sync/add-event-recv')
        self.assertEqual(stats[0][0], 2)

        stats = self.statistics.get_counter('/hanat/mapper/total-users')
        self.assertEqual(stats[0][0] - usersn, 2)
        stats = self.statistics.get_counter('/hanat/mapper/total-mappings')
        self.assertEqual(stats[0][0] - mappingsn, 2)
        stats = self.statistics.get_counter('/hanat/mapper/total-sessions')
        self.assertEqual(stats[0][0] - sessionsn, 2)

        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg0.local_ip4) /
             UDP(sport=self.remote_sync_port, dport=self.local_sync_port) /
             HANATStateSync(sequence_number=2, events=[
                 Event(event_type='del', protocol='tcp', in_l_addr='1.2.3.4',
                       in_r_addr='1.2.3.5', in_l_port=12345, in_r_port=80,
                       out_l_addr='2.3.4.5', out_r_addr='1.2.3.5',
                       out_l_port=34567, out_r_port=80, tenant_id=1,
                       pool_id=2)]))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(1)
        p = capture[0]
        self.assertEqual(p[HANATStateSync].sequence_number, 2)
        self.assertEqual(p[HANATStateSync].flags, 'ACK')

        users = self.vapi.hanat_mapper_user_dump()
        self.assertEqual(len(users) - users_before, 1)
        sessions = self.vapi.hanat_mapper_user_session_dump(users[0].address,
                                                            users[0].tenant_id)
        self.assertEqual(len(sessions), 1)

        stats = self.statistics.get_counter(
            '/hanat/mapper/state-sync/del-event-recv')
        self.assertEqual(stats[0][0], 1)

        stats = self.statistics.get_counter(
            '/err/hanat-state-sync/pkts-processed')
        self.assertEqual(stats, 2)

        self.vapi.papi.hanat_mapper_add_del_ext_addr_pool(prefix='2.3.4.0/28',
                                                          pool_id=2,
                                                          is_add=False)

    def test_hanat_state_sync_send(self):
        bind_layers(UDP, HANATStateSync, sport=self.local_sync_port)

        self.vapi.papi.hanat_mapper_add_del_ext_addr_pool(prefix='2.3.4.0/28',
                                                          pool_id=2,
                                                          is_add=True)

        self.vapi.papi.hanat_mapper_set_state_sync_listener(
            ip_address=self.pg0.local_ip4,
            port=self.local_sync_port,
            path_mtu=512)

        rv = self.vapi.papi.hanat_mapper_add_del_state_sync_failover(
            ip_address=self.pg0.remote_ip4,
            port=self.remote_sync_port,
            is_add=True)

        self.vapi.papi.hanat_mapper_set_pool_failover(
            pool_id=2, failover_index=rv.failover_index)

        failover = self.vapi.papi.hanat_mapper_state_sync_failover_dump()
        self.assertEqual(len(failover), 1)
        self.assertEqual(str(failover[0].ip_address), self.pg0.remote_ip4)
        self.assertEqual(failover[0].port, self.remote_sync_port)
        self.assertEqual(failover[0].failover_index, rv.failover_index)

        pool = self.vapi.papi.hanat_mapper_ext_addr_pool_dump()
        self.assertEqual(len(pool), 1)
        self.assertEqual(str(pool[0].prefix), '2.3.4.0/28')
        self.assertEqual(pool[0].pool_id, 2)
        self.assertEqual(pool[0].failover_index, rv.failover_index)

        self.pg_enable_capture(self.pg_interfaces)
        cli_str = "hanat-mapper add session "
        cli_str += "in-local 1.2.3.4:12345 "
        cli_str += "in-remote 1.2.3.5:80 "
        cli_str += "out-local 2.3.4.5:34567 "
        cli_str += "out-remote 1.2.3.5:80 tcp tenant-id 1 pool-id 2"
        cli_str += "opaque 4141"
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
        seq = p[HANATStateSync].sequence_number
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
            self.assertIn(event.opaque_data, ['AA', ''])

        ack = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
               IP(src=self.pg0.remote_ip4, dst=self.pg0.local_ip4) /
               UDP(sport=self.remote_sync_port, dport=self.local_sync_port) /
               HANATStateSync(sequence_number=seq, flags='ACK'))
        self.pg0.add_stream(ack)
        self.pg_start()

        stats = self.statistics.get_counter(
            '/hanat/mapper/state-sync/add-event-send')
        self.assertEqual(stats[0][0], 2)
        stats = self.statistics.get_counter(
             '/hanat/mapper/state-sync/ack-recv')
        self.assertEqual(stats[0][0], 1)

        self.pg_enable_capture(self.pg_interfaces)
        cli_str = "hanat-mapper add session "
        cli_str += "in-local 1.2.3.4:12346 "
        cli_str += "in-remote 1.2.3.5:80 "
        cli_str += "out-local 2.3.4.5:3467 "
        cli_str += "out-remote 1.2.3.5:80 tcp tenant-id 1 pool-id 2 del"
        self.vapi.cli(cli_str)
        self.vapi.cli("hanat-mapper state sync flush")
        capture = self.pg0.get_capture(1)
        p = capture[0]
        self.assertGreater(p[HANATStateSync].sequence_number, seq)

        self.pg_enable_capture(self.pg_interfaces)
        sleep(12)
        stats = self.statistics.get_counter(
            '/hanat/mapper/state-sync/retry-count')
        self.assertEqual(stats[0][0], 3)
        stats = self.statistics.get_counter(
            '/hanat/mapper/state-sync/missed-count')
        self.assertEqual(stats[0][0], 1)
        capture = self.pg0.get_capture(3)
        for packet in capture:
            self.assertEqual(packet, p)

        self.vapi.papi.hanat_mapper_add_del_ext_addr_pool(prefix='2.3.4.0/28',
                                                          pool_id=2,
                                                          is_add=False)

    def test_hanat_protocol(self):
        session_id = 1
        self.vapi.hanat_mapper_enable(self.mapper_port)
        self.vapi.papi.hanat_mapper_add_del_ext_addr_pool(prefix='10.1.1.1/32',
                                                          pool_id=2,
                                                          is_add=True)

        # in2out
        p1 = (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
              IP(src=self.pg1.remote_ip4, dst=self.pg1.local_ip4) /
              UDP(sport=self.mapper_port, dport=self.mapper_port) / HANAT() /
              HANATSessionRequest(session_id=session_id, poolid=2,
              src='10.0.0.1', dst='10.1.1.2', proto=IP_PROTOS.udp,
              sport=1000, dport=1000, in2out=1))

        self.pg1.add_stream(p1)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        p1 = self.pg1.get_capture(1)[0]

        self.assertEqual(p1[IP].src, self.pg1.local_ip4)
        self.assertEqual(p1[IP].dst, self.pg1.remote_ip4)
        self.assertEqual(p1[UDP].sport, self.mapper_port)
        self.assertEqual(p1[UDP].dport, self.mapper_port)

        self.assertEqual(p1[HANATSessionBinding].type, 1)
        self.assertEqual(p1[HANATSessionBinding].src, '10.1.1.1')
        self.assertEqual(p1[HANATSessionBinding].dst, '10.1.1.2')
        self.assertEqual(p1[HANATSessionBinding].dport, 1000)

        sessions = self.vapi.papi.hanat_mapper_user_session_dump(
            address='10.0.0.1', tenant_id=0)
        self.assertEqual(len(sessions), 1)
        self.assertEqual(str(sessions[0].in_l_addr), '10.0.0.1')
        self.assertEqual(str(sessions[0].in_r_addr), '10.1.1.2')
        self.assertEqual(sessions[0].in_l_port, 1000)
        self.assertEqual(sessions[0].in_r_port, 1000)
        self.assertEqual(str(sessions[0].out_l_addr), '10.1.1.1')
        self.assertEqual(str(sessions[0].out_r_addr), '10.1.1.2')
        self.assertEqual(sessions[0].out_l_port,
                         p1[HANATSessionBinding].sport)
        self.assertEqual(sessions[0].tenant_id, 0)
        self.assertEqual(sessions[0].pool_id, 2)
        self.assertEqual(sessions[0].protocol, IP_PROTOS.udp)

        # out2in
        p2 = (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
              IP(src=self.pg1.remote_ip4, dst=self.pg1.local_ip4) /
              UDP(sport=self.mapper_port, dport=self.mapper_port) / HANAT() /
              HANATSessionRequest(session_id=session_id, poolid=2,
              src='10.1.1.2', dst='10.1.1.1', proto=IP_PROTOS.udp,
              sport=1000, dport=p1[HANATSessionBinding].sport, in2out=0))

        self.pg1.add_stream(p2)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        p2 = capture = self.pg1.get_capture(1)[0]

        self.assertEqual(p2[IP].src, self.pg1.local_ip4)
        self.assertEqual(p2[IP].dst, self.pg1.remote_ip4)
        self.assertEqual(p2[UDP].sport, self.mapper_port)
        self.assertEqual(p2[UDP].dport, self.mapper_port)

        self.assertEqual(p2[HANATSessionBinding].type, 1)
        self.assertEqual(p2[HANATSessionBinding].src, '10.1.1.2')
        self.assertEqual(p2[HANATSessionBinding].dst, '10.0.0.1')
        self.assertEqual(p2[HANATSessionBinding].sport, 1000)
        self.assertEqual(p2[HANATSessionBinding].dport, 1000)

        stats = self.statistics.get_counter('/err/hanat-mapper/pkts-processed')
        self.assertEqual(stats, 2)

    def tearDown(self):
        super(TestHANATmapper, self).tearDown()
        if not self.vpp_dead:
            self.logger.info(self.vapi.cli("show hanat-mapper sessions"))

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
