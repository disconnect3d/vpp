from scapy.all import *

hanattlvs = { 0: "HANATSessionRequest",
              1: "HANATSessionBinding",
              2: "HANATSessionRefresh",
              }

class _HANATGuessPayload:
    name = "Dummy HANAT class that implements guess_payload_class()"

    def guess_payload_class(self, p):
        if len(p) > 1:
            return hanattlvs.get(orb(p[0]), Raw)

class HANATSessionRequest(_HANATGuessPayload, Packet):
    name = "HANAT Session Request"
    fields_desc = [ ByteField("type", 0),
                    ByteField("len", 26),
                    IntField("sessionid", 0),
                    IntField("poolid", 0),
                    IPField("src", '0.0.0.0'),
                    IPField("dst", '0.0.0.0'),
                    ByteEnumField("proto", 0, IP_PROTOS),
                    ThreeBytesField("VNI", 0),
                    ShortField("sport", 0),
                    ShortField("dport", 0),]

class HANATSessionBinding(_HANATGuessPayload, Packet):
    name = "HANAT Session Binding"
    fields_desc = [ ByteField("type", 1),
                    ByteField("len", 20),
                    IntField("sessionid", 0),
                    FlagsField("instr", 0x1, 32,
                    ['NO_TRANSLATE', 'SRC', 'SRC_PORT',
                     'DST', 'DST_PORT', 'TCP_MSS']),
                    IntField("VNI", 0),
                    IPField("src", '0.0.0.0'),
                    IPField("dst", '0.0.0.0'),
                    ShortField("sport", 0),
                    ShortField("dport", 0)]

class HANATSessionRefresh(_HANATGuessPayload, Packet):
    name = "HANAT Session Refresh"
    fields_desc = [ ByteField("type", 2),
                    ByteField("len", 20),
                    IPField("src", '0.0.0.0'),
                    IPField("dst", '0.0.0.0'),
                    ByteEnumField("proto", 0, IP_PROTOS),
                    ThreeBytesField("VNI", 0),
                    ShortField("sport", 0),
                    ShortField("dport", 0)]


class HANAT(_HANATGuessPayload, Packet):
    name = "HANAT"
    fields_desc = [ IntField("coreid", 0)]

def _get_cls(name):
    return globals().get(name, Raw)


def _load_dict(d):
    for k, v in d.items():
        d[k] = _get_cls(v)

_load_dict(hanattlvs)

bind_layers(UDP, HANAT, dport=1234)
