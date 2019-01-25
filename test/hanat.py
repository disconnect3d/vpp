from scapy.all import *

hanattlvs = { 0: "HANAT_SESSION_REQUEST",
              1: "HANAT_SESSION_REPLY",
              2: "HANAT_SESSION_UPDATE",
              }

class _HANATGuessPayload:
    name = "Dummy lass that implements guess_payload_class()"
    def guess_payload_class(self,p):
        print('Guess payload')
        if len(p) > 1:
            return hanattlvs.get(orb(p[0]), Raw)

class HANATSessionRequest(_HANATGuessPayload, Packet):
    name = "HANAT Session Request"
    fields_desc = [ ByteField("type", 0),
                    ByteField("len", None),
                    IntField("sessionid", 0),
                    IntField("poolid", 0),
                    IPField("src", '0.0.0.0'),
                    IPField("dst", '0.0.0.0'),
                    ByteEnumField("proto", 0, IP_PROTOS),
                    ThreeBytesField("VNI", 0),
                    ShortField("sport", 0),
                    ShortField("dport", 0),]

class HANATSessionReply(_HANATGuessPayload, Packet):
    name = "HANAT Session Reply"
    fields_desc = [ ByteField("type", 1),
                    ByteField("len", None),
                    IntField("sessionid", 0),
                    FlagsField("instr", 0x1, 32,
                    ['NO_TRANSLATE', 'SRC', 'SRC_PORT',
                     'DST', 'DST_PORT', 'TCP_MSS']),
                    IPField("src", '0.0.0.0'),
                    IPField("dst", '0.0.0.0'),
                    ShortField("sport", 0),
                    ShortField("dport", 0)]

class HANAT(Packet):
    name = "HANAT"
    fields_desc = [ IntField("coreid", 0),]

bind_layers( UDP, HANAT, sport=1234)
bind_layers(HANAT, HANATSessionRequest)
bind_layers(HANAT, HANATSessionReply)

#def _get_cls(name):
#    return globals().get(name, Raw)
#
#def _load_dict(d):
#    for k, v in d.items():
#        d[k] = _get_cls(v)
#
#_load_dict(hanattlvs)
