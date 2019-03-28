#include <core.p4>
#include <psa.p4>

struct EMPTY { };

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
}

parser MyIP(
    packet_in packet,
    out headers a,
    inout EMPTY b,
    in psa_ingress_parser_input_metadata_t c,
    in EMPTY d,
    in EMPTY e) {

    value_set<bit<16>>(4) pvs;
    state start {
        transition parse_ethernet;
    }
    state parse_ipv4 {
        packet.extract(a.ipv4);
        transition accept;
    }
    state parse_ethernet {
        packet.extract(a.ethernet);
        transition select(a.ethernet.etherType) {
            16w0x800: parse_ipv4;
            default: accept;
        }
    }
}

parser MyEP(
    packet_in packet,
    out EMPTY a,
    inout EMPTY b,
    in psa_egress_parser_input_metadata_t c,
    in EMPTY d,
    in EMPTY e,
    in EMPTY f) {
    state start {
        transition accept;
    }
}

control MyIC(
    inout headers a,
    inout EMPTY b,
    in psa_ingress_input_metadata_t c,
    inout psa_ingress_output_metadata_t d) {
    action bcast() {
        d.multicast_group = (MulticastGroup_t) 1;
    }
    action set_dmac(bit<48> dmac) {
        headers.ethernet.dstAddr = dmac;
    }
    action set_nhop(bit<9> port) {
        d.egress_port = port;
        a.ipv4.ttl = a.ipv4.ttl + 8w255;
    }
    action set_nhop_redirect(bit<9> port) {
        d.egress_port = port;
        a.ipv4.ttl = a.ipv4.ttl + 8w255;
    }
    apply {


    }
}

control MyEC(
    inout EMPTY a,
    inout EMPTY b,
    in psa_egress_input_metadata_t c,
    inout psa_egress_output_metadata_t d) {
    apply { }
}

control MyID(
    packet_out packet,
    out EMPTY a,
    out EMPTY b,
    out EMPTY c,
    inout headers d,
    in EMPTY e,
    in psa_ingress_output_metadata_t f) {
    apply { }
}

control MyED(
    packet_out packet,
    out EMPTY a,
    out EMPTY b,
    inout EMPTY c,
    in EMPTY d,
    in psa_egress_output_metadata_t e,
    in psa_egress_deparser_input_metadata_t f) {
    apply { }
}

IngressPipeline(MyIP(), MyIC(), MyID()) ip;
EgressPipeline(MyEP(), MyEC(), MyED()) ep;

PSA_Switch(
    ip,
    PacketReplicationEngine(),
    ep,
    BufferingQueueingEngine()) main;
