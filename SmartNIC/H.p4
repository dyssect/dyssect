#include <core.p4>
#include <v1model.p4>

header ethernet_t {
        bit<48> dst;
        bit<48> src;
        bit<16> etype;
}

header ipv4_t {
        bit<4> version;
        bit<4> ihl;
        bit<8> diffserv;
        bit<16> total_len;
        bit<16> id;
        bit<3> flags;
        bit<13> offset;
        bit<8> ttl;
        bit<8> protocol;
        bit<16> checksum;
        bit<32> src;
        bit<32> dst;
}

header tcp_t {
        bit<16> src;
        bit<16> dst;
        bit<32> seqno;
        bit<32> ackno;
        bit<4> data_offset;
        bit<4> reserved;
        bit<1> cwr;
        bit<1> ece;
        bit<1> urg;
        bit<1> ack;
        bit<1> psh;
        bit<1> rst;
        bit<1> syn;
        bit<1> fin;
        bit<16> window;
        bit<16> checksum;
        bit<16> urgent_ptr;
}

const bit<16>   ARP_TYPE        = 0x0806;
const bit<16>   IPV4_TYPE       = 0x0800;
const bit<8>    TCP_PROTO       = 0x06;

extern void processing();

struct metadata {

}

struct headers {
	ethernet_t 	ethernet;
	ipv4_t		ipv4;
	tcp_t		tcp;
}

parser ParserImpl(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
        state start {
		packet.extract(hdr.ethernet);
                transition select(hdr.ethernet.etype) {
			IPV4_TYPE:      parse_ipv4;
			default:        accept;
		}
        }
	state parse_ipv4 {
                packet.extract(hdr.ipv4);
                transition select(hdr.ipv4.protocol) {
                        TCP_PROTO:      parse_tcp;
                        default:        accept;
                }
        }
        state parse_tcp {
                packet.extract(hdr.tcp);
                transition accept;
        }
}

control verifyChecksum(inout headers hdr, inout metadata meta) {
        apply {

        }
}

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
	action act() {
		processing();
	}

	table tbl_direction {
		actions = {
			act;
			NoAction;
		}
		default_action = act();
        }

	apply {
		tbl_direction.apply();
	}
}

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
        apply {

        }
}

control computeChecksum(inout headers hdr, inout metadata meta) {
        apply {

        }
}

control DeparserImpl(packet_out packet, in headers hdr) {
        apply {
		packet.emit(hdr.ethernet);		
		packet.emit(hdr.ipv4);		
		packet.emit(hdr.tcp);		
        }
}

V1Switch(ParserImpl(), verifyChecksum(), ingress(), egress(), computeChecksum(), DeparserImpl()) main;
