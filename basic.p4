/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const int<17> LENGTH_4_BITMAP = 0b0001000000000010;
const int<33> LENGTH_5_BITMAP = 0b0;
const int<256> LENGTH_8_BITMAP = 0x0;
const int<512> LENGTH_9_BITMAP = 0x0;
const int<1024> LENGTH_10_BITMAP = 0x0;
const int<2048> LENGTH_11_BITMAP = 0x0;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

struct metadata {
    bit<32> length; // prefix length
    bit<32> numeric;
    bit<1> alreadyMatched;
    macAddr_t dstAddr;
    egressSpec_t outPort;
    bit<32> ip;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

/*FIRST STAGE OF BINARY SEARCH*/
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action process_next_hops_exact(macAddr_t dstAddr, egressSpec_t port) {
        meta.dstAddr = dstAddr;
        meta.outPort = port;
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action process_longer_prefixes_lpm(bit<1> matched, macAddr_t dstAddr, egressSpec_t port) {
        meta.alreadyMatched = matched;
        meta.dstAddr = dstAddr;
        meta.outPort = port;

        if (matched == 1) {
          standard_metadata.egress_spec = port;
          hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
          hdr.ethernet.dstAddr = dstAddr;
          hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        }
    }

    table next_hops_exact {
        key = {
            meta.length: exact;
            meta.numeric: exact;
        }
        actions = {
            process_next_hops_exact;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    table longer_prefixes_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
           process_longer_prefixes_lpm;
           drop;
           NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    apply {
    // find out the length of the longest matching prefix here
        bit<1> shouldContinue = 1;

        bit<5> val5 = (bit<5>) (hdr.ipv4.dstAddr >> 27);

        if ((LENGTH_5_BITMAP >> val5) & 0b1 == 0b1) {
           meta.length = 5;
           meta.numeric = (bit<32>)(val5);
           shouldContinue = 0;
        }

        bit<4> val4 = (bit<4>) (hdr.ipv4.dstAddr >> 28);
        //if (shouldContinue == 1 && (LENGTH_4_BITMAP >> val4) & 0b1 == 0b1) {
          meta.length = 4;
          meta.numeric = (bit<32>) val4;
          shouldContinue = 0;
          meta.ip = hdr.ipv4.dstAddr;
        //}
        meta.alreadyMatched = 0;

        // TCAM table lookup
        longer_prefixes_lpm.apply(); // prefixes longer than 24 bits

        // off-chip next-hop table lookup
        if (meta.alreadyMatched == 0) {
          next_hops_exact.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
