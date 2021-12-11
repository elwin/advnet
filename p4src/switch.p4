/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

//My includes
#include "include/headers.p4"
#include "include/parsers.p4"

//My defines
//ADD DEFINES

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
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

    action set_path(macAddr_t dstAddr, bit<32> hops, bit<8> hop_count) {
        // This action is only called on the first switch after the
        // sending host. Here, we set the encoded hops list as well
        // as the number of hops.
        hdr.path.hops = hops;
        hdr.path.hop_count = hop_count;

        // Here we cheat a bit: Instead of setting the MAC address of
        // the next switch, we simply already set it to the MAC address
        // of the end host (since this is the only one who cares).
        // After that, we forget about it.
        hdr.ethernet.dstAddr = dstAddr;
    }

    table forwarding_table {
        key = {
            hdr.ipv4.dstAddr: lpm;
            meta.hash: exact;
        }
        actions = {
            set_path;
            drop;
        }
        size = 1024;
        default_action = drop;
    }

    apply {
        if (!hdr.path.isValid()) {
            // Here we encounter a packet coming directly from the host,
            // i.e. the path header is not yet set. We enable it
            // and query the forwarding_table for the correct path.

            hdr.path.setValid();
            hdr.path.etherType = hdr.ethernet.etherType;
            hdr.ethernet.etherType = TYPE_PATH;

            if (hdr.ipv4.isValid()) {
                if (hdr.udp.isValid()) {
                    random(meta.hash, (bit<8>)0, (bit<8>)9);
                } else if (hdr.tcp.isValid()) {
                    hash(meta.hash,
                        HashAlgorithm.crc16,
                        (bit<1>) 0,
                        { hdr.ipv4.srcAddr,
                            hdr.ipv4.dstAddr,
                            hdr.tcp.srcPort,
                            hdr.tcp.dstPort,
                            hdr.ipv4.protocol
                        }, (bit<8>) 10
                    );
                }

                forwarding_table.apply();
            }
        }

        // Extract the next hop from the encoded hop list. Let's say the
        // list looks like this: 0x123
        // The last 4 bits (i.e. 0x3) denote the next hop, while the
        // remaining 2x4 bits (i.e. 0x12) denote the hops that will
        // follow after that, including the egress to the end host.
        bit<9> next_hop = (bit<9>) (hdr.path.hops - ((hdr.path.hops >> 4) << 4));
        hdr.path.hops = (hdr.path.hops >> 4);
        hdr.path.hop_count = hdr.path.hop_count - 1;

        standard_metadata.egress_spec = next_hop;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;

        if (hdr.path.hop_count == 0) {
            // Once hop_count has reached 0, this means we're now at the
            // last switch before the end host. Here, we simply remove
            // our header and set the packet to the host.
            hdr.ethernet.etherType = hdr.path.etherType;
            hdr.path.setInvalid();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    apply {

    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	          hdr.ipv4.ihl,
              hdr.ipv4.dscp,
              hdr.ipv4.ecn,
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
***********************  S W I T C H  *******************************
*************************************************************************/

//switch architecture
V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
