/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

// My includes
#include "include/headers.p4"
#include "include/parsers.p4"

// My defines
const bit<4> CLASS_TCP    = 1;
const bit<4> CLASS_UDP    = 2;
#define PATH_WIDTH 32
#define REGISTER_SIZE 1024
#define TIMESTAMP_WIDTH 48
#define FLOWLET_TIMEOUT 48w27500
#define N_PORTS 32


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

    counter(32, CounterType.packets_and_bytes) port_counter;

    direct_meter<bit<32>>(MeterType.bytes) our_meter;

    // Seed for random number generator
    bit<7> seed;

    // Registers to save known flows, egress ports of known flows and timestamps of known flows
    register<bit<PATH_WIDTH>>(REGISTER_SIZE)      hops_reg;
    register<bit<8>>(REGISTER_SIZE)               hop_count_reg;
    register<bit<48>>(REGISTER_SIZE)              dst_mac_addr_reg;
    register<bit<TIMESTAMP_WIDTH>>(REGISTER_SIZE) flowlet_time_stamp_reg;

    // Register for checking the state of the output link
    register<bit<1>>(N_PORTS) link_state;


    action drop() {
        mark_to_drop(standard_metadata);
    }

    action send_heartbeat() {
        // we make sure the other switch treats the packet as probe from the other side
        hdr.heartbeat.from_cp = 0;
        standard_metadata.egress_spec = hdr.heartbeat.port;
    }

    action recognise_flowlet() {

        if (hdr.tcp.isValid()) {
            meta.src_port = hdr.tcp.srcPort;
            meta.dst_port = hdr.tcp.dstPort;
        }

        else if (hdr.udp.isValid()) {
            meta.src_port = hdr.udp.srcPort;
            meta.dst_port = hdr.udp.dstPort;
        }

        hash(meta.flowlet_register_index,
        HashAlgorithm.crc16,
        (bit<1>)0,
        { hdr.ipv4.srcAddr,
        hdr.ipv4.dstAddr,
        meta.src_port,
        meta.dst_port,
        hdr.ipv4.protocol},
        (bit<14>)1024);

        //Read previous time stamp
        hop_count_reg.read(meta.f_hop_count_saved, (bit<32>)meta.flowlet_register_index);

        //Read previous time stamp
        flowlet_time_stamp_reg.read(meta.flowlet_last_stamp, (bit<32>)meta.flowlet_register_index);

        //Update timestamp
        flowlet_time_stamp_reg.write((bit<32>)meta.flowlet_register_index, standard_metadata.ingress_global_timestamp);

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

    action limit_rate() {
        our_meter.read(meta.meter_tag);
    }

    // action rewriteMac(macAddr_t dstAddr){
	//     hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
    //     hdr.ethernet.dstAddr = dstAddr;
    // }

    table forwarding_table {
        key = {
            hdr.ipv4.dstAddr: lpm;
            meta.hash: exact;
            meta.classification: exact;
        }
        actions = {
            set_path;
            drop;
        }
        size = 1024;
        default_action = drop;
    }

    table rate_limiting {
        key = {
            meta.udp_rate_limit_id: exact;
        }
        actions = {
            limit_rate;
            drop;
        }
        size = 8;
        meters = our_meter;
        default_action = drop;
    }

    table alt_forwarding_table {
        key = {
            meta.next_hop: exact;
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            set_path;
            drop;
        }
        size = 1024;
        default_action = drop;
    }

    // table rewrite_mac {
    //     key = {
    //          meta.next_hop: exact;
    //     }
    //     actions = {
    //         rewriteMac;
    //         drop;
    //     }
    //     size = 512;
    //     default_action = drop;
    // }

    apply {
        port_counter.count((bit<32>) standard_metadata.ingress_port);

        if (hdr.heartbeat.isValid()) {
            if (hdr.heartbeat.from_cp == 1) {
                send_heartbeat(); return;
            }

            else {
                drop(); return;
            }

        }

        if (!hdr.ipv4.isValid()) {
            drop(); return;
        }

        // Rate-limiting of UDP packets
        if (hdr.udp.isValid()) {

            if (hdr.udp.srcPort < 100) {
                meta.udp_rate_limit_id = 0;
            }
            else if ((hdr.udp.srcPort >= 100) && (hdr.udp.srcPort < 200)) {
                meta.udp_rate_limit_id = 1;
            }
            else if ((hdr.udp.srcPort >= 200) && (hdr.udp.srcPort < 300)) {
                meta.udp_rate_limit_id = 2;
            }
            else if ((hdr.udp.srcPort >= 300) && (hdr.udp.srcPort < 400)) {
                meta.udp_rate_limit_id = 3;
            }
            else {
                meta.udp_rate_limit_id = 4;
            }
            rate_limiting.apply();
            /* If meter is yellow we randomly drop with a probability*/
            if (meta.meter_tag == 1)
            {
                // Drop with a probability of 30%
                random(seed, (bit<7>)0, (bit<7>)100);
                if (seed <= 30) {
                    drop(); return;
                }
            }
            // If meter is red we drop all 
            else if (meta.meter_tag == 2) {
                drop(); return;
            }

        }

        if (!hdr.path.isValid()) {
            // Here we encounter a packet coming directly from the host,
            // i.e. the path header is not yet set. We enable it
            // and query the forwarding_table for the correct path.

            hdr.path.setValid();
            hdr.path.protocol = hdr.ipv4.protocol;
            hdr.ipv4.protocol = TYPE_PATH;

            // Check if flow has been seen before by the src switch
            recognise_flowlet();
            meta.flowlet_time_diff = standard_metadata.ingress_global_timestamp - meta.flowlet_last_stamp;

            // check if inter-packet gap is > 100ms (for known flow) or flow unknown
            if (meta.flowlet_time_diff > FLOWLET_TIMEOUT || meta.f_hop_count_saved == 0) {

                if (hdr.udp.isValid()) {
                    meta.classification = CLASS_UDP;
                    random(meta.hash, (bit<8>)0, (bit<8>)9);
                } else if (hdr.tcp.isValid()) {
                    meta.classification = CLASS_TCP;
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
                hops_reg.write((bit<32>)meta.flowlet_register_index, hdr.path.hops);
                hop_count_reg.write((bit<32>)meta.flowlet_register_index, hdr.path.hop_count);
                dst_mac_addr_reg.write((bit<32>)meta.flowlet_register_index, hdr.ethernet.dstAddr);

            }

            // Flow is known to the src switch and no timeout
            else {
                // Read next hops saved for the specific flow
                hops_reg.read(hdr.path.hops, (bit<32>)meta.flowlet_register_index);
                hdr.path.hop_count = meta.f_hop_count_saved;

                // Read dst MAC address
                dst_mac_addr_reg.read(hdr.ethernet.dstAddr, (bit<32>)meta.flowlet_register_index);
            }


        }

        // Extract the next hop from the encoded hop list. Let's say the
        // list looks like this: 0x123
        // The last 4 bits (i.e. 0x3) denote the next hop, while the
        // remaining 2x4 bits (i.e. 0x12) denote the hops that will
        // follow after that, including the egress to the end host.
        meta.next_hop = (bit<9>) (hdr.path.hops - ((hdr.path.hops >> 4) << 4));

        // Check if the chosen output link is available, 0 means link down, 1 means link up
        link_state.read(meta.linkState, (bit<32>)meta.next_hop);

        // If link is down
        if (meta.linkState == 0 && hdr.tcp.isValid()) {
            alt_forwarding_table.apply();
            meta.next_hop = (bit<9>) (hdr.path.hops - ((hdr.path.hops >> 4) << 4));
        }

        hdr.path.hops = (hdr.path.hops >> 4);
        hdr.path.hop_count = hdr.path.hop_count - 1;

        standard_metadata.egress_spec = meta.next_hop;
        //rewrite_mac.apply();
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;

        if (hdr.path.hop_count == 0) {
            // Once hop_count has reached 0, this means we're now at the
            // last switch before the end host. Here, we simply remove
            // our header and set the packet to the host.
            hdr.ipv4.protocol = hdr.path.protocol;
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
