/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

// My includes
#include "include/headers.p4"
#include "include/parsers.p4"

// My defines
const bit<4> CLASS_TCP    = 1;
const bit<4> CLASS_UDP    = 2;
#define PATH_WIDTH          32
#define REGISTER_SIZE       1024
#define TIMESTAMP_WIDTH     48
#define FLOWLET_TIMEOUT     48w27500
#define N_PORTS             32
#define PROB_DROP_UDP       30
#define PATH_MULTIPLIER     10


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

    // Counter to count input traffic
    counter(32, CounterType.packets_and_bytes) port_counter;
    // Direct meter to perform rate-limiting
    direct_meter<bit<32>>(MeterType.bytes) our_meter;

    // Seed for random number generator
    bit<7> seed;

    // Registers to save paths of known flows
    register<bit<PATH_WIDTH>>(REGISTER_SIZE)      hops_reg;
    // Registers to save hop count of known flows
    register<bit<8>>(REGISTER_SIZE)               hop_count_reg;
    // Registers to save timestamps for known flows
    register<bit<TIMESTAMP_WIDTH>>(REGISTER_SIZE) flowlet_time_stamp_reg;

    // Register for checking the state of the output link
    // 0 means link down
    // 1 means link up
    register<bit<1>>(N_PORTS) link_state;


    action drop() {
        // Drop packet
        mark_to_drop(standard_metadata);
    }

    action send_heartbeat() {
        // We make sure the other switch treats the packet as probe from the other side
        hdr.heartbeat.from_cp = 0;
        standard_metadata.egress_spec = hdr.heartbeat.port;
    }

    action recognise_flowlet() {
        // Recognise flowlet
        // For TCP, set appropriate port numbers
        if (hdr.tcp.isValid()) {
            meta.src_port = hdr.tcp.srcPort;
            meta.dst_port = hdr.tcp.dstPort;
        }

        // For UDP, set appropriate port numbers
        else if (hdr.udp.isValid()) {
            meta.src_port = hdr.udp.srcPort;
            meta.dst_port = hdr.udp.dstPort;
        }

        // Hash the tuple
        hash(meta.flowlet_register_index,
        HashAlgorithm.crc16,
        (bit<1>)0,
        { hdr.ipv4.srcAddr,
        hdr.ipv4.dstAddr,
        meta.src_port,
        meta.dst_port,
        hdr.ipv4.protocol},
        (bit<14>)1024);

        //Read previous hop count saved
        hop_count_reg.read(meta.f_hop_count_saved, (bit<32>)meta.flowlet_register_index);

        // Read next hops (path) saved for the specific flow
        hops_reg.read(hdr.path.hops, (bit<32>)meta.flowlet_register_index);

        //Read previous time stamp
        flowlet_time_stamp_reg.read(meta.flowlet_last_stamp, (bit<32>)meta.flowlet_register_index);

        //Update timestamp
        flowlet_time_stamp_reg.write((bit<32>)meta.flowlet_register_index, standard_metadata.ingress_global_timestamp);

    }


    action set_path(bit<32> hops, bit<8> hop_count) {
        // This action is only called on the first switch after the
        // sending host. Here, we set the encoded hops list as well
        // as the number of hops.
        hdr.path.hops = hops;
        hdr.path.hop_count = hop_count;
    }

    action limit_rate() {
        // Read the colour of the meter
        our_meter.read(meta.meter_tag);
    }

    action do_nothing() {
        // empty function
    }

    action revoke_path() {
        // path is not valid anymore
        // reset path to dst
        meta.f_hop_count_saved = 0;
    }

    action rewrite_mac(macAddr_t dstAddr) {
        // Update the dst MAC address
	    hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
    }

    // Forwarding table run only on the directly connected switch of the sending host
    // Matches key: dst MAC address, the hash of the flow and the type of traffic (TCP, UDP)
    // Action: Creates the path that the traffic will follow until the destination switch
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

    // Table that performs rate-limiting of UDP traffic
    // Match key: range of ports
    // For ports 1-100:   meta.udp_rate_limit_id = 0
    // For ports 101-200: meta.udp_rate_limit_id = 1
    // For ports 201-300: meta.udp_rate_limit_id = 2
    // For ports 301-400: meta.udp_rate_limit_id = 3
    // For ports 60001-*: meta.udp_rate_limit_id = 4
    // Action: read the meter colour tag
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


    // Table that uses the alternative path in case of failure in the primary path
    // Match key: primary egress port and dst IP address
    // Action: Sets the new path that traffic will follow considering the failure
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

    // Table that checks the state of the selected saved path for only known flows
    // Only performed in the switch connected to the source host
    // If it still alive there is an entry on the table, so nothing will happen
    // If the path is not alive anymore due to failure, the path will be reset
    // Match key: saved path for the target destination
    // Actions:
    //          a) do_nothing  = empty function, just checking if the path is still alive
    //                           by checking if there is an entry on the table
    //          b) revoke_path = if the path is not valid anymore due to failure then
    //                           there will be no entry on the table and this action (default_action)
    //                           is used to reset the path to 0 and let the switch perform the computation again
    table path_state {
        key = {
            hdr.path.hops: exact;
        }
        actions = {
            do_nothing;
            revoke_path;
        }
        size = 1024;
        default_action = revoke_path;
    }

    // Table that sets the correct dst MAC address depending on the next hop
    // Match key: egress port
    // Action: Sets the correct dst MAC address of the next hop
    table egress_to_mac {
        key = {
             meta.next_hop: exact;
        }
        actions = {
            rewrite_mac;
            drop;
        }
        size = 512;
        default_action = drop;
    }

    apply {
        // Measure input traffic on the port
        port_counter.count((bit<32>) standard_metadata.ingress_port);

        // Receive heartbeat
        if (hdr.heartbeat.isValid()) {

            // If heartbeat received from control plane: Send heartbeat to the neighbour
            if (hdr.heartbeat.from_cp == 1) {
                send_heartbeat(); return;
            }

            // If heartbeat received from neighbour: Drop it
            else {
                drop(); return;
            }

        }

        // Drop all traffic apart from IP and drop traffic with ttl = 0
        // to avoid infinite loops in the network
        if (!hdr.ipv4.isValid() || hdr.ipv4.ttl == 0) {
            drop(); return;
        }

        // Decrease ttl
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;

        // Rate-limiting of UDP packets
        if (hdr.udp.isValid()) {

            // Map port ranges to a specific ID

            // For ports 1-100: meta.udp_rate_limit_id = 0
            if (hdr.udp.srcPort <= 100) {
                meta.udp_rate_limit_id = 0;
            }
            // For ports 101-200: meta.udp_rate_limit_id = 1
            else if ((hdr.udp.srcPort > 100) && (hdr.udp.srcPort <= 200)) {
                meta.udp_rate_limit_id = 1;
            }
            // For ports 201-300: meta.udp_rate_limit_id = 2
            else if ((hdr.udp.srcPort > 200) && (hdr.udp.srcPort <= 300)) {
                meta.udp_rate_limit_id = 2;
            }
            // For ports 301-400: meta.udp_rate_limit_id = 3
            else if ((hdr.udp.srcPort > 300) && (hdr.udp.srcPort <= 400)) {
                meta.udp_rate_limit_id = 3;
            }
            // For ports 60001-*: meta.udp_rate_limit_id = 4
            else {
                meta.udp_rate_limit_id = 4;
            }
            // Read the colour of the meter
            rate_limiting.apply();

            /* If meter is yellow we randomly drop with a probability*/
            if (meta.meter_tag == 1)
            {
                // Drop with a probability of 30%
                random(seed, (bit<7>)0, (bit<7>)100);
                if (seed <= PROB_DROP_UDP) {
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

            // Also, swap the the protocol identifier in the IPv4 packet
            // so the parser in the next switch knows about our header
            // and correctly parsers it. The last switch forwarding it
            // to the end-host will swap it back to the initial protocol.
            hdr.path.protocol = hdr.ipv4.protocol;
            hdr.ipv4.protocol = TYPE_PATH;

            // Check if flow has been seen before by the src switch
            recognise_flowlet();
            meta.flowlet_time_diff = standard_metadata.ingress_global_timestamp - meta.flowlet_last_stamp;

            // Flow is known
            if (meta.f_hop_count_saved != 0) {
                // Check if path is still valid
                path_state.apply();
            }

            // Check if inter-packet gap is > 100ms (for known flow) or flow unknown
            if (meta.flowlet_time_diff > FLOWLET_TIMEOUT || meta.f_hop_count_saved == 0) {

                if (hdr.udp.isValid()) {
                    meta.classification = CLASS_UDP;
                } else if (hdr.tcp.isValid()) {
                    meta.classification = CLASS_TCP;
                }

                // Compute hash for UDP and TCP to select a random path
                // For TCP, we will remember this path later to avoid
                // having different delays and thus, reordering.
                random(meta.hash, (bit<8>) 0, (bit<8>) PATH_MULTIPLIER);

                // Select path
                forwarding_table.apply();

                // Save the path and the hop count
                hops_reg.write((bit<32>) meta.flowlet_register_index, hdr.path.hops);
                hop_count_reg.write((bit<32>) meta.flowlet_register_index, hdr.path.hop_count);

            }

            // Flow is known to the src switch and no timeout
            else {
                // Save hop count in the header
                hdr.path.hop_count = meta.f_hop_count_saved;
            }
        }

        // Every switch on the path performs the following
        // Extract the next hop from the encoded hop list. Let's say the
        // list looks like this: 0x123
        // The last 4 bits (i.e. 0x3) denote the next hop, while the
        // remaining 2x4 bits (i.e. 0x12) denote the hops that will
        // follow after that, including the egress to the end host.
        meta.next_hop = (bit<9>) (hdr.path.hops - ((hdr.path.hops >> 4) << 4));

        // Check if the chosen output link is available
        // 0 means link down
        // 1 means link up
        link_state.read(meta.linkState, (bit<32>) meta.next_hop);
        
        // If link is down and TCP traffic
        if((meta.linkState == 0) && hdr.tcp.isValid()) {
            // Read alternative path
            alt_forwarding_table.apply();
            // Set alternative next hop
            meta.next_hop = (bit<9>) (hdr.path.hops - ((hdr.path.hops >> 4) << 4));
        }

        // "Remove" the next hop from the path
        // So that the next hop can read the header correctly
        // Also update the hop count
        hdr.path.hops = (hdr.path.hops >> 4);
        hdr.path.hop_count = hdr.path.hop_count - 1;

        // Set the egress port
        standard_metadata.egress_spec = meta.next_hop;

        // Write the correct dst MAC address depending on the egress port
        egress_to_mac.apply();

        if (hdr.path.hop_count == 0) {
            // Once hop_count has reached 0, this means we're now at the
            // last switch before the destination host. Here, we first swap
            // back the original protocol (from TYPE_PATH to what was here
            // initially, usually TYPE_TCP or TYPE_UDP) and remove the
            // path header before forwarding it to the host.
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
