/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

//My includes
#include "include/headers.p4"
#include "include/parsers.p4"

//My defines
#define N_PREFS 1024
#define PORT_WIDTH 32
#define N_PORTS 32
#define X1 36
#define X2 100
#define REGISTER_SIZE 8192
#define TIMESTAMP_WIDTH 48
#define ID_WIDTH 16
#define FLOWLET_TIMEOUT 48w200000

#define PKT_INSTANCE_TYPE_NORMAL 0
#define PKT_INSTANCE_TYPE_INGRESS_CLONE 1
#define PKT_INSTANCE_TYPE_EGRESS_CLONE 2
#define PKT_INSTANCE_TYPE_COALESCED 3
#define PKT_INSTANCE_TYPE_INGRESS_RECIRC 4
#define PKT_INSTANCE_TYPE_REPLICATION 5
#define PKT_INSTANCE_TYPE_RESUBMIT 6


// Register to get the queue depth of the egress port
// register<bit<32>>(N_PORTS) queue_depth_egress;


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

    // Register containing link states. 0: No Problems. 1: Link failure.
    register<bit<1>>(N_PORTS) linkState;
    //register<bit<PORT_WIDTH>>(N_PORTS) link_lfa;

    register<bit<ID_WIDTH>>(REGISTER_SIZE)        flowlet_to_id;
    register<bit<TIMESTAMP_WIDTH>>(REGISTER_SIZE) flowlet_time_stamp;
    // Registers to save known flows, egress ports of known flows and timestamps of known flows
    register<bit<PORT_WIDTH>>(REGISTER_SIZE)      known_flows_egress;

    counter(32, CounterType.packets_and_bytes) port_counter;

    // Variables needed for RED
    // bit<7> seed;
    // bit<7> probability;
    // bit<7> diff;
    // bit<7> const_diff;
    // bit<7> div;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action send_heartbeat() {
        // we make sure the other switch treats the packet as probe from the other side
        hdr.heartbeat.from_cp = 0;
        standard_metadata.egress_spec = hdr.heartbeat.port;
    }

    action update_flowlet_id(){
        bit<32> random_t;
        random(random_t, (bit<32>)0, (bit<32>)65000);
        meta.flowlet_id = (bit<16>)random_t;
        flowlet_to_id.write((bit<32>)meta.flowlet_register_index, (bit<16>)meta.flowlet_id);
    }


    action rewriteMac(macAddr_t dstAddr){
	    hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        //decrease ttl by 1
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }


    action recognise_flowlet() {

        hash(meta.flowlet_register_index,
	    HashAlgorithm.crc16,
	    (bit<1>)0,
	    { hdr.ipv4.srcAddr,
	      hdr.ipv4.dstAddr,
          hdr.tcp.srcPort,
          hdr.tcp.dstPort,
          hdr.ipv4.protocol},
	    (bit<14>)500);

        known_flows_egress.read(meta.f_egress_saved, (bit<32>)meta.flowlet_register_index);

        //Read previous time stamp
        flowlet_time_stamp.read(meta.flowlet_last_stamp, (bit<32>)meta.flowlet_register_index);

        //Read previous flowlet id
        flowlet_to_id.read(meta.flowlet_id, (bit<32>)meta.flowlet_register_index);

        //Update timestamp
        flowlet_time_stamp.write((bit<32>)meta.flowlet_register_index, standard_metadata.ingress_global_timestamp);


    }

    action set_nhop(macAddr_t dstAddr, egressSpec_t port) {

        //set the src mac address as the previous dst, this is not correct right?
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;

       //set the destination mac address that we got from the match in the table
        hdr.ethernet.dstAddr = dstAddr;

        //set the output port that we also get from the table
        meta.flow_egress = (bit<32>)port;

        //decrease ttl by 1
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action ecmp_group(bit<14> ecmp_group_id, bit<16> num_nhops){

        hash(meta.ecmp_hash,
	    HashAlgorithm.crc16,
	    (bit<1>)0,
	    { hdr.ipv4.srcAddr,
	      hdr.ipv4.dstAddr,
          hdr.tcp.srcPort,
          hdr.tcp.dstPort,
          hdr.ipv4.protocol,
          meta.flowlet_id},
	    num_nhops);

	    meta.ecmp_group_id = ecmp_group_id;
    }

    table ecmp_group_to_nhop {
        key = {
            meta.ecmp_group_id:    exact;
            meta.ecmp_hash:        exact;
        }
        actions = {
            drop;
            set_nhop;
        }
        size = 1024;
        default_action = drop;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            set_nhop;
            ecmp_group;
            drop;
        }
        size = 1024;
        default_action = drop;
    }

    table rewrite_mac {
        key = {
             meta.flow_egress: exact;
        }
        actions = {
            rewriteMac;
            drop;
        }
        size = 512;
        default_action = drop;
    }

    table find_lfa {
        key = {
            meta.flow_egress: exact;
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            set_nhop;
            drop;
        }
        size = 512;
        default_action = drop;
    }

    apply {
        port_counter.count((bit<32>)standard_metadata.ingress_port);

        if (hdr.heartbeat.isValid()) {
            if (hdr.heartbeat.from_cp == 1) {
                send_heartbeat();
            }

            else {
                drop();
            }
        }

        if (hdr.ipv4.isValid()) {

            // Check if the flow is known
            @atomic {

                recognise_flowlet();

                meta.flowlet_time_diff = standard_metadata.ingress_global_timestamp - meta.flowlet_last_stamp;

                // check if inter-packet gap is > 100ms or flow unknown
                if ((meta.f_egress_saved == 0) || ((meta.flowlet_time_diff > FLOWLET_TIMEOUT) && (meta.f_egress_saved != 0))){
                    update_flowlet_id();
                    // DO the load balancing in the controller
                    switch (ipv4_lpm.apply().action_run){
                        ecmp_group: {
                            ecmp_group_to_nhop.apply();
                        }
                    }
                }



            }

            // Flow is not known
            // OR
            // Flow known but flowlet timeout
            if ((meta.f_egress_saved == 0) || ((meta.flowlet_time_diff > FLOWLET_TIMEOUT) && (meta.f_egress_saved != 0))) {

                // Check if link is available
                linkState.read(meta.linkState, meta.flow_egress);

                // Link is operating
                if (meta.linkState == 0) {
                    standard_metadata.egress_spec = (bit<9>) meta.flow_egress;
                    // Save current egress port for the specific flow
                    known_flows_egress.write((bit<32>)meta.flowlet_register_index, meta.flow_egress);
                }

                // Link has failed
                // Find LFA which works
                else {

                    find_lfa.apply();

                    // Read per-link LFA
                    // until an operating link is found
                    // meta.lfa_operating = 0;

                    // // 1st alt
                    // link_lfa.read(meta.lfa_flow_egress, meta.flow_egress);
                    // meta.flow_egress = meta.lfa_flow_egress;
                    // // check if LFA is operating
                    // linkState.read(meta.linkState, meta.lfa_flow_egress);
                    // // link operating
                    // if (meta.linkState == 0) {
                    //     meta.lfa_operating = 1;
                    // }


                    // // 1st alt not operating
                    // // 2nd alt
                    // if (meta.lfa_operating == 0) {
                    //     link_lfa.read(meta.lfa_flow_egress, meta.flow_egress);
                    //     meta.flow_egress = meta.lfa_flow_egress;
                    //     // check if LFA is operating
                    //     linkState.read(meta.linkState, meta.lfa_flow_egress);
                    //     // link operating
                    //     if (meta.linkState == 0) {
                    //         meta.lfa_operating = 1;
                    //     }
                    // }

                    // // 2nd alt not operating
                    // // 3rd alt
                    // if (meta.lfa_operating == 0) {
                    //     link_lfa.read(meta.lfa_flow_egress, meta.flow_egress);
                    //     meta.flow_egress = meta.lfa_flow_egress;
                    //     // check if LFA is operating
                    //     linkState.read(meta.linkState, meta.lfa_flow_egress);
                    //     // link operating
                    //     if (meta.linkState == 0) {
                    //         meta.lfa_operating = 1;
                    //     }
                    // }

                    // // 3rd alt not operating
                    // // 4th alt
                    // if (meta.lfa_operating == 0) {
                    //     link_lfa.read(meta.lfa_flow_egress, meta.flow_egress);
                    //     meta.flow_egress = meta.lfa_flow_egress;
                    //     // check if LFA is operating
                    //     linkState.read(meta.linkState, meta.lfa_flow_egress);
                    //     // link operating
                    //     if (meta.linkState == 0) {
                    //         meta.lfa_operating = 1;
                    //     }
                    // }
                    standard_metadata.egress_spec = (bit<9>) meta.flow_egress;
                    // Save current egress port for the specific flow
                    known_flows_egress.write((bit<32>)meta.flowlet_register_index, meta.flow_egress);

                }

            }

            // Flow is known and still the same flowlet sequence
            else if ((meta.flowlet_time_diff <= FLOWLET_TIMEOUT) && (meta.f_egress_saved != 0)) {

                // Check if link is available
                linkState.read(meta.linkState, meta.f_egress_saved);

                // Link is operating
                if (meta.linkState == 0) {
                    standard_metadata.egress_spec = (bit<9>) meta.f_egress_saved;
                    meta.flow_egress = meta.f_egress_saved;
                    rewrite_mac.apply();
                }

                // Link failure
                else {
                    // Reset known output port
                    known_flows_egress.write((bit<32>)meta.flowlet_register_index, 0);
                    // Resubmission of packet back to the ingress pipeline
                    resubmit({});
                }
            }
        }
    }



        // Read the queue depth of the egress port
        //queue_depth_egress.read(meta.current_queue_depth, (bit<32>)standard_metadata.egress_spec);

        // Do the RED logic
        // if (X1 < meta.current_queue_depth && meta.current_queue_depth < X2) {

        //     random(seed, (bit<7>)0, (bit<7>)100);
        //     const_diff = X2-X1;
        //     diff = (meta.current_queue_depth - X1);
        //     div = diff / const_diff;
        //     probability = 100*div;

        //     if (seed < probability) {
        //         drop();
        //     }
        // }
        // else if (meta.current_queue_depth > X2) {
        //     drop();
        // }


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