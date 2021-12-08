/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

//My includes
#include "include/headers.p4"
#include "include/parsers.p4"

//My defines

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

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            set_nhop;
            drop;
        }
        size = 1024;
        default_action = set_nhop;
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
            ipv4_lpm.apply();
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