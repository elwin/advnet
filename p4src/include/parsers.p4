/*************************************************************************
*********************** P A R S E R  *******************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    // Parse Ethernet header
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType){
            HEARTBEAT: parse_heartbeat;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    // Parse Heartbeat header
    state parse_heartbeat {
        packet.extract(hdr.heartbeat);
        transition accept;
    }

    // Parse IPv4 header
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            TYPE_PATH: parse_path;
            TYPE_TCP: parse_tcp;
            TYPE_UDP: parse_udp;
            default: accept;
        }
    }

    // Parse PATH header
    state parse_path {
        packet.extract(hdr.path);
        transition select(hdr.path.protocol){
            TYPE_TCP: parse_tcp;
            TYPE_UDP: parse_udp;
            default: accept;
        }
    }

    // Parse TCP header
    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    // Parse UDP header
    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }

}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {

        // Parsed headers have to be added again into the packet.
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.path);
        packet.emit(hdr.heartbeat);

        // Only emitted if valid
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    }
}
