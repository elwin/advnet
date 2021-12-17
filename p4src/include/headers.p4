/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/
// Includes
#include <core.p4>
#include <v1model.p4>

// Ethernet Types
const bit<16> TYPE_IPV4 = 0x0800;
const bit<16> HEARTBEAT = 0x1234;

// IPv4 Types
const bit<8>  TYPE_TCP  = 6;
const bit<8>  TYPE_UDP  = 17;
const bit<8>  TYPE_PATH = 144;

// Define constants
#define PORT_WIDTH 32

// Typedefs
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<9> egressSpec_t;

// Define headers

// Ethernet header
header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

// Heartbeat header
header heartbeat_t {
    bit<9>    port;
    bit<1>    from_cp;
    bit<6>    padding;
}

// IPv4 header
header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<6>    dscp;
    bit<2>    ecn;
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

// TCP header
header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

// UDP header
header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length;
    bit<16> checksum;
}

// PATH header
// Includes:
//   a) hops: includes the egress ports that the switches in the path will read to forward the traffic
//            e.g. if the source switch creates a path with hops = 0x231, the following switches will
//            follow the egress ports 2, 3, 1 respectively just by reading this field
//   b) hop_count: the count of the hops on the path
//   c) protocol: here we temporarily store the actual protocol of the payload in IPv4 to
//                eventually write it back when we remove this header
header path_t {
    bit<32> hops;
    bit<8>  hop_count;
    bit<8>  protocol;
}


// Instantiate metadata fields
struct metadata {
    bit<8>  hash;                   // hash to select path on the forwarding_table
    bit<4>  classification;         // UDP or TCP traffic
    bit<8>  udp_rate_limit_id;      // Map port ranges to an ID
    bit<13> flowlet_register_index; // Hash result of the flow tuple
    bit<48> flowlet_last_stamp;     // Time stamp of flow
    bit<48> flowlet_time_diff;      // Time difference between current time and time stamp
    bit<8>  f_hop_count_saved;      // Read previous hop count saved
    bit<32> meter_tag;              // Colour of the direct meter
    bit<16> src_port;               // Src port for TCP or UDP
    bit<16> dst_port;               // Dst port for TCP or UDP
    bit<1>  linkState;              // State of link
    bit<9>  next_hop;               // Egress port chosen to forward the packet to
}

// Instantiate packet headers
struct headers {
    ethernet_t                      ethernet;
    ipv4_t                          ipv4;
    path_t                          path;
    heartbeat_t                     heartbeat;
    tcp_t                           tcp;
    udp_t                           udp;
}

