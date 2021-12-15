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
const bit<8> TYPE_PATH  = 144;

// Define constants
#define PORT_WIDTH 32

typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<9> egressSpec_t;

// Define headers
header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header heartbeat_t {
    bit<9>    port;
    bit<1>    from_cp;
    bit<6>    padding;
}

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

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length;
    bit<16> checksum;
}

header path_t {
    bit<32> hops;
    bit<8>  hop_count;
    bit<8>  protocol;
    bit<8>  padding;
}


// Instantiate metadata fields
struct metadata {
    bit<8>  hash;
    bit<8>  flow_hash;
    bit<4>  classification;
    bit<8>  udp_rate_limit_id;
    bit<13> flowlet_register_index;
    bit<48> flowlet_last_stamp;
    bit<48> flowlet_time_diff;
    bit<16> flowlet_id;
    bit<48> dst_mac_saved;
    bit<32> f_hops_saved;
    bit<8>  f_hop_count_saved;
    bit<4>  classification;
    bit<32> meter_tag;
    bit<16> src_port;
    bit<16> dst_port;
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

