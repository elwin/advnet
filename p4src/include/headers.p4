/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/
// Includes
#include <core.p4>
#include <v1model.p4>

// Define constants
const bit<16> HEARTBEAT = 0x1234;
const bit<16> TYPE_IPV4 = 0x800;

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
    bit<2>    ecn;
    bit<6>    dscp;
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

header tcp_t{
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

// Instantiate metadata fields
struct metadata {
    bit<14> ecmp_hash;
    bit<14> ecmp_group_id;
}

// Instantiate packet headers
struct headers {
    ethernet_t                      ethernet;
    ipv4_t                          ipv4;
    tcp_t                           tcp;
    heartbeat_t                     heartbeat;
}

