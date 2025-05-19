#ifndef PACKET_STRUCTS_H
#define PACKET_STRUCTS_H

#include <pcap.h>
#include <netinet/in.h>

#pragma pack(push, 1)
struct eth_header {
    u_char dest[6];
    u_char src[6];
    u_short type;
};

struct ip_header {
    u_char ver_len;
    u_char tos;
    u_short total_len;
    u_short id;
    u_short frag_off;
    u_char ttl;
    u_char protocol;
    u_short checksum;
    u_int src_addr;
    u_int dest_addr;
};

struct tcp_header {
    u_short src_port;
    u_short dest_port;
    u_int seq;
    u_int ack;
    u_char offset;
    u_char flags;
    u_short window;
    u_short checksum;
    u_short urgent_ptr;
};
#pragma pack(pop)

#endif
