#ifndef DISSECTOR_H
#define DISSECTOR_H

#include "sniffer.h"

// Ethernet frame structure
struct ethernet_header {
    u_char dest_mac[6];
    u_char src_mac[6];
    u_short ether_type;
} __attribute__((packed));

// IPv4 header structure (already defined in netinet/ip.h as struct iphdr)
// IPv6 header structure (already defined in netinet/ip6.h as struct ip6_hdr)

// ARP header structure
struct arp_header {
    u_short hardware_type;
    u_short protocol_type;
    u_char hardware_len;
    u_char protocol_len;
    u_short operation;
    u_char sender_mac[6];
    u_char sender_ip[4];
    u_char target_mac[6];
    u_char target_ip[4];
};

// TCP and UDP headers are already defined in netinet/tcp.h and netinet/udp.h

// Function declarations for packet dissection
void dissect_ethernet(const u_char *packet, int *offset);
void dissect_ipv4(const u_char *packet, int *offset, int packet_len);
void dissect_ipv6(const u_char *packet, int *offset, int packet_len);
void dissect_arp(const u_char *packet, int *offset);
void dissect_tcp(const u_char *packet, int *offset, int payload_len);
void dissect_udp(const u_char *packet, int *offset, int payload_len);
void dissect_payload(const u_char *packet, int offset, int payload_len, int src_port, int dst_port);

// Utility functions
void print_mac_address(const u_char *mac);
void print_hex_dump(const u_char *data, int len, const char *prefix);
const char* get_ethertype_string(u_short ether_type);
const char* get_ip_protocol_string(u_char protocol);
const char* get_arp_operation_string(u_short operation);
void print_tcp_flags(u_char flags);

#endif // DISSECTOR_H