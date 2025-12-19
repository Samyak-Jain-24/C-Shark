#include "dissector.h"
#include "sniffer.h"

void dissect_ethernet(const u_char *packet, int *offset) {
    struct ether_header *eth = (struct ether_header *)(packet + *offset);
    
    printf("L2 (Ethernet): Dst MAC: ");
    print_mac_address(eth->ether_dhost);
    printf(" | Src MAC: ");
    print_mac_address(eth->ether_shost);
    printf(" | EtherType: %s (0x%04X)\n", 
           get_ethertype_string(ntohs(eth->ether_type)), ntohs(eth->ether_type));
    
    *offset += 14;  // Standard ethernet header size
    
    // Process next layer based on EtherType
    u_short ether_type = ntohs(eth->ether_type);
    switch (ether_type) {
        case 0x0800: // IPv4
            dissect_ipv4(packet, &*offset, 0);
            break;
        case 0x86DD: // IPv6
            dissect_ipv6(packet, &*offset, 0);
            break;
        case 0x0806: // ARP
            dissect_arp(packet, &*offset);
            break;
        default:
            printf("L3: Unknown protocol (0x%04X)\n", ether_type);
            break;
    }
}

void dissect_ipv4(const u_char *packet, int *offset, int packet_len) {
    struct iphdr *ip = (struct iphdr *)(packet + *offset);
    
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip->saddr), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip->daddr), dst_ip, INET_ADDRSTRLEN);
    
    printf("L3 (IPv4): Src IP: %s | Dst IP: %s | Protocol: %s (%d) | TTL: %d\n",
           src_ip, dst_ip, get_ip_protocol_string(ip->protocol), ip->protocol, ip->ttl);
    
    printf("ID: 0x%04X | Total Length: %d | Header Length: %d bytes",
           ntohs(ip->id), ntohs(ip->tot_len), ip->ihl * 4);
    
    // Decode flags
    u_short flags = ntohs(ip->frag_off);
    if (flags & 0x4000) printf(" | Flags: [DF]"); // Don't Fragment
    if (flags & 0x2000) printf(" | Flags: [MF]"); // More Fragments
    printf("\n");
    
    *offset += ip->ihl * 4;
    
    // Calculate payload length
    int payload_len = ntohs(ip->tot_len) - (ip->ihl * 4);
    
    // Process next layer
    switch (ip->protocol) {
        case IPPROTO_TCP:
            dissect_tcp(packet, &*offset, payload_len);
            break;
        case IPPROTO_UDP:
            dissect_udp(packet, &*offset, payload_len);
            break;
        case IPPROTO_ICMP:
            printf("L4 (ICMP): ICMP packet detected\n");
            break;
        default:
            printf("L4: Unknown protocol (%d)\n", ip->protocol);
            break;
    }
}

void dissect_ipv6(const u_char *packet, int *offset, int packet_len) {
    struct ip6_hdr *ip6 = (struct ip6_hdr *)(packet + *offset);
    
    char src_ip[INET6_ADDRSTRLEN], dst_ip[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &(ip6->ip6_src), src_ip, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &(ip6->ip6_dst), dst_ip, INET6_ADDRSTRLEN);
    
    printf("L3 (IPv6): Src IP: %s | Dst IP: %s\n", src_ip, dst_ip);
    printf("Next Header: %s (%d) | Hop Limit: %d | Traffic Class: %d | Flow Label: 0x%05X | Payload Length: %d\n",
           get_ip_protocol_string(ip6->ip6_nxt), ip6->ip6_nxt, ip6->ip6_hlim,
           (ntohl(ip6->ip6_flow) & 0x0FF00000) >> 20,
           ntohl(ip6->ip6_flow) & 0x000FFFFF,
           ntohs(ip6->ip6_plen));
    
    *offset += sizeof(struct ip6_hdr);
    
    int payload_len = ntohs(ip6->ip6_plen);
    
    // Process next layer
    switch (ip6->ip6_nxt) {
        case IPPROTO_TCP:
            dissect_tcp(packet, &*offset, payload_len);
            break;
        case IPPROTO_UDP:
            dissect_udp(packet, &*offset, payload_len);
            break;
        case IPPROTO_ICMPV6:
            printf("L4 (ICMPv6): ICMPv6 packet detected\n");
            break;
        default:
            printf("L4: Unknown next header (%d)\n", ip6->ip6_nxt);
            break;
    }
}

void dissect_arp(const u_char *packet, int *offset) {
    struct arp_header *arp = (struct arp_header *)(packet + *offset);
    
    char sender_ip[INET_ADDRSTRLEN], target_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, arp->sender_ip, sender_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, arp->target_ip, target_ip, INET_ADDRSTRLEN);
    
    printf("L3 (ARP): Operation: %s (%d) | Sender IP: %s | Target IP: %s\n",
           get_arp_operation_string(ntohs(arp->operation)), ntohs(arp->operation),
           sender_ip, target_ip);
    
    printf("Sender MAC: ");
    print_mac_address(arp->sender_mac);
    printf(" | Target MAC: ");
    print_mac_address(arp->target_mac);
    printf("\n");
    
    printf("HW Type: %d | Proto Type: 0x%04X | HW Len: %d | Proto Len: %d\n",
           ntohs(arp->hardware_type), ntohs(arp->protocol_type),
           arp->hardware_len, arp->protocol_len);
    
    *offset += 28;  // ARP header size
}

void dissect_tcp(const u_char *packet, int *offset, int payload_len) {
    struct tcphdr *tcp = (struct tcphdr *)(packet + *offset);
    
    int src_port = ntohs(tcp->th_sport);
    int dst_port = ntohs(tcp->th_dport);
    
    printf("L4 (TCP): Src Port: %d", src_port);
    const char *src_service = get_port_name(src_port);
    if (strlen(src_service) > 0) {
        printf(" (%s)", src_service);
    }
    
    printf(" | Dst Port: %d", dst_port);
    const char *dst_service = get_port_name(dst_port);
    if (strlen(dst_service) > 0) {
        printf(" (%s)", dst_service);
    }
    
    printf(" | Seq: %u | Ack: %u | Flags: ",
           ntohl(tcp->th_seq), ntohl(tcp->th_ack));
    
    print_tcp_flags(tcp->th_flags);
    
    printf("\nWindow: %d | Checksum: 0x%04X | Header Length: %d bytes\n",
           ntohs(tcp->th_win), ntohs(tcp->th_sum), tcp->th_off * 4);
    
    *offset += tcp->th_off * 4;
    
    // Calculate application payload length
    int app_payload_len = payload_len - (tcp->th_off * 4);
    if (app_payload_len > 0) {
        dissect_payload(packet, *offset, app_payload_len, src_port, dst_port);
    }
}

void dissect_udp(const u_char *packet, int *offset, int payload_len) {
    struct udphdr *udp = (struct udphdr *)(packet + *offset);
    
    int src_port = ntohs(udp->uh_sport);
    int dst_port = ntohs(udp->uh_dport);
    
    printf("L4 (UDP): Src Port: %d", src_port);
    const char *src_service = get_port_name(src_port);
    if (strlen(src_service) > 0) {
        printf(" (%s)", src_service);
    }
    
    printf(" | Dst Port: %d", dst_port);
    const char *dst_service = get_port_name(dst_port);
    if (strlen(dst_service) > 0) {
        printf(" (%s)", dst_service);
    }
    
    printf(" | Length: %d | Checksum: 0x%04X\n",
           ntohs(udp->uh_ulen), ntohs(udp->uh_sum));
    
    *offset += sizeof(struct udphdr);
    
    // Calculate application payload length
    int app_payload_len = ntohs(udp->uh_ulen) - sizeof(struct udphdr);
    if (app_payload_len > 0) {
        dissect_payload(packet, *offset, app_payload_len, src_port, dst_port);
    }
}

void dissect_payload(const u_char *packet, int offset, int payload_len, int src_port, int dst_port) {
    const char *protocol = identify_application_protocol(src_port, dst_port);
    
    printf("L7 (Payload): Identified as %s", protocol);
    if (src_port == 53 || dst_port == 53) {
        printf(" on port 53");
    } else if (src_port == 80 || dst_port == 80) {
        printf(" on port 80");
    } else if (src_port == 443 || dst_port == 443) {
        printf(" on port 443");
    }
    printf(" - %d bytes\n", payload_len);
    
    // Display hex dump of first 64 bytes
    int display_len = (payload_len > MAX_PAYLOAD_DISPLAY) ? MAX_PAYLOAD_DISPLAY : payload_len;
    if (display_len > 0) {
        printf("Data (first %d bytes):\n", display_len);
        print_hex_dump(packet + offset, display_len, "");
    }
}

void print_mac_address(const u_char *mac) {
    printf("%02X:%02X:%02X:%02X:%02X:%02X", 
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_hex_dump(const u_char *data, int len, const char *prefix) {
    int i, j;
    char ascii_buf[17];
    
    for (i = 0; i < len; i += 16) {
        // Print offset
        if (strlen(prefix) > 0) {
            printf("%s", prefix);
        }
        
        // Print hex bytes
        for (j = 0; j < 16; j++) {
            if (i + j < len) {
                printf("%02X ", data[i + j]);
                ascii_buf[j] = (isprint(data[i + j])) ? data[i + j] : '.';
            } else {
                printf("   ");
                ascii_buf[j] = ' ';
            }
        }
        ascii_buf[16] = '\0';
        
        // Print ASCII representation
        printf("%s\n", ascii_buf);
    }
}

const char* get_ethertype_string(u_short ether_type) {
    switch (ether_type) {
        case 0x0800: return "IPv4";
        case 0x0806: return "ARP";
        case 0x86DD: return "IPv6";
        case 0x8100: return "VLAN";
        default: return "Unknown";
    }
}

const char* get_ip_protocol_string(u_char protocol) {
    switch (protocol) {
        case IPPROTO_ICMP: return "ICMP";
        case IPPROTO_TCP: return "TCP";
        case IPPROTO_UDP: return "UDP";
        case IPPROTO_ICMPV6: return "ICMPv6";
        case IPPROTO_ESP: return "ESP";
        case IPPROTO_AH: return "AH";
        default: return "Unknown";
    }
}

const char* get_arp_operation_string(u_short operation) {
    switch (operation) {
        case 1: return "Request";
        case 2: return "Reply";
        case 3: return "RARP Request";
        case 4: return "RARP Reply";
        default: return "Unknown";
    }
}

void print_tcp_flags(u_char flags) {
    int first = 1;
    printf("[");
    
    if (flags & 0x01) { // FIN
        printf("FIN");
        first = 0;
    }
    if (flags & 0x02) { // SYN
        if (!first) printf(",");
        printf("SYN");
        first = 0;
    }
    if (flags & 0x04) { // RST
        if (!first) printf(",");
        printf("RST");
        first = 0;
    }
    if (flags & 0x08) { // PSH
        if (!first) printf(",");
        printf("PSH");
        first = 0;
    }
    if (flags & 0x10) { // ACK
        if (!first) printf(",");
        printf("ACK");
        first = 0;
    }
    if (flags & 0x20) { // URG
        if (!first) printf(",");
        printf("URG");
        first = 0;
    }
    if (flags & 0x40) { // ECE
        if (!first) printf(",");
        printf("ECE");
        first = 0;
    }
    if (flags & 0x80) { // CWR
        if (!first) printf(",");
        printf("CWR");
        first = 0;
    }
    
    printf("]");
}
