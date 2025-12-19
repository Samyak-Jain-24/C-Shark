#include "storage.h"
#include "dissector.h"
#include "utils.h"

int init_session(void) {
    // Free any existing session
    free_session();
    
    // Allocate memory for new session
    current_session.packets = malloc(MAX_PACKETS * sizeof(stored_packet_t));
    if (current_session.packets == NULL) {
        fprintf(stderr, "[C-Shark] Error: Could not allocate memory for packet storage\n");
        return -1;
    }
    
    current_session.count = 0;
    current_session.capacity = MAX_PACKETS;
    current_session.active_filter = FILTER_NONE;
    memset(current_session.interface_name, 0, sizeof(current_session.interface_name));
    
    return 0;
}

int store_packet(const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    if (current_session.packets == NULL) {
        if (init_session() < 0) {
            return -1;
        }
    }
    
    if (current_session.count >= current_session.capacity) {
        // Session is full, could implement circular buffer here
        return -1;
    }
    
    stored_packet_t *stored_pkt = &current_session.packets[current_session.count];
    
    // Allocate memory for packet data
    stored_pkt->data = malloc(pkthdr->caplen);
    if (stored_pkt->data == NULL) {
        fprintf(stderr, "[C-Shark] Error: Could not allocate memory for packet data\n");
        return -1;
    }
    
    // Copy packet data
    memcpy(stored_pkt->data, packet, pkthdr->caplen);
    
    // Copy packet header
    stored_pkt->header = *pkthdr;
    stored_pkt->packet_id = current_session.count + 1;
    stored_pkt->timestamp = pkthdr->ts;
    
    current_session.count++;
    return 0;
}

void free_session(void) {
    if (current_session.packets != NULL) {
        // Free individual packet data
        for (int i = 0; i < current_session.count; i++) {
            if (current_session.packets[i].data != NULL) {
                free(current_session.packets[i].data);
                current_session.packets[i].data = NULL;
            }
        }
        
        // Free packet array
        free(current_session.packets);
        current_session.packets = NULL;
    }
    
    current_session.count = 0;
    current_session.capacity = 0;
}

int get_packet_count(void) {
    return current_session.count;
}

stored_packet_t* get_packet(int index) {
    if (index < 0 || index >= current_session.count || current_session.packets == NULL) {
        return NULL;
    }
    
    return &current_session.packets[index];
}

void print_session_summary(void) {
    if (current_session.count == 0) {
        printf("No packets in session.\n");
        return;
    }
    
    printf("Packet Summary (all %d packets):\n", current_session.count);
    printf("%-6s %-20s %-8s %-18s %-18s %-10s\n", 
           "ID", "Timestamp", "Length", "Src", "Dst", "Protocol");
    printf("%-6s %-20s %-8s %-18s %-18s %-10s\n", 
           "---", "---", "---", "---", "---", "---");
    
    int max_display = current_session.count;
    
    for (int i = 0; i < max_display; i++) {
        stored_packet_t *pkt = &current_session.packets[i];
        
        char timestamp_str[32];
        format_timestamp(&pkt->timestamp, timestamp_str, sizeof(timestamp_str));
        
        // Extract basic info for summary
        struct ether_header *eth = (struct ether_header *)pkt->data;
        char src_info[19] = "Unknown";
        char dst_info[19] = "Unknown";
        char protocol[11] = "Unknown";
        
        u_short ether_type = ntohs(eth->ether_type);
        
        if (ether_type == 0x0800) { // IPv4
            struct iphdr *ip = (struct iphdr *)(pkt->data + 14);
            inet_ntop(AF_INET, &(ip->saddr), src_info, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(ip->daddr), dst_info, INET_ADDRSTRLEN);
            
            if (ip->protocol == IPPROTO_TCP) {
                strcpy(protocol, "TCP");
            } else if (ip->protocol == IPPROTO_UDP) {
                strcpy(protocol, "UDP");
            } else if (ip->protocol == IPPROTO_ICMP) {
                strcpy(protocol, "ICMP");
            }
        } else if (ether_type == 0x86DD) { // IPv6
            strcpy(protocol, "IPv6");
            snprintf(src_info, sizeof(src_info), "IPv6");
            snprintf(dst_info, sizeof(dst_info), "IPv6");
        } else if (ether_type == 0x0806) { // ARP
            strcpy(protocol, "ARP");
            struct arp_header *arp = (struct arp_header *)(pkt->data + 14);
            inet_ntop(AF_INET, arp->sender_ip, src_info, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, arp->target_ip, dst_info, INET_ADDRSTRLEN);
        }
        
        printf("%-6d %-20s %-8u %-18s %-18s %-10s\n",
               pkt->packet_id, timestamp_str, pkt->header.len,
               src_info, dst_info, protocol);
    }
}
