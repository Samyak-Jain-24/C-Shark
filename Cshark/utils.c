#include "utils.h"

int check_root_privileges(void) {
    if (geteuid() != 0) {
        fprintf(stderr, "\n[C-Shark] Error: Root privileges required for packet capture\n");
        fprintf(stderr, "[C-Shark] Please run with: sudo ./cshark\n\n");
        return -1;
    }
    return 0;
}

void clear_input_buffer(void) {
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
}

int get_user_choice(int min, int max) {
    int choice;
    char line[256];
    
    while (1) {
        if (fgets(line, sizeof(line), stdin) == NULL) {
            // Handle Ctrl+D (EOF)
            printf("\n[C-Shark] Exiting C-Shark...\n");
            exit(0);
        }
        
        if (sscanf(line, "%d", &choice) == 1 && choice >= min && choice <= max) {
            return choice;
        }
        
        printf("Invalid input. Please enter a number between %d and %d: ", min, max);
    }
}

void print_banner(void) {
    printf("\n");
    printf("==============================================\n");
    printf("[C-Shark] The Command-Line Packet Predator\n");
    printf("==============================================\n");
}

void print_separator(void) {
    printf("-----------------------------------------\n");
}

const char* filter_type_to_string(filter_type_t filter) {
    switch (filter) {
        case FILTER_NONE: return "None";
        case FILTER_HTTP: return "HTTP";
        case FILTER_HTTPS: return "HTTPS";
        case FILTER_DNS: return "DNS";
        case FILTER_ARP: return "ARP";
        case FILTER_TCP: return "TCP";
        case FILTER_UDP: return "UDP";
        default: return "Unknown";
    }
}

int matches_filter(const u_char *packet, int packet_len, filter_type_t filter) {
    if (filter == FILTER_NONE) {
        return 1; // No filter, matches everything
    }
    
    if (packet_len < 14) {  // Standard ethernet header size
        return 0;
    }
    
    struct ether_header *eth = (struct ether_header *)packet;
    u_short ether_type = ntohs(eth->ether_type);
    
    switch (filter) {
        case FILTER_ARP:
            return (ether_type == 0x0806);
            
        case FILTER_TCP:
        case FILTER_UDP:
        case FILTER_HTTP:
        case FILTER_HTTPS:
        case FILTER_DNS: {
            if (ether_type == 0x0800) { // IPv4
                if (packet_len < 14 + sizeof(struct iphdr)) {
                    return 0;
                }
                
                struct iphdr *ip = (struct iphdr *)(packet + 14);
                
                if (filter == FILTER_TCP && ip->protocol == IPPROTO_TCP) {
                    return 1;
                }
                if (filter == FILTER_UDP && ip->protocol == IPPROTO_UDP) {
                    return 1;
                }
                
                // For port-specific filters, need to check transport layer
                if (ip->protocol == IPPROTO_TCP && (filter == FILTER_HTTP || filter == FILTER_HTTPS)) {
                    if (packet_len < 14 + (ip->ihl * 4) + sizeof(struct tcphdr)) {
                        return 0;
                    }
                    
                    struct tcphdr *tcp = (struct tcphdr *)(packet + 14 + (ip->ihl * 4));
                    int src_port = ntohs(tcp->th_sport);
                    int dst_port = ntohs(tcp->th_dport);
                    
                    if (filter == FILTER_HTTP && (src_port == 80 || dst_port == 80)) {
                        return 1;
                    }
                    if (filter == FILTER_HTTPS && (src_port == 443 || dst_port == 443)) {
                        return 1;
                    }
                }
                
                if (ip->protocol == IPPROTO_UDP && filter == FILTER_DNS) {
                    if (packet_len < 14 + (ip->ihl * 4) + sizeof(struct udphdr)) {
                        return 0;
                    }
                    
                    struct udphdr *udp = (struct udphdr *)(packet + 14 + (ip->ihl * 4));
                    int src_port = ntohs(udp->uh_sport);
                    int dst_port = ntohs(udp->uh_dport);
                    
                    if (src_port == 53 || dst_port == 53) {
                        return 1;
                    }
                }
            } else if (ether_type == 0x86DD) { // IPv6
                if (packet_len < 14 + sizeof(struct ip6_hdr)) {
                    return 0;
                }
                
                struct ip6_hdr *ip6 = (struct ip6_hdr *)(packet + 14);
                
                if (filter == FILTER_TCP && ip6->ip6_nxt == IPPROTO_TCP) {
                    return 1;
                }
                if (filter == FILTER_UDP && ip6->ip6_nxt == IPPROTO_UDP) {
                    return 1;
                }
                
                // Similar port checking for IPv6...
                if (ip6->ip6_nxt == IPPROTO_TCP && (filter == FILTER_HTTP || filter == FILTER_HTTPS)) {
                    if (packet_len < 14 + sizeof(struct ip6_hdr) + sizeof(struct tcphdr)) {
                        return 0;
                    }
                    
                    struct tcphdr *tcp = (struct tcphdr *)(packet + 14 + sizeof(struct ip6_hdr));
                    int src_port = ntohs(tcp->th_sport);
                    int dst_port = ntohs(tcp->th_dport);
                    
                    if (filter == FILTER_HTTP && (src_port == 80 || dst_port == 80)) {
                        return 1;
                    }
                    if (filter == FILTER_HTTPS && (src_port == 443 || dst_port == 443)) {
                        return 1;
                    }
                }
                
                if (ip6->ip6_nxt == IPPROTO_UDP && filter == FILTER_DNS) {
                    if (packet_len < 14 + sizeof(struct ip6_hdr) + sizeof(struct udphdr)) {
                        return 0;
                    }
                    
                    struct udphdr *udp = (struct udphdr *)(packet + 14 + sizeof(struct ip6_hdr));
                    int src_port = ntohs(udp->uh_sport);
                    int dst_port = ntohs(udp->uh_dport);
                    
                    if (src_port == 53 || dst_port == 53) {
                        return 1;
                    }
                }
            }
            return 0;
        }
        
        default:
            return 0;
    }
}

void format_timestamp(struct timeval *tv, char *buffer, size_t buffer_size) {
    time_t raw_time = tv->tv_sec;
    struct tm *timeinfo = localtime(&raw_time);
    
    snprintf(buffer, buffer_size, "%02d:%02d:%02d.%06ld",
             timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec, tv->tv_usec);
}
