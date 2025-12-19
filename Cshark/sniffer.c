#include "sniffer.h"
#include "utils.h"

int discover_interfaces(void) {
    pcap_if_t *interfaces, *temp;
    char errbuf[PCAP_ERRBUF_SIZE];
    int count = 0;
    
    printf("[C-Shark] Searching for available interfaces... ");
    
    // Get list of interfaces
    if (pcap_findalldevs(&interfaces, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return -1;
    }
    
    printf("Found!\n\n");
    
    // Display interfaces
    for (temp = interfaces; temp != NULL; temp = temp->next) {
        count++;
        printf("%d. %s", count, temp->name);
        if (temp->description) {
            printf(" (%s)", temp->description);
        }
        printf("\n");
    }
    
    pcap_freealldevs(interfaces);
    
    if (count == 0) {
        printf("No interfaces found!\n");
        return -1;
    }
    
    return count;
}

int select_interface(char *device_name, size_t name_len) {
    pcap_if_t *interfaces, *temp;
    char errbuf[PCAP_ERRBUF_SIZE];
    int count = 0, choice;
    
    // Get list of interfaces again
    if (pcap_findalldevs(&interfaces, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return -1;
    }
    
    // Count interfaces
    for (temp = interfaces; temp != NULL; temp = temp->next) {
        count++;
    }
    
    printf("\nSelect an interface to sniff (1-%d): ", count);
    choice = get_user_choice(1, count);
    
    // Get selected interface name
    temp = interfaces;
    for (int i = 1; i < choice; i++) {
        temp = temp->next;
    }
    
    strncpy(device_name, temp->name, name_len - 1);
    device_name[name_len - 1] = '\0';
    
    pcap_freealldevs(interfaces);
    return 0;
}

int setup_filter(pcap_t *handle, filter_type_t filter_type) {
    struct bpf_program fp;
    char filter_exp[256];
    bpf_u_int32 net = 0;
    
    // Build filter expression based on type
    switch (filter_type) {
        case FILTER_HTTP:
            strcpy(filter_exp, "tcp port 80");
            break;
        case FILTER_HTTPS:
            strcpy(filter_exp, "tcp port 443");
            break;
        case FILTER_DNS:
            strcpy(filter_exp, "udp port 53 or tcp port 53");
            break;
        case FILTER_ARP:
            strcpy(filter_exp, "arp");
            break;
        case FILTER_TCP:
            strcpy(filter_exp, "tcp");
            break;
        case FILTER_UDP:
            strcpy(filter_exp, "udp");
            break;
        default:
            return 0; // No filter
    }
    
    // Compile filter
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Error compiling filter: %s\n", pcap_geterr(handle));
        return -1;
    }
    
    // Apply filter
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Error applying filter: %s\n", pcap_geterr(handle));
        pcap_freecode(&fp);
        return -1;
    }
    
    pcap_freecode(&fp);
    return 0;
}

const char* get_port_name(int port) {
    switch (port) {
        case 20: return "FTP-DATA";
        case 21: return "FTP";
        case 22: return "SSH";
        case 23: return "TELNET";
        case 25: return "SMTP";
        case 53: return "DNS";
        case 67: return "DHCP-SERVER";
        case 68: return "DHCP-CLIENT";
        case 69: return "TFTP";
        case 80: return "HTTP";
        case 110: return "POP3";
        case 119: return "NNTP";
        case 123: return "NTP";
        case 143: return "IMAP";
        case 161: return "SNMP";
        case 194: return "IRC";
        case 443: return "HTTPS";
        case 465: return "SMTPS";
        case 993: return "IMAPS";
        case 995: return "POP3S";
        case 1433: return "MSSQL";
        case 1521: return "ORACLE";
        case 3306: return "MYSQL";
        case 3389: return "RDP";
        case 5432: return "POSTGRESQL";
        case 5900: return "VNC";
        case 8080: return "HTTP-ALT";
        default: return "";
    }
}

const char* identify_application_protocol(int src_port, int dst_port) {
    // Check well-known ports for both source and destination
    if (src_port == 80 || dst_port == 80) return "HTTP";
    if (src_port == 443 || dst_port == 443) return "HTTPS/TLS";
    if (src_port == 53 || dst_port == 53) return "DNS";
    if (src_port == 22 || dst_port == 22) return "SSH";
    if (src_port == 21 || dst_port == 21) return "FTP";
    if (src_port == 25 || dst_port == 25) return "SMTP";
    if (src_port == 110 || dst_port == 110) return "POP3";
    if (src_port == 143 || dst_port == 143) return "IMAP";
    if (src_port == 993 || dst_port == 993) return "IMAPS";
    if (src_port == 995 || dst_port == 995) return "POP3S";
    if (src_port == 465 || dst_port == 465) return "SMTPS";
    
    return "Unknown";
}
