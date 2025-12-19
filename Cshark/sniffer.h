#ifndef SNIFFER_H
#define SNIFFER_H

#define _DEFAULT_SOURCE
#define _BSD_SOURCE
#define __FAVOR_BSD

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <net/if_arp.h>
#include <time.h>
#include <ctype.h>
#include <stdint.h>

// BSD-style type definitions for compatibility (must be before pcap.h)
#ifndef u_char
typedef unsigned char u_char;
#endif
#ifndef u_short
typedef unsigned short u_short;
#endif
#ifndef u_int
typedef unsigned int u_int;
#endif
#ifndef u_long
typedef unsigned long u_long;
#endif

#include <pcap.h>

// Maximum number of packets to store
#define MAX_PACKETS 10000
#define MAX_PAYLOAD_DISPLAY 64
#define SNAP_LEN 65535
#define PROMISCUOUS 1
#define TIMEOUT_MS 1000

// Program states for Ctrl+C handling
typedef enum {
    STATE_INTERFACE_SELECTION = 0,
    STATE_MAIN_MENU,
    STATE_CAPTURING,
    STATE_INSPECTION
} program_state_t;

// Filter types
typedef enum {
    FILTER_NONE = 0,
    FILTER_HTTP,
    FILTER_HTTPS,
    FILTER_DNS,
    FILTER_ARP,
    FILTER_TCP,
    FILTER_UDP
} filter_type_t;

// Packet storage structure
typedef struct {
    u_char *data;
    struct pcap_pkthdr header;
    int packet_id;
    struct timeval timestamp;
} stored_packet_t;

// Session management
typedef struct {
    stored_packet_t *packets;
    int count;
    int capacity;
    char interface_name[256];
    filter_type_t active_filter;
} packet_session_t;

// Global variables
extern packet_session_t current_session;
extern volatile int stop_sniffing;
extern int packet_counter;
extern pcap_t *global_handle;
extern volatile program_state_t current_state;

// Function declarations
int discover_interfaces(void);
int select_interface(char *device_name, size_t name_len);
void start_sniffing(pcap_t *handle, int with_filter);
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet);
void process_packet(const struct pcap_pkthdr *pkthdr, const u_char *packet, int packet_id);
void signal_handler(int signum);
int setup_filter(pcap_t *handle, filter_type_t filter_type);
void display_main_menu(void);
void inspect_last_session(void);
void inspect_packet_detail(int packet_id);
void cleanup_session(void);

// Protocol identification functions
const char* get_port_name(int port);
const char* identify_application_protocol(int src_port, int dst_port);

#endif // SNIFFER_H