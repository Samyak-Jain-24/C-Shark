#include "sniffer.h"
#include "dissector.h"
#include "storage.h"
#include "utils.h"

// Global variables
packet_session_t current_session = {0};
volatile int stop_sniffing = 0;
int packet_counter = 0;
pcap_t *global_handle = NULL;
volatile program_state_t current_state = STATE_INTERFACE_SELECTION;

void signal_handler(int signum) {
    if (signum == SIGINT) {
        switch (current_state) {
            case STATE_CAPTURING:
                stop_sniffing = 1;
                printf("\n[C-Shark] Stopping capture...\n");
                if (global_handle != NULL) {
                    pcap_breakloop(global_handle);
                }
                break;
            case STATE_INTERFACE_SELECTION:
                printf("\n\n[C-Shark] Please select an interface from the list above.\n");
                printf("Select an interface to sniff (enter number): ");
                fflush(stdout);
                break;
            case STATE_MAIN_MENU:
                printf("\n");
                display_main_menu();
                break;
            case STATE_INSPECTION:
                printf("\n\n[C-Shark] Use Ctrl+D to exit or enter 0 to return to main menu.\n");
                printf("Enter packet ID to inspect (0 to return to main menu): ");
                fflush(stdout);
                break;
        }
    } else if (signum == SIGTERM) {
        printf("\n[C-Shark] Exiting C-Shark...\n");
        cleanup_session();
        exit(0);
    }
}

int main() {
    char device_name[256];
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    int choice;
    
    // Check for root privileges first
    if (check_root_privileges() < 0) {
        return 1;
    }
    
    // Set up signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Print banner
    print_banner();
    
    // Set state for interface selection
    current_state = STATE_INTERFACE_SELECTION;
    
    // Discover and select interface
    if (discover_interfaces() < 0) {
        fprintf(stderr, "[C-Shark] Error: Could not discover network interfaces\n");
        return 1;
    }
    
    if (select_interface(device_name, sizeof(device_name)) < 0) {
        fprintf(stderr, "[C-Shark] Error: Invalid interface selection\n");
        return 1;
    }
    
    // Open device for sniffing
    handle = pcap_open_live(device_name, SNAP_LEN, PROMISCUOUS, TIMEOUT_MS, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "[C-Shark] Error opening device %s: %s\n", device_name, errbuf);
        return 1;
    }
    
    printf("[C-Shark] Interface '%s' selected. What's next?\n\n", device_name);
    strncpy(current_session.interface_name, device_name, sizeof(current_session.interface_name) - 1);
    
    // Set state for main menu
    current_state = STATE_MAIN_MENU;
    
    // Main program loop
    while (1) {
        display_main_menu();
        choice = get_user_choice(1, 4);
        
        switch (choice) {
            case 1:
                // Start sniffing all packets
                start_sniffing(handle, 0);
                break;
            case 2:
                // Start sniffing with filters
                start_sniffing(handle, 1);
                break;
            case 3:
                // Inspect last session
                inspect_last_session();
                break;
            case 4:
                // Exit
                printf("[C-Shark] Exiting C-Shark...\n");
                pcap_close(handle);
                cleanup_session();
                return 0;
            default:
                printf("[C-Shark] Invalid choice. Please try again.\n");
        }
    }
    
    pcap_close(handle);
    cleanup_session();
    return 0;
}

void display_main_menu(void) {
    printf("\n1. Start Sniffing (All Packets)\n");
    printf("2. Start Sniffing (With Filters)\n");
    printf("3. Inspect Last Session\n");
    printf("4. Exit C-Shark\n\n");
    printf("Select an option (1-4): ");
    fflush(stdout);
}

void start_sniffing(pcap_t *handle, int with_filter) {
    filter_type_t filter = FILTER_NONE;
    
    if (with_filter) {
        printf("\nSelect filter:\n");
        printf("1. HTTP\n");
        printf("2. HTTPS\n");
        printf("3. DNS\n");
        printf("4. ARP\n");
        printf("5. TCP\n");
        printf("6. UDP\n");
        printf("Select filter (1-6): ");
        
        int filter_choice = get_user_choice(1, 6);
        switch (filter_choice) {
            case 1: filter = FILTER_HTTP; break;
            case 2: filter = FILTER_HTTPS; break;
            case 3: filter = FILTER_DNS; break;
            case 4: filter = FILTER_ARP; break;
            case 5: filter = FILTER_TCP; break;
            case 6: filter = FILTER_UDP; break;
        }
        
        if (setup_filter(handle, filter) < 0) {
            printf("[C-Shark] Error setting up filter\n");
            return;
        }
    }
    
    // Initialize new session
    free_session();
    init_session();
    current_session.active_filter = filter;
    
    printf("\n[C-Shark] Starting packet capture on %s", current_session.interface_name);
    if (filter != FILTER_NONE) {
        printf(" with %s filter", filter_type_to_string(filter));
    }
    printf("...\n");
    printf("[C-Shark] Press Ctrl+C to stop capture\n\n");
    
    stop_sniffing = 0;
    packet_counter = 0;
    global_handle = handle;
    current_state = STATE_CAPTURING;
    
    // Start packet capture loop
    pcap_loop(handle, -1, packet_handler, (u_char*)&filter);
    
    // Reset global handle and state
    global_handle = NULL;
    current_state = STATE_MAIN_MENU;
    
    printf("\n[C-Shark] Capture stopped. %d packets captured.\n", packet_counter);
    printf("[C-Shark] Returning to main menu...\n");
}

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    filter_type_t *filter = (filter_type_t*)user_data;
    
    if (stop_sniffing) {
        return;
    }
    
    // Apply filter if specified
    if (*filter != FILTER_NONE && !matches_filter(packet, pkthdr->caplen, *filter)) {
        return;
    }
    
    packet_counter++;
    
    // Store packet
    store_packet(pkthdr, packet);
    
    // Process and display packet
    process_packet(pkthdr, packet, packet_counter);
    
    // Add small delay to make output readable
    usleep(10000); // 10ms
}

void process_packet(const struct pcap_pkthdr *pkthdr, const u_char *packet, int packet_id) {
    print_separator();
    
    // Print packet header info
    char timestamp_str[64];
    format_timestamp((struct timeval*)&pkthdr->ts, timestamp_str, sizeof(timestamp_str));
    
    printf("Packet #%d | Timestamp: %s | Length: %u bytes\n", 
           packet_id, timestamp_str, pkthdr->len);
    
    // Dissect layers
    int offset = 0;
    dissect_ethernet(packet, &offset);
}

void cleanup_session(void) {
    free_session();
}

void inspect_last_session(void) {
    current_state = STATE_INSPECTION;
    
    if (current_session.count == 0) {
        printf("\n[C-Shark] No packets in session. Start sniffing first!\n");
        current_state = STATE_MAIN_MENU;
        return;
    }
    
    printf("\n[C-Shark] Last session summary:\n");
    printf("Interface: %s\n", current_session.interface_name);
    printf("Filter: %s\n", filter_type_to_string(current_session.active_filter));
    printf("Total packets: %d\n\n", current_session.count);
    
    print_session_summary();
    
    printf("\nEnter packet ID to inspect (0 to return to main menu): ");
    int packet_id = get_user_choice(0, current_session.count);
    
    if (packet_id > 0) {
        inspect_packet_detail(packet_id);
    }
    
    current_state = STATE_MAIN_MENU;
}

void inspect_packet_detail(int packet_id) {
    if (packet_id < 1 || packet_id > current_session.count) {
        printf("[C-Shark] Invalid packet ID\n");
        return;
    }
    
    stored_packet_t *pkt = get_packet(packet_id - 1);
    if (pkt == NULL) {
        printf("[C-Shark] Could not retrieve packet\n");
        return;
    }
    
    printf("\n");
    print_separator();
    printf("DETAILED PACKET INSPECTION - Packet #%d\n", packet_id);
    print_separator();
    
    char timestamp_str[64];
    format_timestamp(&pkt->header.ts, timestamp_str, sizeof(timestamp_str));
    
    printf("Capture Info:\n");
    printf("  Timestamp: %s\n", timestamp_str);
    printf("  Captured Length: %u bytes\n", pkt->header.caplen);
    printf("  Original Length: %u bytes\n", pkt->header.len);
    printf("\n");
    
    // Full hex dump of the packet
    printf("Complete Packet Hex Dump:\n");
    print_hex_dump(pkt->data, pkt->header.caplen, "  ");
    printf("\n");
    
    // Detailed layer analysis
    printf("Layer-by-Layer Analysis:\n");
    int offset = 0;
    dissect_ethernet(pkt->data, &offset);
    
    printf("\n");
}
