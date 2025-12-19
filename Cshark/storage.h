#ifndef STORAGE_H
#define STORAGE_H

#include "sniffer.h"

// Function declarations for packet storage
int init_session(void);
int store_packet(const struct pcap_pkthdr *pkthdr, const u_char *packet);
void free_session(void);
int get_packet_count(void);
stored_packet_t* get_packet(int index);
void print_session_summary(void);

#endif // STORAGE_H