#ifndef UTILS_H
#define UTILS_H

#include "sniffer.h"

// Utility functions
void clear_input_buffer(void);
int get_user_choice(int min, int max);
void print_banner(void);
void print_separator(void);
int check_root_privileges(void);
const char* filter_type_to_string(filter_type_t filter);
int matches_filter(const u_char *packet, int packet_len, filter_type_t filter);

// Time utilities
void format_timestamp(struct timeval *tv, char *buffer, size_t buffer_size);

#endif // UTILS_H