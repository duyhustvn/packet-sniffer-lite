#ifndef SNIFFER_TYPES_H
#define SNIFFER_TYPES_H

#include <stddef.h>
#include <stdint.h>

#define HOST_MAX_LEN 256

struct packet_view {
    uint8_t ip_version;
    char src_ip[46];
    char dst_ip[46];
    uint16_t src_port;
    uint16_t dst_port;
    const uint8_t *payload;
    size_t payload_len;
};

#endif
