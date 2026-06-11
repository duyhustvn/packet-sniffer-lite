#ifndef SNIFFER_H
#define SNIFFER_H

#include <stdbool.h>
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

bool parse_packet(const uint8_t *frame, size_t frame_len, struct packet_view *out);
bool extract_http_host(const uint8_t *payload, size_t payload_len, char *host, size_t host_len);
bool extract_tls_sni(const uint8_t *payload, size_t payload_len, char *host, size_t host_len);

#endif
