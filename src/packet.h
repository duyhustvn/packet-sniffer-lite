#ifndef PACKET_H
#define PACKET_H

#include <stddef.h>
#include <stdint.h>

#define HOST_MAX_LEN 256

struct packet_view {
  uint8_t ip_version;
  char src_ip[46];
  char dst_ip[46];
  union {
    uint32_t v4;
    uint8_t v6[16];
  } src_ip_bin, dst_ip_bin;
  uint16_t src_port;
  uint16_t dst_port;
  const uint8_t *payload;
  size_t payload_len;
};

void print_packet(struct packet_view *pkt);

#endif
