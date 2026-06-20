#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include "sniffer_types.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

bool parse_packet(const uint8_t *frame, size_t frame_len, struct packet_view *out);

#endif
