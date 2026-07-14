#ifndef TLS_SNI_PARSER_H
#define TLS_SNI_PARSER_H

#include "packet.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

bool extract_tls_sni(const uint8_t *payload, size_t payload_len, char *host,
                     size_t host_len);

#endif
