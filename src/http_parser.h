#ifndef HTTP_PARSER_H
#define HTTP_PARSER_H

#include "common.h"

bool extract_http_host(const uint8_t *payload, size_t payload_len, char *host,
                       size_t host_len);

#endif
