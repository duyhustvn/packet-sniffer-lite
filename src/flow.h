#ifndef FLOW_H
#define FLOW_H

#include "uthash.h"

typedef struct {
    uint8_t ip_version;
    char src_ip[46];
    char dst_ip[46];
    uint16_t src_port;
    uint16_t dst_port;
} FlowKey;

typedef struct {
    FlowKey key;

    uint8_t *buffer; 
    size_t buffer_len;
    uint32_t next_seq;

    uint64_t created_at_ms;
    uint64_t updated_at_ms;

    UT_hash_handle hh;
} Flow;

#endif // FLOW_H