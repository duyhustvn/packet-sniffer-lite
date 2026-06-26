#ifndef FLOW_H
#define FLOW_H

#include "uthash.h"

typedef struct {
    uint8_t ip_version;
    uint32_t src_ip;
    uint32_t dst_ip;
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

void construct_key(
    FlowKey *key, 
    uint8_t ip_version, 
    uint32_t src_ip, 
    uint32_t dst_ip, 
    uint16_t src_port, 
    uint16_t dst_port);

#endif // FLOW_H