#ifndef FLOW_H
#define FLOW_H

#include "uthash.h"
#include <stdbool.h>
#include <stdint.h>

typedef struct {
  uint8_t ip_version;
  uint32_t src_ip;
  uint32_t dst_ip;
  uint16_t src_port;
  uint16_t dst_port;
} FlowKey;

typedef struct {
  FlowKey key;

  uint8_t buffer[4096]; // 4 KB
  size_t buffer_len;
  uint32_t next_seq;

  uint16_t expected_payload_len;

  uint64_t created_at_ms;
  uint64_t updated_at_ms;

  bool complete;

  UT_hash_handle hh;
} Flow;

void construct_key(FlowKey *key, uint8_t ip_version, uint32_t src_ip,
                   uint32_t dst_ip, uint16_t src_port, uint16_t dst_port);

Flow *lookup(FlowKey *key, Flow *flows);

void upsert(FlowKey *key, Flow **flows, uint8_t *data, size_t data_len,
            uint32_t sequence_number);

#endif // FLOW_H