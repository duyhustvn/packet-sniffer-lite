#include "flow.h"
#include "common.h"

void print_key(FlowKey *key) {
  printf("key: %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u\n", key->src_ip >> 24,
         (key->src_ip >> 16) & 0xFF, (key->src_ip >> 8) & 0xFF,
         key->src_ip & 0xFF, key->src_port, key->dst_ip >> 24,
         (key->dst_ip >> 16) & 0xFF, (key->dst_ip >> 8) & 0xFF,
         key->dst_ip & 0xFF, key->dst_port);
}

void construct_key(FlowKey *key, uint8_t ip_version, uint32_t src_ip,
                   uint32_t dst_ip, uint16_t src_port, uint16_t dst_port) {
  // Xóa sạch bộ nhớ để tránh lỗi padding
  memset(key, 0, sizeof(FlowKey));

  key->ip_version = ip_version;
  key->src_ip = src_ip;
  key->dst_ip = dst_ip;
  key->src_port = src_port;
  key->dst_port = dst_port;
}

Flow *lookup(FlowKey *key, Flow *flows) {
  Flow *f;
  HASH_FIND(hh, flows, key, sizeof(FlowKey), f);
  return f;
}

void upsert(FlowKey *key, Flow **flows, Flow *f) {
  if (key != NULL) {
    memcpy(&f->key, key, sizeof(FlowKey));
  }
  HASH_ADD(hh, *flows, key, sizeof(FlowKey), f);
}
