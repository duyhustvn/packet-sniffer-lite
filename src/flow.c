#include "flow.h"

void construct_key(FlowKey *key, uint8_t ip_version, uint32_t src_ip,
                   uint32_t dst_ip, uint16_t src_port, uint16_t dst_port) {
  // Xóa sạch bộ nhớ để tránh lỗi padding
  memset(&key, 0, sizeof(key));

  key->ip_version = ip_version;
  key->src_ip = src_ip;
  key->dst_ip = dst_ip;
  key->src_port = src_port;
  key->dst_port = dst_port;
}