#include "flow.h"
#include "common.h"
#include "util.h"

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

void upsert(FlowKey *key, Flow **flows, uint8_t *data, size_t data_len,
            uint32_t sequence_number) {
  Flow *f = lookup(key, *flows);
  if (f != NULL) {
    // Kiểm tra xem có đúng sequence number
    if (f->next_seq != sequence_number) {
      return;
    }

    // append data to buffer
    memcpy(f->buffer + f->buffer_len, data, data_len);
    f->buffer_len += data_len;
    f->next_seq = sequence_number + data_len;
    f->updated_at_ms = now_ms();

    if (f->expected_payload_len == f->buffer_len) {
      f->complete = true;
      return;
    }
  } else {
    // insert new flow
    f = (Flow *)malloc(sizeof(Flow));
    if (f == NULL) {
      return;
    }
    memset(f, 0, sizeof(Flow));
    memcpy(&f->key, key, sizeof(FlowKey));
    memcpy(f->buffer, data, data_len);
    f->buffer_len = data_len;
    f->created_at_ms = now_ms();
    f->updated_at_ms = now_ms();
    f->next_seq = sequence_number + data_len;

    // Check if payload has TLS payload length
    if (data_len >= 5 && data[0] == 0x16) {
      uint16_t payload_len = (data[3] << 8) | data[4];
      // 5 bytes TLS record headers + độ dài payload của record
      f->expected_payload_len = 5 + payload_len;

#ifdef DEBUG
      printf("data_len: %ld expected_payload_len: %u \n", data_len,
             f->expected_payload_len);
#endif

      if (f->expected_payload_len == data_len) {
        f->complete = true;
      }
    }

    HASH_ADD(hh, *flows, key, sizeof(FlowKey), f);
  }
}
