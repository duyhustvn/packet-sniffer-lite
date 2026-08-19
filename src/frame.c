#include "frame.h"
#include "common.h"
#include "http_parser.h"
#include "packet.h"
#include "packet_parser.h"
#include "tls_sni_parser.h"
#include "util.h"

#include <arpa/inet.h>

void process_frame(const uint8_t *buffer, size_t buffer_len, Flow **flows) {
  struct packet pkt;
  if (!parse_packet(buffer, buffer_len, &pkt) || pkt.payload_len == 0) {
    return;
  }

  // bool tls_payload_complete = false;
  FlowKey key;
  Flow *flow = NULL;
  if (pkt.ip_version == 4 &&
      (ntohs(pkt.dst_port) == 80 || ntohs(pkt.dst_port) == 443)) {
    construct_key(&key, pkt.ip_version, pkt.src_ip_bin.v4, pkt.dst_ip_bin.v4,
                  pkt.src_port, pkt.dst_port);

    flow = lookup(&key, *flows);
    if (flow != NULL) {
      if (flow->complete) {
        // tls_payload_complete = true;
      } else {
#ifdef DEBUG
        printf(
            "The package is segmented. Expected next seq: %u, pkt seq: %u \n",
            flow->next_seq, pkt.sequence_number);
#endif /* ifdef DEBUG */
        // Kiểm tra xem có đúng sequence number
        if (flow->next_seq != pkt.sequence_number) {
          return;
        }

        // append data to buffer
        memcpy(flow->buffer + flow->buffer_len, pkt.payload, pkt.payload_len);
        flow->buffer_len += pkt.payload_len;
        flow->next_seq = pkt.sequence_number + pkt.payload_len;
        flow->updated_at_ms = now_ms();

        if (flow->expected_payload_len == flow->buffer_len) {
#ifdef DEBUG
          printf("The package is segmented and pair success");
#endif /* ifdef DEBUG */
          flow->complete = true;
        } else {
#ifdef DEBUG
          printf("The package is segmented and pair not success");
#endif /* ifdef DEBUG */
        }
      }
    } else {
      // upsert(&key, flows, pkt.payload, pkt.payload_len, pkt.sequence_number);
      flow = (Flow *)malloc(sizeof(Flow));
      if (flow == NULL) {
        return;
      }

      uint8_t *data = pkt.payload;
      size_t data_len = pkt.payload_len;

      memset(flow, 0, sizeof(Flow));
      memcpy(&flow->key, &key, sizeof(FlowKey));
      memcpy(flow->buffer, pkt.payload, pkt.payload_len);
      flow->buffer_len = pkt.payload_len;
      flow->created_at_ms = now_ms();
      flow->updated_at_ms = now_ms();
      flow->next_seq = pkt.sequence_number + pkt.payload_len;

      // Check if payload has TLS payload length
      if (pkt.payload_len >= 5 && data[0] == 0x16) {
        uint16_t payload_len = (data[3] << 8) | data[4];
        // 5 bytes TLS record headers + độ dài payload của record
        flow->expected_payload_len = 5 + payload_len;

#ifdef DEBUG
        // printf("data_len: %ld expected_payload_len: %u \n", data_len,
        // flow->expected_payload_len);
#endif

        if (flow->expected_payload_len == data_len) {
          flow->complete = true;
        }
      }

      upsert(&key, flows, flow);
    }
  } else {
    // construct_key(&key, out->ip_version, out->src_ip_bin.v6,
    // out->dst_ip_bin.v6,
    //              out->src_port, out->dst_port);
    // chưa hỗ trợ ipv6
    return;
  }

  char host[HOST_MAX_LEN];
  const char *kind = NULL;

  if (ntohs(pkt.dst_port) == 80 && flow->complete) {
    if (extract_http_host(pkt.payload, pkt.payload_len, host, sizeof(host))) {
      kind = "HTTP";
    }
  } else if (ntohs(pkt.dst_port) == 443 && flow->complete) {
    if (extract_tls_sni(pkt.payload, pkt.payload_len, host, sizeof(host))) {
      kind = "TLS-SNI";
    }
  }

  if (kind != NULL) {
    printf("***********************************************\n");
#ifdef DEBUG
    // print_key(&key);
    print_packet(&pkt);
#endif
    printf("host=%s\n", host);
    printf("***********************************************\n\n");
    fflush(stdout);
  }
}
