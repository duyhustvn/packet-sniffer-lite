#include "frame.h"
#include "common.h"
#include "http_parser.h"
#include "packet.h"
#include "packet_parser.h"
#include "tls_sni_parser.h"

#include <arpa/inet.h>

void process_frame(const uint8_t *buffer, size_t buffer_len, Flow **flows) {
  struct packet pkt;
  if (!parse_packet(buffer, buffer_len, &pkt) || pkt.payload_len == 0) {
    return;
  }

#ifdef DEBUG
  print_packet(&pkt);
#endif

  FlowKey key;
  Flow *flow = NULL;
  bool tls_payload_complete = false;
  if (pkt.ip_version == 4) {
    construct_key(&key, pkt.ip_version, pkt.src_ip_bin.v4, pkt.dst_ip_bin.v4,
                  pkt.src_port, pkt.dst_port);
#ifdef DEBUG
    print_key(&key);
#endif
    flow = lookup(&key, *flows);
    if (flow != NULL && flow->complete) {
      tls_payload_complete = true;
    } else {
      upsert(&key, flows, pkt.payload, pkt.payload_len, pkt.sequence_number);
      return;
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

  if ((ntohs(pkt.dst_port) == 80 || ntohs(pkt.src_port) == 80) &&
      tls_payload_complete &&
      extract_http_host(pkt.payload, pkt.payload_len, host, sizeof(host))) {
    kind = "HTTP";
  } else if ((ntohs(pkt.dst_port) == 443 || ntohs(pkt.src_port) == 443) &&
             tls_payload_complete &&
             extract_tls_sni(pkt.payload, pkt.payload_len, host,
                             sizeof(host))) {
    kind = "TLS-SNI";
  }

  if (kind != NULL) {
    print_packet(&pkt);
    printf("host=%s\n", host);
    fflush(stdout);
  }
}
