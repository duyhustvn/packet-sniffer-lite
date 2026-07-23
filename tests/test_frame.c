#include "frame.h"
#include "flow.h"
#include "packet_parser.h"
#include "unity.h"

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void setUp(void) {}

void tearDown(void) {}

static size_t build_eth_header(uint8_t *buf, uint16_t ether_type) {
  uint8_t dst_mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
  uint8_t src_mac[6] = {0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb};
  memcpy(buf, dst_mac, 6);
  memcpy(buf + 6, src_mac, 6);
  uint16_t et = htons(ether_type);
  memcpy(buf + 12, &et, 2);
  return 14;
}

static size_t build_ipv4_header(uint8_t *buf, uint8_t ihl, uint16_t total_len,
                                uint8_t protocol, uint16_t frag_off,
                                const char *src_ip_str,
                                const char *dst_ip_str) {
  struct iphdr *ip = (struct iphdr *)(void *)buf;
  memset(ip, 0, ihl * 4);
  ip->version = 4;
  ip->ihl = ihl;
  ip->tos = 0;
  ip->tot_len = htons(total_len);
  ip->id = htons(0x1234);
  ip->frag_off = htons(frag_off);
  ip->ttl = 64;
  ip->protocol = protocol;
  ip->check = 0;
  inet_pton(AF_INET, src_ip_str, &ip->saddr);
  inet_pton(AF_INET, dst_ip_str, &ip->daddr);
  return ihl * 4;
}

static size_t build_ipv6_header(uint8_t *buf, uint16_t payload_len,
                                uint8_t next_header, const char *src_ip_str,
                                const char *dst_ip_str) {
  struct ip6_hdr *ip6 = (struct ip6_hdr *)(void *)buf;
  memset(ip6, 0, sizeof(*ip6));
  ip6->ip6_vfc = 0x60;
  ip6->ip6_plen = htons(payload_len);
  ip6->ip6_nxt = next_header;
  ip6->ip6_hlim = 64;
  inet_pton(AF_INET6, src_ip_str, &ip6->ip6_src);
  inet_pton(AF_INET6, dst_ip_str, &ip6->ip6_dst);
  return sizeof(*ip6);
}

static size_t build_tcp_header(uint8_t *buf, uint16_t src_port,
                               uint16_t dst_port, uint32_t seq,
                               uint8_t data_offset_words) {
  memset(buf, 0, data_offset_words * 4);
  uint16_t sp = htons(src_port);
  uint16_t dp = htons(dst_port);
  uint32_t sq = htonl(seq);
  memcpy(buf, &sp, 2);
  memcpy(buf + 2, &dp, 2);
  memcpy(buf + 4, &sq, 4);
  buf[12] = (uint8_t)(data_offset_words << 4);
  buf[13] = 0x18;
  buf[14] = 0x20;
  buf[15] = 0x00;
  return data_offset_words * 4;
}

static void free_flows(Flow **flows) {
  if (flows == NULL || *flows == NULL) {
    return;
  }
  Flow *current, *tmp;
  HASH_ITER(hh, *flows, current, tmp) {
    HASH_DEL(*flows, current);
    free(current);
  }
}

static void test_process_frame_invalid_frame(void) {
  uint8_t invalid_frame[10] = {0x00};
  Flow *flows = NULL;

  process_frame(invalid_frame, sizeof(invalid_frame), &flows);
  TEST_ASSERT_NULL(flows);
}

static void test_process_frame_zero_payload(void) {
  uint8_t frame[512];
  size_t eth_len = build_eth_header(frame, ETH_P_IP);
  size_t ip_len = build_ipv4_header(frame + eth_len, 5, 20 + 20, IPPROTO_TCP, 0,
                                    "192.168.1.1", "10.0.0.1");
  size_t tcp_len = build_tcp_header(frame + eth_len + ip_len, 1234, 80, 100, 5);
  size_t total_len = eth_len + ip_len + tcp_len;

  Flow *flows = NULL;
  process_frame(frame, total_len, &flows);
  TEST_ASSERT_NULL(flows);
}

static void test_process_frame_ipv6_ignored(void) {
  uint8_t frame[512];
  const char *payload_data = "IPv6 Payload";
  size_t payload_len = strlen(payload_data);

  size_t eth_len = build_eth_header(frame, ETH_P_IPV6);
  size_t ip6_len = build_ipv6_header(frame + eth_len, 20 + payload_len,
                                     IPPROTO_TCP, "2001:db8::1", "2001:db8::2");
  size_t tcp_len = build_tcp_header(frame + eth_len + ip6_len, 5555, 80, 500, 5);
  memcpy(frame + eth_len + ip6_len + tcp_len, payload_data, payload_len);

  Flow *flows = NULL;
  process_frame(frame, eth_len + ip6_len + tcp_len + payload_len, &flows);
  TEST_ASSERT_NULL(flows);
}

static void test_process_frame_ipv4_http_flow_creation(void) {
  uint8_t frame[512];
  const char *payload_data =
      "GET /index.html HTTP/1.1\r\nHost: myapp.com\r\n\r\n";
  size_t payload_len = strlen(payload_data);

  size_t eth_len = build_eth_header(frame, ETH_P_IP);
  size_t ip_len =
      build_ipv4_header(frame + eth_len, 5, 20 + 20 + payload_len, IPPROTO_TCP,
                        0, "192.168.1.100", "10.0.0.1");
  size_t tcp_len =
      build_tcp_header(frame + eth_len + ip_len, 12345, 80, 1000, 5);
  memcpy(frame + eth_len + ip_len + tcp_len, payload_data, payload_len);
  size_t total_frame_len = eth_len + ip_len + tcp_len + payload_len;

  Flow *flows = NULL;
  process_frame(frame, total_frame_len, &flows);

  TEST_ASSERT_NOT_NULL(flows);

  struct in_addr src_addr, dst_addr;
  inet_pton(AF_INET, "192.168.1.100", &src_addr);
  inet_pton(AF_INET, "10.0.0.1", &dst_addr);

  FlowKey key;
  construct_key(&key, 4, src_addr.s_addr, dst_addr.s_addr, htons(12345),
                htons(80));

  Flow *f = lookup(&key, flows);
  TEST_ASSERT_NOT_NULL(f);
  TEST_ASSERT_EQUAL_UINT(payload_len, f->buffer_len);
  TEST_ASSERT_EQUAL_MEMORY(payload_data, f->buffer, payload_len);

  free_flows(&flows);
}

static void test_process_frame_tls_flow_completion(void) {
  uint8_t frame[512];
  uint8_t tls_payload[] = {
      0x16, 0x03, 0x01, 0x00, 0x05,
      'H',  'E',  'L',  'L',  'O'};
  size_t payload_len = sizeof(tls_payload);

  size_t eth_len = build_eth_header(frame, ETH_P_IP);
  size_t ip_len =
      build_ipv4_header(frame + eth_len, 5, 20 + 20 + payload_len, IPPROTO_TCP,
                        0, "192.168.1.50", "10.0.0.2");
  size_t tcp_len =
      build_tcp_header(frame + eth_len + ip_len, 54321, 443, 2000, 5);
  memcpy(frame + eth_len + ip_len + tcp_len, tls_payload, payload_len);
  size_t total_frame_len = eth_len + ip_len + tcp_len + payload_len;

  Flow *flows = NULL;

  process_frame(frame, total_frame_len, &flows);
  TEST_ASSERT_NOT_NULL(flows);

  struct in_addr src_addr, dst_addr;
  inet_pton(AF_INET, "192.168.1.50", &src_addr);
  inet_pton(AF_INET, "10.0.0.2", &dst_addr);

  FlowKey key;
  construct_key(&key, 4, src_addr.s_addr, dst_addr.s_addr, htons(54321),
                htons(443));

  Flow *f = lookup(&key, flows);
  TEST_ASSERT_NOT_NULL(f);

  process_frame(frame, total_frame_len, &flows);

  free_flows(&flows);
}

static void test_process_frame_out_of_order_seq(void) {
  uint8_t frame1[512], frame2[512];
  const char *data1 = "Part1";
  size_t len1 = strlen(data1);

  size_t eth_len = build_eth_header(frame1, ETH_P_IP);
  size_t ip_len = build_ipv4_header(frame1 + eth_len, 5, 20 + 20 + len1,
                                    IPPROTO_TCP, 0, "192.168.1.1", "10.0.0.1");
  size_t tcp_len =
      build_tcp_header(frame1 + eth_len + ip_len, 10000, 80, 100, 5);
  memcpy(frame1 + eth_len + ip_len + tcp_len, data1, len1);

  Flow *flows = NULL;
  process_frame(frame1, eth_len + ip_len + tcp_len + len1, &flows);
  TEST_ASSERT_NOT_NULL(flows);

  const char *data2 = "Part2";
  size_t len2 = strlen(data2);
  build_eth_header(frame2, ETH_P_IP);
  build_ipv4_header(frame2 + eth_len, 5, 20 + 20 + len2, IPPROTO_TCP, 0,
                    "192.168.1.1", "10.0.0.1");
  build_tcp_header(frame2 + eth_len + ip_len, 10000, 80, 9999, 5);
  memcpy(frame2 + eth_len + ip_len + tcp_len, data2, len2);

  process_frame(frame2, eth_len + ip_len + tcp_len + len2, &flows);

  struct in_addr src_addr, dst_addr;
  inet_pton(AF_INET, "192.168.1.1", &src_addr);
  inet_pton(AF_INET, "10.0.0.1", &dst_addr);
  FlowKey key;
  construct_key(&key, 4, src_addr.s_addr, dst_addr.s_addr, htons(10000),
                htons(80));

  Flow *f = lookup(&key, flows);
  TEST_ASSERT_NOT_NULL(f);
  TEST_ASSERT_EQUAL_UINT(5, f->buffer_len);

  free_flows(&flows);
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_process_frame_invalid_frame);
  RUN_TEST(test_process_frame_zero_payload);
  RUN_TEST(test_process_frame_ipv6_ignored);
  RUN_TEST(test_process_frame_ipv4_http_flow_creation);
  RUN_TEST(test_process_frame_tls_flow_completion);
  RUN_TEST(test_process_frame_out_of_order_seq);
  return UNITY_END();
}
