#include "flow.h"
#include "unity.h"
#include <stdlib.h>
#include <string.h>

void setUp(void) {
  // Runs before each test case
}

void tearDown(void) {
  // Runs after each test case
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
  *flows = NULL;
}

void test_construct_key(void) {
  typedef struct {
    uint8_t ip_version;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
  } KeyTestCase;

  KeyTestCase cases[] = {
      {4, 0x01020304, 0x05060708, 1234, 80},
      {6, 0x11111111, 0x22222222, 5678, 443},
      {4, 0x7f000001, 0x7f000001, 8080, 8080},
      {4, 0x00000000, 0xffffffff, 0, 65535},
  };

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    FlowKey key;
    // Fill with garbage to test that construct_key clears all padding bytes
    memset(&key, 0xFF, sizeof(FlowKey));

    construct_key(&key, cases[i].ip_version, cases[i].src_ip, cases[i].dst_ip,
                  cases[i].src_port, cases[i].dst_port);

    TEST_ASSERT_EQUAL_UINT8_MESSAGE(cases[i].ip_version, key.ip_version,
                                    "IP version mismatch");
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(cases[i].src_ip, key.src_ip,
                                     "Source IP mismatch");
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(cases[i].dst_ip, key.dst_ip,
                                     "Destination IP mismatch");
    TEST_ASSERT_EQUAL_UINT16_MESSAGE(cases[i].src_port, key.src_port,
                                     "Source port mismatch");
    TEST_ASSERT_EQUAL_UINT16_MESSAGE(cases[i].dst_port, key.dst_port,
                                     "Destination port mismatch");
  }
}

void test_print_key(void) {
  FlowKey key;
  construct_key(&key, 4, 0x0a000001, 0x0a000002, 12345, 80);
  // Ensure print_key executes without crashing
  print_key(&key);
}

void test_lookup_empty_table(void) {
  Flow *flows = NULL;
  FlowKey key;
  construct_key(&key, 4, 0x01020304, 0x05060708, 1234, 80);

  Flow *found = lookup(&key, flows);
  TEST_ASSERT_NULL(found);
}

void test_upsert_and_lookup_single(void) {
  Flow *flows = NULL;
  FlowKey key;
  construct_key(&key, 4, 0x01020304, 0x05060708, 1234, 80);

  Flow *flow = (Flow *)malloc(sizeof(Flow));
  TEST_ASSERT_NOT_NULL(flow);
  memset(flow, 0, sizeof(Flow));

  const char *data = "GET / HTTP/1.1\r\n";
  size_t data_len = strlen(data);
  memcpy(flow->buffer, data, data_len);
  flow->buffer_len = data_len;
  flow->next_seq = 1000 + data_len;
  flow->complete = false;

  upsert(&key, &flows, flow);

  // Lookup existing key
  Flow *found = lookup(&key, flows);
  TEST_ASSERT_NOT_NULL(found);
  TEST_ASSERT_EQUAL_PTR(flow, found);
  TEST_ASSERT_EQUAL_UINT8(4, found->key.ip_version);
  TEST_ASSERT_EQUAL_UINT32(0x01020304, found->key.src_ip);
  TEST_ASSERT_EQUAL_UINT32(0x05060708, found->key.dst_ip);
  TEST_ASSERT_EQUAL_UINT16(1234, found->key.src_port);
  TEST_ASSERT_EQUAL_UINT16(80, found->key.dst_port);
  TEST_ASSERT_EQUAL_UINT32(data_len, found->buffer_len);
  TEST_ASSERT_EQUAL_MEMORY(data, found->buffer, data_len);
  TEST_ASSERT_EQUAL_UINT32(1000 + data_len, found->next_seq);
  TEST_ASSERT_FALSE(found->complete);

  // Lookup non-existent key
  FlowKey non_existent_key;
  construct_key(&non_existent_key, 4, 0x01020304, 0x05060708, 1234, 81);
  Flow *not_found = lookup(&non_existent_key, flows);
  TEST_ASSERT_NULL(not_found);

  free_flows(&flows);
  TEST_ASSERT_NULL(flows);
}

void test_upsert_multiple_flows(void) {
  typedef struct {
    uint8_t ip_version;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    const char *payload;
    uint32_t next_seq;
    bool complete;
  } FlowItem;

  FlowItem items[] = {
      {4, 0x0a000001, 0x0a000002, 10001, 80, "HTTP Request 1", 1015, false},
      {4, 0x0a000001, 0x0a000002, 10002, 80, "HTTP Request 2", 1015, false},
      {4, 0x0a000003, 0x0a000004, 20001, 443, "TLS ClientHello 1", 2017, true},
      {6, 0x11112222, 0x33334444, 30001, 8080, "IPv6 Traffic", 3012, false},
  };

  Flow *flows = NULL;
  size_t count = sizeof(items) / sizeof(items[0]);

  for (size_t i = 0; i < count; i++) {
    FlowKey key;
    construct_key(&key, items[i].ip_version, items[i].src_ip, items[i].dst_ip,
                  items[i].src_port, items[i].dst_port);

    Flow *f = (Flow *)malloc(sizeof(Flow));
    TEST_ASSERT_NOT_NULL(f);
    memset(f, 0, sizeof(Flow));

    size_t payload_len = strlen(items[i].payload);
    memcpy(f->buffer, items[i].payload, payload_len);
    f->buffer_len = payload_len;
    f->next_seq = items[i].next_seq;
    f->complete = items[i].complete;

    upsert(&key, &flows, f);
  }

  // Check count in hash table
  unsigned int hash_count = HASH_COUNT(flows);
  TEST_ASSERT_EQUAL_UINT(count, hash_count);

  // Validate lookup for each item
  for (size_t i = 0; i < count; i++) {
    FlowKey key;
    construct_key(&key, items[i].ip_version, items[i].src_ip, items[i].dst_ip,
                  items[i].src_port, items[i].dst_port);

    Flow *found = lookup(&key, flows);
    TEST_ASSERT_NOT_NULL(found);
    TEST_ASSERT_EQUAL_UINT8(items[i].ip_version, found->key.ip_version);
    TEST_ASSERT_EQUAL_UINT32(items[i].src_ip, found->key.src_ip);
    TEST_ASSERT_EQUAL_UINT32(items[i].dst_ip, found->key.dst_ip);
    TEST_ASSERT_EQUAL_UINT16(items[i].src_port, found->key.src_port);
    TEST_ASSERT_EQUAL_UINT16(items[i].dst_port, found->key.dst_port);

    size_t expected_len = strlen(items[i].payload);
    TEST_ASSERT_EQUAL_UINT32(expected_len, found->buffer_len);
    TEST_ASSERT_EQUAL_MEMORY(items[i].payload, found->buffer, expected_len);
    TEST_ASSERT_EQUAL_UINT32(items[i].next_seq, found->next_seq);
    TEST_ASSERT_EQUAL_INT(items[i].complete, found->complete);
  }

  free_flows(&flows);
  TEST_ASSERT_NULL(flows);
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_construct_key);
  RUN_TEST(test_print_key);
  RUN_TEST(test_lookup_empty_table);
  RUN_TEST(test_upsert_and_lookup_single);
  RUN_TEST(test_upsert_multiple_flows);
  return UNITY_END();
}