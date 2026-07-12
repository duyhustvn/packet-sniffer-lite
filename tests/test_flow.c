#include "flow.h"
#include "unity.h"
#include <stdlib.h>
#include <string.h>

void setUp(void) {
  // Hàm này chạy trước mỗi test case
}

void tearDown(void) {
  // Hàm này chạy sau mỗi test case
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
      {4, 0x7f000001, 0x7f000001, 8080, 8080}
  };

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    FlowKey key;
    construct_key(&key, cases[i].ip_version, cases[i].src_ip, cases[i].dst_ip,
                  cases[i].src_port, cases[i].dst_port);

    TEST_ASSERT_EQUAL_UINT8_MESSAGE(cases[i].ip_version, key.ip_version, "IP version mismatch");
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(cases[i].src_ip, key.src_ip, "Source IP mismatch");
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(cases[i].dst_ip, key.dst_ip, "Destination IP mismatch");
    TEST_ASSERT_EQUAL_UINT16_MESSAGE(cases[i].src_port, key.src_port, "Source port mismatch");
    TEST_ASSERT_EQUAL_UINT16_MESSAGE(cases[i].dst_port, key.dst_port, "Destination port mismatch");
  }
}

void test_flow_insert_and_lookup(void) {
  typedef struct {
    const char *name;
    // Input Key
    uint8_t ip_version;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    // Input Data
    uint8_t data[128];
    size_t data_len;
    uint32_t seq;
    // Expected Output
    uint8_t expected_buffer[128];
    size_t expected_len;
    uint32_t expected_next_seq;
    bool expected_complete;
  } FlowTestCase;

  FlowTestCase cases[] = {
      {
          .name = "IPv4 HTTP flow",
          .ip_version = 4,
          .src_ip = 0x01020304,
          .dst_ip = 0x05060708,
          .src_port = 1234,
          .dst_port = 80,
          .data = "GET / HTTP/1.1\r\n",
          .data_len = 16,
          .seq = 1000,
          .expected_buffer = "GET / HTTP/1.1\r\n",
          .expected_len = 16,
          .expected_next_seq = 1016,
          .expected_complete = false
      },
      {
          .name = "HTTP flow append",
          .ip_version = 4,
          .src_ip = 0x01020304,
          .dst_ip = 0x05060708,
          .src_port = 1234,
          .dst_port = 80,
          .data = "Host: localhost\r\n",
          .data_len = 17,
          .seq = 1016,
          .expected_buffer = "GET / HTTP/1.1\r\nHost: localhost\r\n",
          .expected_len = 33,
          .expected_next_seq = 1033,
          .expected_complete = false
      },
      {
          .name = "IPv6 HTTPS flow",
          .ip_version = 6,
          .src_ip = 0x11112222,
          .dst_ip = 0x33334444,
          .src_port = 5678,
          .dst_port = 443,
          .data = "ClientHello",
          .data_len = 11,
          .seq = 2000,
          .expected_buffer = "ClientHello",
          .expected_len = 11,
          .expected_next_seq = 2011,
          .expected_complete = false
      },
      {
          .name = "TLS complete single packet",
          .ip_version = 4,
          .src_ip = 0x0a0b0c0d,
          .dst_ip = 0x0e0f1011,
          .src_port = 4321,
          .dst_port = 443,
          .data = {0x16, 0x03, 0x03, 0x00, 0x0a, 0x05, 0x06, 0x07, 0x08, 0x09},
          .data_len = 10,
          .seq = 3000,
          .expected_buffer = {0x16, 0x03, 0x03, 0x00, 0x0a, 0x05, 0x06, 0x07, 0x08, 0x09},
          .expected_len = 10,
          .expected_next_seq = 3010,
          .expected_complete = true
      },
      {
          .name = "TLS incomplete first packet",
          .ip_version = 4,
          .src_ip = 0x0a0b0c0d,
          .dst_ip = 0x0e0f1011,
          .src_port = 8888,
          .dst_port = 443,
          .data = {0x16, 0x03, 0x03, 0x00, 0x0a},
          .data_len = 5,
          .seq = 4000,
          .expected_buffer = {0x16, 0x03, 0x03, 0x00, 0x0a},
          .expected_len = 5,
          .expected_next_seq = 4005,
          .expected_complete = false
      },
      {
          .name = "TLS complete second packet",
          .ip_version = 4,
          .src_ip = 0x0a0b0c0d,
          .dst_ip = 0x0e0f1011,
          .src_port = 8888,
          .dst_port = 443,
          .data = {0x05, 0x06, 0x07, 0x08, 0x09},
          .data_len = 5,
          .seq = 4005,
          .expected_buffer = {0x16, 0x03, 0x03, 0x00, 0x0a, 0x05, 0x06, 0x07, 0x08, 0x09},
          .expected_len = 10,
          .expected_next_seq = 4010,
          .expected_complete = true
      },
      {
          .name = "Invalid sequence number (ignored)",
          .ip_version = 4,
          .src_ip = 0x0a0b0c0d,
          .dst_ip = 0x0e0f1011,
          .src_port = 8888,
          .dst_port = 443,
          .data = {0xaa, 0xbb, 0xcc},
          .data_len = 3,
          .seq = 9999, // Wrong sequence number, expected 4010
          .expected_buffer = {0x16, 0x03, 0x03, 0x00, 0x0a, 0x05, 0x06, 0x07, 0x08, 0x09},
          .expected_len = 10,
          .expected_next_seq = 4010,
          .expected_complete = true
      },
      {
          .name = "Tiny packet insertion (len < 5)",
          .ip_version = 4,
          .src_ip = 0x0a0b0c0d,
          .dst_ip = 0x0e0f1011,
          .src_port = 9999,
          .dst_port = 80,
          .data = "ACK",
          .data_len = 3,
          .seq = 5000,
          .expected_buffer = "ACK",
          .expected_len = 3,
          .expected_next_seq = 5003,
          .expected_complete = false
      }
  };

  Flow *flows = NULL;
  Flow *current, *tmp;

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    FlowKey key;
    construct_key(&key, cases[i].ip_version, cases[i].src_ip, cases[i].dst_ip,
                  cases[i].src_port, cases[i].dst_port);

    upsert(&key, &flows, cases[i].data, cases[i].data_len, cases[i].seq);

    Flow *found = lookup(&key, flows);

    TEST_ASSERT_NOT_NULL_MESSAGE(found, cases[i].name);
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(cases[i].expected_len, found->buffer_len, cases[i].name);
    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(cases[i].expected_buffer, found->buffer, cases[i].expected_len, cases[i].name);
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(cases[i].expected_next_seq, found->next_seq, cases[i].name);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].expected_complete, found->complete, cases[i].name);
  }

  // Giải phóng bộ nhớ các flow
  HASH_ITER(hh, flows, current, tmp) {
    HASH_DEL(flows, current);
    free(current);
  }
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_construct_key);
  RUN_TEST(test_flow_insert_and_lookup);
  return UNITY_END();
}