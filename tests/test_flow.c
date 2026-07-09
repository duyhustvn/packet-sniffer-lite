#include "unity.h"
#include "flow.h"
#include <string.h>
#include <stdlib.h>

void setUp(void) {
    // Hàm này chạy trước mỗi test case
}

void tearDown(void) {
    // Hàm này chạy sau mỗi test case
}

void test_construct_key(void) {
    FlowKey key;
    // Điền dữ liệu vào key
    construct_key(&key, 4, 0x01020304, 0x05060708, 1234, 80);

    // Kiểm tra các giá trị trong struct FlowKey
    TEST_ASSERT_EQUAL_UINT8(4, key.ip_version);
    TEST_ASSERT_EQUAL_UINT32(0x01020304, key.src_ip);
    TEST_ASSERT_EQUAL_UINT32(0x05060708, key.dst_ip);
    TEST_ASSERT_EQUAL_UINT16(1234, key.src_port);
    TEST_ASSERT_EQUAL_UINT16(80, key.dst_port);
}

void test_flow_insert_and_lookup(void) {
    Flow *flows = NULL;
    Flow *current, *tmp;
    FlowKey key;
    construct_key(&key, 4, 0x01020304, 0x05060708, 1234, 80);

    uint8_t data[] = "hello";
    upsert(&key, &flows, data, sizeof(data) - 1, 0);

    Flow *found = lookup(&key, flows);

    TEST_ASSERT_NOT_NULL(found);
    TEST_ASSERT_EQUAL_UINT32(sizeof(data) - 1, found->buffer_len);
    TEST_ASSERT_EQUAL_MEMORY(data, found->buffer, sizeof(data) - 1);

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