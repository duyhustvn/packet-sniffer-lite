#include "sniffer.h"

#include <stdio.h>
#include <string.h>

static int hex_value(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

static int hex_to_bytes(const char *hex, uint8_t *out, size_t out_len)
{
    size_t hex_len = strlen(hex);
    if (hex_len != out_len * 2) {
        return 1;
    }

    for (size_t i = 0; i < out_len; i++) {
        int hi = hex_value(hex[i * 2]);
        int lo = hex_value(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) {
            return 1;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }

    return 0;
}

static int test_http_host(void)
{
    const uint8_t request[] =
        "GET / HTTP/1.1\r\n"
        "User-Agent: test\r\n"
        "Host: example.com\r\n"
        "\r\n";
    char host[HOST_MAX_LEN];

    if (!extract_http_host(request, sizeof(request) - 1, host, sizeof(host))) {
        fprintf(stderr, "HTTP parser did not find Host header\n");
        return 1;
    }

    if (strcmp(host, "example.com") != 0) {
        fprintf(stderr, "HTTP parser got '%s'\n", host);
        return 1;
    }

    return 0;
}

static int test_tls_sni_hex(void)
{
    const uint8_t client_hello[] = {
        0x16, 0x03, 0x01, 0x00, 0x43,
        0x01, 0x00, 0x00, 0x3f,
        0x03, 0x03,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
        0x00, 0x02, 0x13, 0x01,
        0x01, 0x00,
        0x00, 0x14,
        0x00, 0x00, 0x00, 0x10,
        0x00, 0x0e,
        0x00, 0x00, 0x0b,
        'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'
    };
    char host[HOST_MAX_LEN];

    if (!extract_tls_sni(client_hello, sizeof(client_hello), host, sizeof(host))) {
        fprintf(stderr, "TLS parser did not find SNI\n");
        return 1;
    }

    if (strcmp(host, "example.com") != 0) {
        fprintf(stderr, "TLS parser got '%s'\n", host);
        return 1;
    }

    return 0;
}

static int test_tls_sni_hex_stream(void)
{
    const char *payload_hex =
        "160303033b0100033703031d55483d258d3657dcaaf65b00ec7f6591d533a7f4983d58536608890c3363a3"
        "2049c4a1770a901392310d91b110235fec52c32d30102d78d5398284cc3a2527e8003a130213031301130"
        "4c02ccca9c0adc00ac02bc0acc009c030cca8c014c02fc013009dc09d0035009cc09c002f009fccaac09"
        "f0039009ec09e0033010002b4ff01000100002d0003020100002300000005000501000000000000001700"
        "150000127777772e676f6f676c65617069732e636f6d00100017001502683208687474702f312e31086874"
        "74702f312e300033006b00690017004104d5446443124830e157e64dcf96d8e4eb1a8cb94eebde9678fc"
        "aea91066a0ac6b263120fd01845767e33fe07088a0d506f73f716bddb3a089aad537bd3f996dd1001d00"
        "206c925154f78eaad15f07833bb889d603efacc87ede0170525f45100e01293c64001c00024001000b00"
        "020100000d00220020040108090804040308070501080a0805050308080601080b0806060302010203002b"
        "00050403040303000a00160014001700180019001d001e0100010101020103010400150062000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000029"
        "0137010200fc026f53a77e9d94a3b276979e0e73a4fec74742606a328f92e5e4c11f54e8bf4f063e407"
        "7b77726e7ce5f537075e13e663fb3952c6d9d3eb68e016fa26460c11fa93324485e115ea0109f99f5574"
        "dff3f956ff4dba20f89faba1965f869a934e55ce2106b1c942f9b4d7493cf4d4a63b90174514f1e805"
        "57ea9c101cb9495d260039646fd3e35a4a801ac38506085ade3ab96beb1c3e91c3915d4b7be315cfc42"
        "104036ed1e502cef68192112a128b32ffd2675091968845a6595830fb7551dc19ed4a8f4a51755df9a3"
        "f7ca75a6ca718d0f08c702558c6cb3dfb6ad0bc6d633c18340f2ee4ee13a8018a5e095fb45e7982484b"
        "47137b0b2e2c2d5635883edf270031309c0e728e4b18dc10ceccb4547e50085c67ac88720eabf92857e"
        "7bdc3dddf9172f99e0a3ef9494805fb715ecd8ac19389";
    uint8_t payload[832];
    char host[HOST_MAX_LEN];

    if (hex_to_bytes(payload_hex, payload, sizeof(payload)) != 0) {
        fprintf(stderr, "Captured TLS payload hex is invalid\n");
        return 1;
    }

    if (!extract_tls_sni(payload, sizeof(payload), host, sizeof(host))) {
        fprintf(stderr, "TLS parser did not find SNI in captured payload\n");
        return 1;
    }

    if (strcmp(host, "www.googleapis.com") != 0) {
        fprintf(stderr, "TLS parser got '%s' from captured payload\n", host);
        return 1;
    }

    return 0;
}

int main(void)
{
    if (test_http_host() != 0 ||
        test_tls_sni_hex() != 0 ||
        test_tls_sni_hex_stream() != 0) {
        return 1;
    }

    puts("parser tests passed");
    return 0;
}
