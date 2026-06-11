#include "sniffer.h"

#include <stdio.h>
#include <string.h>

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

static int test_tls_sni(void)
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

int main(void)
{
    if (test_http_host() != 0 || test_tls_sni() != 0) {
        return 1;
    }

    puts("parser tests passed");
    return 0;
}
