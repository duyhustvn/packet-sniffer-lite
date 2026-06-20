#include "http_parser.h"

#include <ctype.h>
#include <string.h>

static int ascii_tolower(int c)
{
    return tolower((unsigned char)c);
}

static bool starts_with_ci(const uint8_t *p, size_t len, const char *needle)
{
    size_t nlen = strlen(needle);
    if (len < nlen) {
        return false;
    }

    for (size_t i = 0; i < nlen; i++) {
        if (ascii_tolower(p[i]) != ascii_tolower((unsigned char)needle[i])) {
            return false;
        }
    }
    return true;
}

static bool looks_like_http_request(const uint8_t *payload, size_t len)
{
    static const char *methods[] = {
        "GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE "
    };

    for (size_t i = 0; i < sizeof(methods) / sizeof(methods[0]); i++) {
        if (starts_with_ci(payload, len, methods[i])) {
            return true;
        }
    }
    return false;
}

bool extract_http_host(const uint8_t *payload, size_t payload_len, char *host, size_t host_len)
{
    if (host_len == 0 || !looks_like_http_request(payload, payload_len)) {
        return false;
    }

    size_t line_start = 0;
    while (line_start < payload_len) {
        size_t line_end = line_start;
        while (line_end < payload_len && payload[line_end] != '\n') {
            line_end++;
        }

        size_t line_len = line_end - line_start;
        if (line_len > 0 && payload[line_start + line_len - 1] == '\r') {
            line_len--;
        }

        if (line_len == 0) {
            return false;
        }

        const uint8_t *line = payload + line_start;
        if (starts_with_ci(line, line_len, "Host:")) {
            size_t pos = 5;
            while (pos < line_len && (line[pos] == ' ' || line[pos] == '\t')) {
                pos++;
            }

            size_t value_len = line_len - pos;
            while (value_len > 0 &&
                   (line[pos + value_len - 1] == ' ' || line[pos + value_len - 1] == '\t')) {
                value_len--;
            }

            if (value_len == 0 || value_len >= host_len) {
                return false;
            }

            memcpy(host, line + pos, value_len);
            host[value_len] = '\0';
            return true;
        }

        line_start = line_end < payload_len ? line_end + 1 : payload_len;
    }

    return false;
}
