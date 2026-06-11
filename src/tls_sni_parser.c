#include "sniffer.h"

#include <string.h>

static bool get_u8(const uint8_t *buf, size_t len, size_t *off, uint8_t *out)
{
    if (*off + 1 > len) {
        return false;
    }
    *out = buf[*off];
    (*off)++;
    return true;
}

static bool get_u16(const uint8_t *buf, size_t len, size_t *off, uint16_t *out)
{
    if (*off + 2 > len) {
        return false;
    }
    *out = ((uint16_t)buf[*off] << 8) | buf[*off + 1];
    *off += 2;
    return true;
}

static bool skip_bytes(size_t len, size_t *off, size_t n)
{
    if (*off + n > len) {
        return false;
    }
    *off += n;
    return true;
}

static bool copy_hostname(const uint8_t *buf, size_t len, size_t off,
                          char *host, size_t host_len)
{
    if (len == 0 || len >= host_len) {
        return false;
    }

    for (size_t i = 0; i < len; i++) {
        uint8_t c = buf[off + i];
        if (c < 0x21 || c > 0x7e) {
            return false;
        }
    }

    memcpy(host, buf + off, len);
    host[len] = '\0';
    return true;
}

bool extract_tls_sni(const uint8_t *payload, size_t payload_len, char *host, size_t host_len)
{
    if (payload_len < 5 || host_len == 0) {
        return false;
    }

    size_t off = 0;
    uint8_t content_type;
    if (!get_u8(payload, payload_len, &off, &content_type) || content_type != 22) {
        return false;
    }

    uint16_t record_version;
    uint16_t record_len;
    if (!get_u16(payload, payload_len, &off, &record_version) ||
        !get_u16(payload, payload_len, &off, &record_len)) {
        return false;
    }
    (void)record_version;

    if (off + record_len > payload_len || record_len < 4) {
        return false;
    }
    size_t record_end = off + record_len;

    uint8_t handshake_type;
    if (!get_u8(payload, record_end, &off, &handshake_type) || handshake_type != 1) {
        return false;
    }

    if (off + 3 > record_end) {
        return false;
    }
    size_t handshake_len = ((size_t)payload[off] << 16) |
                           ((size_t)payload[off + 1] << 8) |
                           payload[off + 2];
    off += 3;

    if (off + handshake_len > record_end) {
        return false;
    }
    size_t handshake_end = off + handshake_len;

    if (!skip_bytes(handshake_end, &off, 2) || !skip_bytes(handshake_end, &off, 32)) {
        return false;
    }

    uint8_t session_id_len;
    if (!get_u8(payload, handshake_end, &off, &session_id_len) ||
        !skip_bytes(handshake_end, &off, session_id_len)) {
        return false;
    }

    uint16_t cipher_suites_len;
    if (!get_u16(payload, handshake_end, &off, &cipher_suites_len) ||
        !skip_bytes(handshake_end, &off, cipher_suites_len)) {
        return false;
    }

    uint8_t compression_methods_len;
    if (!get_u8(payload, handshake_end, &off, &compression_methods_len) ||
        !skip_bytes(handshake_end, &off, compression_methods_len)) {
        return false;
    }

    uint16_t extensions_len;
    if (!get_u16(payload, handshake_end, &off, &extensions_len)) {
        return false;
    }
    if (off + extensions_len > handshake_end) {
        return false;
    }

    size_t extensions_end = off + extensions_len;
    while (off + 4 <= extensions_end) {
        uint16_t ext_type;
        uint16_t ext_len;
        if (!get_u16(payload, extensions_end, &off, &ext_type) ||
            !get_u16(payload, extensions_end, &off, &ext_len)) {
            return false;
        }
        if (off + ext_len > extensions_end) {
            return false;
        }

        if (ext_type == 0) {
            size_t sni_off = off;
            uint16_t list_len;
            if (!get_u16(payload, off + ext_len, &sni_off, &list_len) ||
                sni_off + list_len > off + ext_len) {
                return false;
            }

            size_t list_end = sni_off + list_len;
            while (sni_off + 3 <= list_end) {
                uint8_t name_type;
                uint16_t name_len;
                if (!get_u8(payload, list_end, &sni_off, &name_type) ||
                    !get_u16(payload, list_end, &sni_off, &name_len)) {
                    return false;
                }
                if (sni_off + name_len > list_end) {
                    return false;
                }
                if (name_type == 0) {
                    return copy_hostname(payload, name_len, sni_off, host, host_len);
                }
                sni_off += name_len;
            }
            return false;
        }

        off += ext_len;
    }

    return false;
}
