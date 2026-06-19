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

// Tong quan ve payload TLS ma ham nay mong doi:
// payload tro toi byte dau tien SAU TCP header, tuc TCP payload. Voi HTTPS,
// TCP payload thuong bat dau bang mot TLS record:
//
// [TLS record header 5 bytes][TLS record body...]
//
// TLS record header:
// - content_type: 1 byte. Gia tri 22 (0x16) nghia la Handshake.
// - record_version: 2 bytes. Vi du 0x0303.
// - record_len: 2 bytes. Do dai record body, KHONG tinh 5 byte header.
//
// Record body cua ClientHello lai bat dau bang TLS handshake message:
// [handshake_type 1 byte][handshake_len 3 bytes][ClientHello body...]
//
// - handshake_type = 1 nghia la ClientHello.
// - handshake_len la do dai ClientHello body, KHONG tinh 4 byte handshake header.
//
// ClientHello body co cac field theo thu tu:
// [version 2][random 32][session_id_len 1][session_id...]
// [cipher_suites_len 2][cipher_suites...]
// [compression_methods_len 1][compression_methods...]
// [extensions_len 2][extensions...]
//
// Moi extension co dang:
// [ext_type 2][ext_len 2][ext_data...]
//
// SNI la extension type 0. Ben trong SNI extension:
// [server_name_list_len 2]
// [name_type 1][name_len 2][hostname bytes...]
//
// Ham nay tim name_type = 0 (host_name), copy hostname vao host va tra ve true.
// Neu payload khong phai TLS ClientHello, bi cat giua chung, hoac khong co SNI
// thi tra ve false. Neu TLS record bi tach qua nhieu TCP segment, payload hien
// tai co the chua du record_len va ham cung se tra ve false.
bool extract_tls_sni(const uint8_t *payload, size_t payload_len, char *host, size_t host_len)
{
    if (payload_len < 5 || host_len == 0) {
        return false;
    }

    // TLS record header starts at payload[0].
    size_t off = 0;
    uint8_t content_type;
    if (!get_u8(payload, payload_len, &off, &content_type) || content_type != 22) {
        // content_type: 22 means handshake
        return false;
    }

    uint16_t record_version;
    uint16_t record_len;
    if (!get_u16(payload, payload_len, &off, &record_version) ||
        !get_u16(payload, payload_len, &off, &record_len)) {
        return false;
    }
    (void)record_version;

    // off is now 5, right after the TLS record header:
    // [content_type 1][legacy_version 2][record_len 2].
    // record_len is the TLS record body length, not the current TCP payload
    // length. If off + record_len is larger than payload_len, the current TCP
    // payload does not contain the full TLS record yet, usually because the TLS
    // record was split across multiple TCP segments.
    // For a handshake record, the body must contain at least the 4-byte
    // handshake header: [handshake_type 1][handshake_len 3].
    if (off + record_len > payload_len || record_len < 4) {
        return false;
    }
    size_t record_end = off + record_len;

    // The record body must start with a ClientHello handshake message.
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

    // Skip ClientHello legacy_version and random. They are not needed for SNI.
    if (!skip_bytes(handshake_end, &off, 2) || !skip_bytes(handshake_end, &off, 32)) {
        return false;
    }

    // Skip variable-length session_id.
    uint8_t session_id_len;
    if (!get_u8(payload, handshake_end, &off, &session_id_len) ||
        !skip_bytes(handshake_end, &off, session_id_len)) {
        return false;
    }

    // Skip variable-length cipher_suites list.
    uint16_t cipher_suites_len;
    if (!get_u16(payload, handshake_end, &off, &cipher_suites_len) ||
        !skip_bytes(handshake_end, &off, cipher_suites_len)) {
        return false;
    }

    // Skip variable-length compression_methods list.
    uint8_t compression_methods_len;
    if (!get_u8(payload, handshake_end, &off, &compression_methods_len) ||
        !skip_bytes(handshake_end, &off, compression_methods_len)) {
        return false;
    }

    // The SNI is stored inside ClientHello extensions.
    uint16_t extensions_len;
    if (!get_u16(payload, handshake_end, &off, &extensions_len)) {
        return false;
    }
    if (off + extensions_len > handshake_end) {
        return false;
    }

    size_t extensions_end = off + extensions_len;
    while (off + 4 <= extensions_end) {
        // Each extension has a 4-byte header followed by ext_len bytes of data.
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
            // Extension type 0 is server_name. Look for a host_name entry
            // and copy its hostname bytes into the caller's host buffer.
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
