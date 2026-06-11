#include "sniffer.h"

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <string.h>

#define TCP_MIN_HLEN 20
#define VLAN_TAG_HLEN 4
#define IPV4_FLAG_MORE_FRAGMENTS 0x2000
#define IPV4_FRAGMENT_OFFSET_MASK 0x1fff

static bool read_u16(const uint8_t *buf, size_t len, size_t off, uint16_t *out)
{
    if (off + 2 > len) {
        return false;
    }

    uint16_t tmp;
    memcpy(&tmp, buf + off, sizeof(tmp));
    *out = ntohs(tmp);
    return true;
}

static bool skip_ipv6_extensions(const uint8_t *packet, size_t packet_len,
                                 uint8_t *next_header, size_t *off)
{
    while (1) {
        switch (*next_header) {
        case IPPROTO_HOPOPTS:
        case IPPROTO_DSTOPTS:
        case IPPROTO_ROUTING: {
            if (*off + 2 > packet_len) {
                return false;
            }
            uint8_t nh = packet[*off];
            uint8_t hdr_ext_len = packet[*off + 1];
            size_t bytes = ((size_t)hdr_ext_len + 1) * 8;
            if (*off + bytes > packet_len) {
                return false;
            }
            *next_header = nh;
            *off += bytes;
            break;
        }
        case IPPROTO_FRAGMENT:
            if (*off + 8 > packet_len) {
                return false;
            }
            *next_header = packet[*off];
            *off += 8;
            break;
        case IPPROTO_AH:
            if (*off + 2 > packet_len) {
                return false;
            }
            *next_header = packet[*off];
            *off += ((size_t)packet[*off + 1] + 2) * 4;
            if (*off > packet_len) {
                return false;
            }
            break;
        default:
            return true;
        }
    }
}

static bool parse_tcp(const uint8_t *packet, size_t packet_len, size_t tcp_off,
                      struct packet_view *out)
{
    if (tcp_off + TCP_MIN_HLEN > packet_len) {
        return false;
    }

    uint16_t src_port;
    uint16_t dst_port;
    if (!read_u16(packet, packet_len, tcp_off, &src_port) ||
        !read_u16(packet, packet_len, tcp_off + 2, &dst_port)) {
        return false;
    }

    size_t tcp_hlen = (size_t)(packet[tcp_off + 12] >> 4) * 4;
    if (tcp_hlen < TCP_MIN_HLEN || tcp_off + tcp_hlen > packet_len) {
        return false;
    }

    out->src_port = src_port;
    out->dst_port = dst_port;
    out->payload = packet + tcp_off + tcp_hlen;
    out->payload_len = packet_len - tcp_off - tcp_hlen;
    return true;
}

static bool parse_ipv4(const uint8_t *packet, size_t packet_len, struct packet_view *out)
{
    if (packet_len < sizeof(struct iphdr)) {
        return false;
    }

    const struct iphdr *ip = (const struct iphdr *)(const void *)packet;
    size_t ip_hlen = (size_t)ip->ihl * 4;
    if (ip->version != 4 || ip_hlen < sizeof(struct iphdr) || ip_hlen > packet_len) {
        return false;
    }

    uint16_t total_len = ntohs(ip->tot_len);
    if (total_len < ip_hlen || total_len > packet_len) {
        return false;
    }

    uint16_t frag = ntohs(ip->frag_off);
    if ((frag & (IPV4_FLAG_MORE_FRAGMENTS | IPV4_FRAGMENT_OFFSET_MASK)) != 0) {
        return false;
    }

    if (ip->protocol != IPPROTO_TCP) {
        return false;
    }

    struct in_addr src = {.s_addr = ip->saddr};
    struct in_addr dst = {.s_addr = ip->daddr};
    if (inet_ntop(AF_INET, &src, out->src_ip, sizeof(out->src_ip)) == NULL ||
        inet_ntop(AF_INET, &dst, out->dst_ip, sizeof(out->dst_ip)) == NULL) {
        return false;
    }

    out->ip_version = 4;
    return parse_tcp(packet, total_len, ip_hlen, out);
}

static bool parse_ipv6(const uint8_t *packet, size_t packet_len, struct packet_view *out)
{
    if (packet_len < sizeof(struct ip6_hdr)) {
        return false;
    }

    const struct ip6_hdr *ip6 = (const struct ip6_hdr *)(const void *)packet;
    if ((ip6->ip6_vfc >> 4) != 6) {
        return false;
    }

    size_t payload_len = ntohs(ip6->ip6_plen);
    size_t full_len = sizeof(struct ip6_hdr) + payload_len;
    if (full_len > packet_len) {
        return false;
    }

    uint8_t next_header = ip6->ip6_nxt;
    size_t off = sizeof(struct ip6_hdr);
    if (!skip_ipv6_extensions(packet, full_len, &next_header, &off)) {
        return false;
    }

    if (next_header != IPPROTO_TCP) {
        return false;
    }

    if (inet_ntop(AF_INET6, &ip6->ip6_src, out->src_ip, sizeof(out->src_ip)) == NULL ||
        inet_ntop(AF_INET6, &ip6->ip6_dst, out->dst_ip, sizeof(out->dst_ip)) == NULL) {
        return false;
    }

    out->ip_version = 6;
    return parse_tcp(packet, full_len, off, out);
}

bool parse_packet(const uint8_t *frame, size_t frame_len, struct packet_view *out)
{
    memset(out, 0, sizeof(*out));

    if (frame_len < ETH_HLEN) {
        return false;
    }

    size_t off = ETH_HLEN;
    uint16_t ether_type;
    if (!read_u16(frame, frame_len, 12, &ether_type)) {
        return false;
    }

    while (ether_type == ETH_P_8021Q || ether_type == ETH_P_8021AD) {
        if (!read_u16(frame, frame_len, off + 2, &ether_type)) {
            return false;
        }
        off += VLAN_TAG_HLEN;
        if (off > frame_len) {
            return false;
        }
    }

    if (ether_type == ETH_P_IP) {
        return parse_ipv4(frame + off, frame_len - off, out);
    }
    if (ether_type == ETH_P_IPV6) {
        return parse_ipv6(frame + off, frame_len - off, out);
    }

    return false;
}
