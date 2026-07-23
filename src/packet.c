#include "packet.h"
#include <arpa/inet.h>
#include <stdio.h>

void print_packet(struct packet *pkt) {
  if (pkt->ip_version == 4) {
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &pkt->src_ip_bin.v4, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &pkt->dst_ip_bin.v4, dst_ip, sizeof(dst_ip));
    printf("IP %s:%u -> %s:%u seq_num=%u\n", src_ip, pkt->src_port, dst_ip,
           pkt->dst_port, pkt->sequence_number);
  } else if (pkt->ip_version == 6) {
    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, pkt->src_ip_bin.v6, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET6, pkt->dst_ip_bin.v6, dst_ip, sizeof(dst_ip));
    printf("IP %s:%u -> %s:%u seq_num=%u\n", src_ip, pkt->src_port, dst_ip,
           pkt->dst_port, pkt->sequence_number);
  }
}
