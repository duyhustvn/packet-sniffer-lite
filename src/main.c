#define _GNU_SOURCE

#include "sniffer.h"

#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

static volatile sig_atomic_t keep_running = 1;

static void on_signal(int signo)
{
    (void)signo;
    keep_running = 0;
}

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [-i interface]\n", prog);
    fprintf(stderr, "Example: sudo %s -i eth0\n", prog);
}

static int bind_interface(int fd, const char *ifname)
{
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);

    if (ioctl(fd, SIOCGIFINDEX, &ifr) == -1) {
        perror("ioctl(SIOCGIFINDEX)");
        return -1;
    }

    struct sockaddr_ll addr;
    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ALL);
    addr.sll_ifindex = ifr.ifr_ifindex;

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("bind(AF_PACKET)");
        return -1;
    }

    return 0;
}

int main(int argc, char **argv)
{
    const char *ifname = NULL;

    int opt;
    while ((opt = getopt(argc, argv, "hi:")) != -1) {
        switch (opt) {
        case 'i':
            ifname = optarg;
            break;
        case 'h':
        default:
            usage(argv[0]);
            return opt == 'h' ? 0 : 1;
        }
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd == -1) {
        perror("socket(AF_PACKET)");
        fprintf(stderr, "Hint: run with sudo or grant CAP_NET_RAW.\n");
        return 1;
    }

    if (ifname != NULL && bind_interface(fd, ifname) == -1) {
        close(fd);
        return 1;
    }

    fprintf(stderr, "Listening%s%s. Press Ctrl-C to stop.\n",
            ifname ? " on " : "", ifname ? ifname : "");

    uint8_t buffer[65536];
    while (keep_running) {
        ssize_t nread = recvfrom(fd, buffer, sizeof(buffer), 0, NULL, NULL);
        if (nread == -1) {
            if (errno == EINTR) {
                continue;
            }
            perror("recvfrom");
            close(fd);
            return 1;
        }

        struct packet_view pkt;
        if (!parse_packet(buffer, (size_t)nread, &pkt) || pkt.payload_len == 0) {
            continue;
        }

        char host[HOST_MAX_LEN];
        const char *kind = NULL;

        if ((pkt.dst_port == 80 || pkt.src_port == 80) &&
            extract_http_host(pkt.payload, pkt.payload_len, host, sizeof(host))) {
            kind = "HTTP";
        } else if ((pkt.dst_port == 443 || pkt.src_port == 443) &&
                   extract_tls_sni(pkt.payload, pkt.payload_len, host, sizeof(host))) {
            kind = "TLS-SNI";
        }

        if (kind != NULL) {
            printf("%s %s:%u -> %s:%u host=%s\n",
                   kind,
                   pkt.src_ip, pkt.src_port,
                   pkt.dst_ip, pkt.dst_port,
                   host);
            fflush(stdout);
        }
    }

    close(fd);
    return 0;
}
