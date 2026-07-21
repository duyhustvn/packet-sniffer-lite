#define _GNU_SOURCE

#include "flow.h"
#include "frame.h"

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

static void on_signal(int signo) {
  (void)signo;
  keep_running = 0;
}

static void usage(const char *prog) {
  fprintf(stderr, "Usage: %s [-v] [-i interface]\n", prog);
  fprintf(stderr, "Example: sudo %s -v -i eth0\n", prog);
}

static int bind_interface(int fd, const char *ifname) {
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

int main(int argc, char **argv) {
  const char *ifname = NULL;

  int opt;
  while ((opt = getopt(argc, argv, "hi:v")) != -1) {
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
  Flow *flows = NULL;
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
    process_frame(buffer, (size_t)nread, &flows);
  }

  close(fd);
  return 0;
}
