#include "common.h"
#include "frame.h"
#include "http_parser.h"
#include "packet_parser.h"
#include "tls_sni_parser.h"
#include "unity.h"
#include "unity_internals.h"

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

void setUp(void) {
  // Hàm này chạy trước mỗi test case
}

void tearDown(void) {
  // Hàm này chạy sau mỗi test case
}

static int hex_value(char c) {
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

static int hex_to_bytes(const char *hex, uint8_t *out, size_t out_len) {
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

static void test_http_host(void) {
  const uint8_t request[] = "GET / HTTP/1.1\r\n"
                            "User-Agent: test\r\n"
                            "Host: example.com\r\n"
                            "\r\n";
  char host[HOST_MAX_LEN];

  TEST_ASSERT_TRUE_MESSAGE(
      extract_http_host(request, sizeof(request) - 1, host, sizeof(host)),
      "HTTP parser did not find Host header");
  TEST_ASSERT_EQUAL_STRING_MESSAGE("example.com", host,
                                   "HTTP parser got wrong host");
}

static void test_tls_sni_hex(void) {
  const uint8_t client_hello[] = {
      0x16, 0x03, 0x01, 0x00, 0x43, 0x01, 0x00, 0x00, 0x3f, 0x03, 0x03, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x13, 0x01,
      0x01, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x10, 0x00, 0x0e, 0x00, 0x00,
      0x0b, 'e',  'x',  'a',  'm',  'p',  'l',  'e',  '.',  'c',  'o',  'm'};
  char host[HOST_MAX_LEN];

  TEST_ASSERT_TRUE_MESSAGE(
      extract_tls_sni(client_hello, sizeof(client_hello), host, sizeof(host)),
      "TLS parser did not find SNI");
  TEST_ASSERT_EQUAL_STRING_MESSAGE("example.com", host,
                                   "TLS parser got wrong host");
}

static void test_tls_sni_hex_stream(void) {
  typedef struct {
    const char *name;
    const char *payload_hex;
    const char *expected_host;
    int expected_success;
  } TestCase;

  TestCase cases[] = {
      {
          .name = "Valid SNI - googleapis.com",
          .payload_hex =
              "160303033b0100033703031d55483d258d3657dcaaf65b00ec7f6591d533a7f4"
              "983d58536608890c3363a32049c4a1770a901392310d91b110235fec52c32d30"
              "102d78d5398284cc3a2527e8003a1302130313011304c02ccca9c0adc00ac02b"
              "c0acc009c030cca8c014c02fc013009dc09d0035009cc09c002f009fccaac09f"
              "0039009ec09e0033010002b4ff01000100002d00030201000023000000050005"
              "01000000000000001700150000127777772e676f6f676c65617069732e636f6d"
              "00100017001502683208687474702f312e3108687474702f312e300033006b00"
              "690017004104d5446443124830e157e64dcf96d8e4eb1a8cb94eebde9678fcae"
              "a91066a0ac6b263120fd01845767e33fe07088a0d506f73f716bddb3a089aad5"
              "37bd3f996dd1001d00206c925154f78eaad15f07833bb889d603efacc87ede01"
              "70525f45100e01293c64001c00024001000b00020100000d0022002004010809"
              "0804040308070501080a0805050308080601080b0806060302010203002b0005"
              "0403040303000a00160014001700180019001d001e0100010101020103010400"
              "1500620000000000000000000000000000000000000000000000000000000000"
              "0000000000000000000000000000000000000000000000000000000000000000"
              "0000000000000000000000000000000000000000000000000000000000000000"
              "000000000000290137010200fc026f53a77e9d94a3b276979e0e73a4fec74742"
              "606a328f92e5e4c11f54e8bf4f063e4077b77726e7ce5f537075e13e663fb395"
              "2c6d9d3eb68e016fa26460c11fa93324485e115ea0109f99f5574dff3f956ff4"
              "dba20f89faba1965f869a934e55ce2106b1c942f9b4d7493cf4d4a63b9017451"
              "4f1e80557ea9c101cb9495d260039646fd3e35a4a801ac38506085ade3ab96be"
              "b1c3e91c3915d4b7be315cfc42104036ed1e502cef68192112a128b32ffd2675"
              "091968845a6595830fb7551dc19ed4a8f4a51755df9a3f7ca75a6ca718d0f08c"
              "702558c6cb3dfb6ad0bc6d633c18340f2ee4ee13a8018a5e095fb45e7982484b"
              "47137b0b2e2c2d5635883edf270031309c0e728e4b18dc10ceccb4547e50085c"
              "67ac88720eabf92857e7bdc3dddf9172f99e0a3ef9494805fb715ecd8ac1938"
              "9",
          .expected_host = "www.googleapis.com",
          .expected_success = 1,
      },
      {
          .name = "Valid SNI - gateway.facebook.com", // this payload is big
                                                      // because it is segmented
          .payload_hex =
              "16030107ca010007c6030312f41626be82b34df3ce81da15e5b4f556dd374bca"
              "7763a8257fb65bdde1bcce20cd222ba0c27c4927250d153b1492469d4b3f01f3"
              "419b7f5cf303107d489f8f5100207a7a130113021303c02bc02fc02cc030cca9"
              "cca8c013c014009c009d002f00350100075d1a1a0000002d000201010010000b"
              "000908687474702f312e31fe0d011a0000010001ba0020a9b5214c08702e7ef7"
              "fa8fbeaa7f5a0487c06c0ccfded3afc5e2714746e0cb6b00f0bf9a1c2207ed98"
              "f1466b79854865e0c81873f78e7e464bd34b27e86bae49b44b136509bbeccde4"
              "7f62a6c79f64f9c0d3f40c204ab1056e71a637d2c830d18a9a50a0c5c69247d4"
              "b431d831fbeb3fcccf8bd1a0929f7caaabff3e67e8c618c05e93e7a410281b1e"
              "15f36fe4e17ba9a45f4863a4f5ed316cb2731b5a1ac4b59b0ec844c4a4519229"
              "fba5a1e86d2100d17543e188d12c3868bc988f97c54bf6921c20f4940537e872"
              "7b09d966613cda4af2c921e070d76c0c1a12e872608a65776af0e622f4b31148"
              "be3d394fbe8f93b7f2dd254b1e95fb93d3ad83463db02261e054b0bf8cc28bbc"
              "f43e0cc3e2b0c38cdc000b00020100002b000706eaea03040303000a000c000a"
              "baba11ec001d0017001800230000000000190017000014676174657761792e66"
              "616365626f6f6b2e636f6d00120000001b0003020002003304ef04edbaba0001"
              "0011ec04c0d0033266ac66ed4b3ff497b7123898b4784b90e649f5f98aed04b4"
              "cdb3cd78b793ee2a0661536aad2711f9f5ad3663ab9cd9577c256e61a2aec498"
              "ae89eb863ff7b102d17c265292e5d805aa024bf2753d8e081023aa49e986a122"
              "36703a43c23d89c7df3440fe81a11d5718c52573ff276a5e7a7d9bc6494d8643"
              "312262911309c00811231a4aa520b0f9f297d070b28dc68b810114d86c1b22ba"
              "c5e23590fe6938b85a0680637be2dacdc4c09b4317ad0b8cab5ee2b8d7d557ee"
              "f4a983ac8330d7a9ada6c0c387609ea73ac7ac3aed975d5492070bdb37d4da77"
              "bab335fff6558c03b50e4a61860c5d55226387c29982ebb51af679ba1c930fc3"
              "909d00c1e89422e09911ffc801526a0320fba8f0820525b5291375019e76914f"
              "2513ddfbc022b56a44e94ba18470ce889eed7a872c0110e6b3a4e3614bfb66c5"
              "10f3525143a80bc30c7ba613390caa1079a635f001e4563ca963aaef01564677"
              "c76937acc210722532721cdbb92214577ab4a4f4bc14ad8619aaf4a6855604aa"
              "9b8021cbc9f7c9a946c3ce19813256660cb657a67810c4b4c6111e94668b018e"
              "37dc86df6988c469ba8877348c828439d9464267073e467c2c6c314e428d0e3c"
              "282a2abae6b729c1f48ac6b34babf631bfd88a8f3c89146b9165cc97ad953135"
              "2850b937a1d7878efca9b347dab15913400a0b05ab53c42f4c5ffcbb07b09c18"
              "59d8a9492383c9f51705a33e5734c005da1c22e3c4a86369e717083c10bd877c"
              "7c46cc02f40b224d45a243d92a4ca95c9414b60643b4a330c81c86a483506633"
              "38960b5820f9076c21ab1953c719578c64f62cbbfb226873bc5eac9758aa4612"
              "107c92f39119c0e170bc793a3443686fe05f59e15ed5bbbae63ba796482f9d27"
              "ab54852b235c256e062add8123b8eb36475c94f2c81db0e5af25e89ba037c2c0"
              "c47ef1429c99606db488695c0a0df852a892364a956c2ebae48db618245dfc56"
              "adc704ff98ccf4607624dbacbef38ac22a798a7654f9f57c5d2820cbb1068cc3"
              "8c59297dccd33d8b2676f4e4726dc2478ce8134816999ae124f1507620995cc0"
              "5cbc4a5b2a648514f1807082061282c48c027521f4e674e0d0a369d67a42e6a8"
              "4ca4c89e5b8babfaa39132a243fa1c58930dfc5c22ae103dd4561639cb3f1101"
              "39a1e2682df0ad729063e6807a50c535f25606fb421c69ec17d51013699b9bfc"
              "b688865b95db071160b291bb5abb2295083c162744ec8bcb27c7d4a305754881"
              "0ef96579dc3aaeb0273f183ae43824e87245cf03997202c7180548d83833506c"
              "bf12f200a8a827cd413a7c303575d2250980279c638f3ae0447debc32ff42693"
              "303bd5409670153ee69acc0ecac8b1126a30119ca8dc4158b017d8c181261ab3"
              "9ffb9fb8a88d295283889857ce4b9a88e7b6cbdabb459a03b5a6cdcbd3833eb5"
              "aa44ab7555a7b88f0908c60a7a593989d0eb8854c28f702c1fe2423727b24a19"
              "3893b73645e5b57e4540b0ec235f82d135087486d498c28ca3aa24a03527c34f"
              "66579ad8c60fefb15395fa39677aceef5787f1a3ce3ca6c8dfc1814ad69eb7f9"
              "c670c111c8e80690905267101e81e95986b9cab2e42f45b1b6f3e667b0464dea"
              "7544d0783f102206a207368540d46f567e84b6b7cbfcabcaa0cdf71ebf472d56"
              "f0cb6716c8654ad9f9e5e7681c3f2d48e75f0d226ca6945c3c6cac5969a76b94"
              "3c10d6dd48001d00206c93e249025342157cefd491f670797e948560c9bacbb0"
              "1cc7d017572ea1906e00170000000d0012001004030804040105030805050108"
              "060601ff01000100000500050100000000baba000100002900b50090008a7652"
              "ddc3aae3008f28129f6dd15d53a66e61ea6b76760f7e6a9347d2fb7ac2020000"
              "0000e81c15441dd16e148f84874ee442c7037408bdf6196a3a639740379976b2"
              "882d79f4f8dfa7174a67b611ecfe9e516a056b9fd8d3c633cca2856d54fc2481"
              "fca133c0c996b9794e8b24a34c84044f1c328ba2ba3c10ce24edde19c54598ad"
              "de5519cd3deb122e174afc230021203d94cedcd9b93ee505787fd7401f46e9a0"
              "680fdc65552fb9f0cbe7ab361c4861",
          .expected_host = "gateway.facebook.com",
          .expected_success = 1,
      },
      {
          .name = "Invalid hex format (odd length)",
          .payload_hex = "16030",
          .expected_host = NULL,
          .expected_success = 0,
      },
      {
          .name = "Invalid hex characters",
          .payload_hex = "160303033g",
          .expected_host = NULL,
          .expected_success = 0,
      },
      {
          .name = "Valid payload but no SNI",
          .payload_hex = "16030300050100000100",
          .expected_host = NULL,
          .expected_success = 0,
      },
  };

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    uint8_t payload[2048];
    char host[HOST_MAX_LEN];
    size_t payload_len = strlen(cases[i].payload_hex) / 2;

    TEST_ASSERT_TRUE_MESSAGE(payload_len <= sizeof(payload), cases[i].name);

    int hex_status = hex_to_bytes(cases[i].payload_hex, payload, payload_len);
    if (cases[i].expected_success) {
      TEST_ASSERT_EQUAL_INT_MESSAGE(0, hex_status, cases[i].name);
      TEST_ASSERT_TRUE_MESSAGE(
          extract_tls_sni(payload, payload_len, host, sizeof(host)),
          cases[i].name);
      TEST_ASSERT_EQUAL_STRING_MESSAGE(cases[i].expected_host, host,
                                       cases[i].name);
    } else {
      if (hex_status == 0) {
        TEST_ASSERT_FALSE_MESSAGE(
            extract_tls_sni(payload, payload_len, host, sizeof(host)),
            cases[i].name);
      }
    }
  }
}

static size_t build_eth_header(uint8_t *buf, uint16_t ether_type) {
  uint8_t dst_mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
  uint8_t src_mac[6] = {0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb};
  memcpy(buf, dst_mac, 6);
  memcpy(buf + 6, src_mac, 6);
  uint16_t et = htons(ether_type);
  memcpy(buf + 12, &et, 2);
  return 14;
}

static size_t build_vlan_frame(uint8_t *buf, uint16_t vlan_id,
                               uint16_t real_ethertype) {
  uint8_t dst_mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
  uint8_t src_mac[6] = {0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb};
  memcpy(buf, dst_mac, 6);
  memcpy(buf + 6, src_mac, 6);

  uint16_t tpid = htons(ETH_P_8021Q);
  uint16_t tci = htons(vlan_id & 0x0fff);
  uint16_t et = htons(real_ethertype);

  memcpy(buf + 12, &tpid, 2);
  memcpy(buf + 14, &tci, 2);
  memcpy(buf + 16, &et, 2);
  return 18;
}

static size_t build_qinq_frame(uint8_t *buf, uint16_t outer_vlan,
                               uint16_t inner_vlan, uint16_t real_ethertype) {
  uint8_t dst_mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
  uint8_t src_mac[6] = {0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb};
  memcpy(buf, dst_mac, 6);
  memcpy(buf + 6, src_mac, 6);

  uint16_t outer_tpid = htons(ETH_P_8021AD);
  uint16_t outer_tci = htons(outer_vlan & 0x0fff);
  uint16_t inner_tpid = htons(ETH_P_8021Q);
  uint16_t inner_tci = htons(inner_vlan & 0x0fff);
  uint16_t et = htons(real_ethertype);

  memcpy(buf + 12, &outer_tpid, 2);
  memcpy(buf + 14, &outer_tci, 2);
  memcpy(buf + 16, &inner_tpid, 2);
  memcpy(buf + 18, &inner_tci, 2);
  memcpy(buf + 20, &et, 2);
  return 22;
}

static size_t build_ipv4_header(uint8_t *buf, uint8_t ihl, uint16_t total_len,
                                uint8_t protocol, uint16_t frag_off,
                                const char *src_ip_str,
                                const char *dst_ip_str) {
  struct iphdr *ip = (struct iphdr *)(void *)buf;
  memset(ip, 0, ihl * 4);
  ip->version = 4;
  ip->ihl = ihl;
  ip->tos = 0;
  ip->tot_len = htons(total_len);
  ip->id = htons(0x1234);
  ip->frag_off = htons(frag_off);
  ip->ttl = 64;
  ip->protocol = protocol;
  ip->check = 0;
  inet_pton(AF_INET, src_ip_str, &ip->saddr);
  inet_pton(AF_INET, dst_ip_str, &ip->daddr);
  return ihl * 4;
}

static size_t build_ipv6_header(uint8_t *buf, uint16_t payload_len,
                                uint8_t next_header, const char *src_ip_str,
                                const char *dst_ip_str) {
  struct ip6_hdr *ip6 = (struct ip6_hdr *)(void *)buf;
  memset(ip6, 0, sizeof(*ip6));
  ip6->ip6_vfc = 0x60;
  ip6->ip6_plen = htons(payload_len);
  ip6->ip6_nxt = next_header;
  ip6->ip6_hlim = 64;
  inet_pton(AF_INET6, src_ip_str, &ip6->ip6_src);
  inet_pton(AF_INET6, dst_ip_str, &ip6->ip6_dst);
  return sizeof(*ip6);
}

static size_t build_tcp_header(uint8_t *buf, uint16_t src_port,
                               uint16_t dst_port, uint32_t seq,
                               uint8_t data_offset_words) {
  memset(buf, 0, data_offset_words * 4);
  uint16_t sp = htons(src_port);
  uint16_t dp = htons(dst_port);
  uint32_t sq = htonl(seq);
  memcpy(buf, &sp, 2);
  memcpy(buf + 2, &dp, 2);
  memcpy(buf + 4, &sq, 4);
  buf[12] = (uint8_t)(data_offset_words << 4);
  buf[13] = 0x18;
  buf[14] = 0x20;
  buf[15] = 0x00;
  return data_offset_words * 4;
}

static void test_parse_packet_ipv4_valid_tcp(void) {
  uint8_t frame[512];
  const char *payload_data = "Hello, parse_packet!";
  size_t payload_len = strlen(payload_data);

  size_t eth_len = build_eth_header(frame, ETH_P_IP);
  size_t ip_len =
      build_ipv4_header(frame + eth_len, 5, 20 + 20 + payload_len, IPPROTO_TCP,
                        0, "192.168.1.100", "10.0.0.1");
  size_t tcp_len =
      build_tcp_header(frame + eth_len + ip_len, 12345, 80, 100000, 5);
  memcpy(frame + eth_len + ip_len + tcp_len, payload_data, payload_len);
  size_t total_frame_len = eth_len + ip_len + tcp_len + payload_len;

  struct packet pkt;
  TEST_ASSERT_TRUE(parse_packet(frame, total_frame_len, &pkt));
  TEST_ASSERT_EQUAL_INT(4, pkt.ip_version);
  TEST_ASSERT_EQUAL_UINT16(htons(12345), pkt.src_port);
  TEST_ASSERT_EQUAL_UINT16(htons(80), pkt.dst_port);
  TEST_ASSERT_EQUAL_UINT32(htonl(100000), pkt.sequence_number);
  TEST_ASSERT_EQUAL_UINT(payload_len, pkt.payload_len);
  TEST_ASSERT_EQUAL_MEMORY(payload_data, pkt.payload, payload_len);

  struct in_addr expected_src, expected_dst;
  inet_pton(AF_INET, "192.168.1.100", &expected_src);
  inet_pton(AF_INET, "10.0.0.1", &expected_dst);
  TEST_ASSERT_EQUAL_UINT32(expected_src.s_addr, pkt.src_ip_bin.v4);
  TEST_ASSERT_EQUAL_UINT32(expected_dst.s_addr, pkt.dst_ip_bin.v4);
}

static void test_parse_packet_ipv4_ethernet_padding(void) {
  uint8_t frame[512];
  memset(frame, 0xAA, sizeof(frame));

  const char *payload_data = "Test";
  size_t payload_len = strlen(payload_data);

  size_t eth_len = build_eth_header(frame, ETH_P_IP);
  size_t ip_len =
      build_ipv4_header(frame + eth_len, 5, 20 + 20 + payload_len, IPPROTO_TCP,
                        0, "192.168.1.1", "192.168.1.2");
  size_t tcp_len =
      build_tcp_header(frame + eth_len + ip_len, 1111, 2222, 50, 5);
  memcpy(frame + eth_len + ip_len + tcp_len, payload_data, payload_len);

  struct packet pkt;
  TEST_ASSERT_TRUE(parse_packet(frame, 128, &pkt));
  TEST_ASSERT_EQUAL_UINT(payload_len, pkt.payload_len);
  TEST_ASSERT_EQUAL_MEMORY(payload_data, pkt.payload, payload_len);
}

static void test_parse_packet_ipv4_options(void) {
  uint8_t frame[512];
  const char *payload_data = "With IPv4 Options";
  size_t payload_len = strlen(payload_data);

  size_t eth_len = build_eth_header(frame, ETH_P_IP);
  size_t ip_len = build_ipv4_header(frame + eth_len, 6, 24 + 20 + payload_len,
                                    IPPROTO_TCP, 0, "172.16.0.1", "172.16.0.2");
  memset(frame + eth_len + 20, 0x01, 4);

  size_t tcp_len =
      build_tcp_header(frame + eth_len + ip_len, 3333, 4444, 999, 5);
  memcpy(frame + eth_len + ip_len + tcp_len, payload_data, payload_len);
  size_t total_frame_len = eth_len + ip_len + tcp_len + payload_len;

  struct packet pkt;
  TEST_ASSERT_TRUE(parse_packet(frame, total_frame_len, &pkt));
  TEST_ASSERT_EQUAL_UINT(payload_len, pkt.payload_len);
  TEST_ASSERT_EQUAL_MEMORY(payload_data, pkt.payload, payload_len);

  struct in_addr expected_src, expected_dst;
  inet_pton(AF_INET, "172.16.0.1", &expected_src);
  inet_pton(AF_INET, "172.16.0.2", &expected_dst);
  TEST_ASSERT_EQUAL_UINT32(expected_src.s_addr, pkt.src_ip_bin.v4);
  TEST_ASSERT_EQUAL_UINT32(expected_dst.s_addr, pkt.dst_ip_bin.v4);
}

static void test_parse_packet_vlan_single_tag(void) {
  uint8_t frame[512];
  const char *payload_data = "VLAN Tagged";
  size_t payload_len = strlen(payload_data);

  size_t eth_vlan_len = build_vlan_frame(frame, 100, ETH_P_IP);
  size_t ip_len =
      build_ipv4_header(frame + eth_vlan_len, 5, 20 + 20 + payload_len,
                        IPPROTO_TCP, 0, "10.10.10.1", "10.10.10.2");
  size_t tcp_len =
      build_tcp_header(frame + eth_vlan_len + ip_len, 8080, 80, 500, 5);
  memcpy(frame + eth_vlan_len + ip_len + tcp_len, payload_data, payload_len);
  size_t total_frame_len = eth_vlan_len + ip_len + tcp_len + payload_len;

  struct packet pkt;
  TEST_ASSERT_TRUE(parse_packet(frame, total_frame_len, &pkt));
  TEST_ASSERT_EQUAL_INT(4, pkt.ip_version);
  TEST_ASSERT_EQUAL_UINT16(htons(8080), pkt.src_port);
  TEST_ASSERT_EQUAL_UINT16(htons(80), pkt.dst_port);
  TEST_ASSERT_EQUAL_UINT(payload_len, pkt.payload_len);
  TEST_ASSERT_EQUAL_MEMORY(payload_data, pkt.payload, payload_len);

  struct in_addr expected_src, expected_dst;
  inet_pton(AF_INET, "10.10.10.1", &expected_src);
  inet_pton(AF_INET, "10.10.10.2", &expected_dst);
  TEST_ASSERT_EQUAL_UINT32(expected_src.s_addr, pkt.src_ip_bin.v4);
  TEST_ASSERT_EQUAL_UINT32(expected_dst.s_addr, pkt.dst_ip_bin.v4);
}

static void test_parse_packet_vlan_double_tag(void) {
  uint8_t frame[512];
  const char *payload_data = "QinQ Stacked VLAN";
  size_t payload_len = strlen(payload_data);

  size_t qinq_len = build_qinq_frame(frame, 200, 100, ETH_P_IP);
  size_t ip_len =
      build_ipv4_header(frame + qinq_len, 5, 20 + 20 + payload_len, IPPROTO_TCP,
                        0, "10.20.30.40", "10.20.30.50");
  size_t tcp_len =
      build_tcp_header(frame + qinq_len + ip_len, 9000, 443, 777, 5);
  memcpy(frame + qinq_len + ip_len + tcp_len, payload_data, payload_len);
  size_t total_frame_len = qinq_len + ip_len + tcp_len + payload_len;

  struct packet pkt;
  TEST_ASSERT_TRUE(parse_packet(frame, total_frame_len, &pkt));
  TEST_ASSERT_EQUAL_INT(4, pkt.ip_version);
  TEST_ASSERT_EQUAL_UINT16(htons(9000), pkt.src_port);
  TEST_ASSERT_EQUAL_UINT16(htons(443), pkt.dst_port);
  TEST_ASSERT_EQUAL_UINT(payload_len, pkt.payload_len);
  TEST_ASSERT_EQUAL_MEMORY(payload_data, pkt.payload, payload_len);

  struct in_addr expected_src, expected_dst;
  inet_pton(AF_INET, "10.20.30.40", &expected_src);
  inet_pton(AF_INET, "10.20.30.50", &expected_dst);
  TEST_ASSERT_EQUAL_UINT32(expected_src.s_addr, pkt.src_ip_bin.v4);
  TEST_ASSERT_EQUAL_UINT32(expected_dst.s_addr, pkt.dst_ip_bin.v4);
}

static void test_parse_packet_ipv6_valid_tcp(void) {
  uint8_t frame[512];
  const char *payload_data = "IPv6 TCP Payload";
  size_t payload_len = strlen(payload_data);

  size_t eth_len = build_eth_header(frame, ETH_P_IPV6);
  size_t ip6_len = build_ipv6_header(frame + eth_len, 20 + payload_len,
                                     IPPROTO_TCP, "2001:db8::1", "2001:db8::2");
  size_t tcp_len =
      build_tcp_header(frame + eth_len + ip6_len, 54321, 443, 50000, 5);
  memcpy(frame + eth_len + ip6_len + tcp_len, payload_data, payload_len);
  size_t total_frame_len = eth_len + ip6_len + tcp_len + payload_len;

  struct packet pkt;
  TEST_ASSERT_TRUE(parse_packet(frame, total_frame_len, &pkt));
  TEST_ASSERT_EQUAL_INT(6, pkt.ip_version);
  TEST_ASSERT_EQUAL_UINT16(htons(54321), pkt.src_port);
  TEST_ASSERT_EQUAL_UINT16(htons(443), pkt.dst_port);
  TEST_ASSERT_EQUAL_UINT32(htonl(50000), pkt.sequence_number);
  TEST_ASSERT_EQUAL_UINT(payload_len, pkt.payload_len);
  TEST_ASSERT_EQUAL_MEMORY(payload_data, pkt.payload, payload_len);

  struct in6_addr expected_src6, expected_dst6;
  inet_pton(AF_INET6, "2001:db8::1", &expected_src6);
  inet_pton(AF_INET6, "2001:db8::2", &expected_dst6);
  TEST_ASSERT_EQUAL_MEMORY(&expected_src6, pkt.src_ip_bin.v6, 16);
  TEST_ASSERT_EQUAL_MEMORY(&expected_dst6, pkt.dst_ip_bin.v6, 16);
}

static void test_parse_packet_ipv6_extension_header(void) {
  uint8_t frame[512];
  const char *payload_data = "IPv6 HopOpts Payload";
  size_t payload_len = strlen(payload_data);

  size_t eth_len = build_eth_header(frame, ETH_P_IPV6);
  size_t ip6_len =
      build_ipv6_header(frame + eth_len, 8 + 20 + payload_len, IPPROTO_HOPOPTS,
                        "2001:db8::10", "2001:db8::20");

  uint8_t *ext = frame + eth_len + ip6_len;
  memset(ext, 0, 8);
  ext[0] = IPPROTO_TCP;
  ext[1] = 0;

  size_t ext_len = 8;
  size_t tcp_len =
      build_tcp_header(frame + eth_len + ip6_len + ext_len, 8080, 80, 1234, 5);
  memcpy(frame + eth_len + ip6_len + ext_len + tcp_len, payload_data,
         payload_len);
  size_t total_frame_len = eth_len + ip6_len + ext_len + tcp_len + payload_len;

  struct packet pkt;
  TEST_ASSERT_TRUE(parse_packet(frame, total_frame_len, &pkt));
  TEST_ASSERT_EQUAL_INT(6, pkt.ip_version);
  TEST_ASSERT_EQUAL_UINT16(htons(8080), pkt.src_port);
  TEST_ASSERT_EQUAL_UINT16(htons(80), pkt.dst_port);
  TEST_ASSERT_EQUAL_UINT(payload_len, pkt.payload_len);
  TEST_ASSERT_EQUAL_MEMORY(payload_data, pkt.payload, payload_len);

  struct in6_addr expected_src6, expected_dst6;
  inet_pton(AF_INET6, "2001:db8::10", &expected_src6);
  inet_pton(AF_INET6, "2001:db8::20", &expected_dst6);
  TEST_ASSERT_EQUAL_MEMORY(&expected_src6, pkt.src_ip_bin.v6, 16);
  TEST_ASSERT_EQUAL_MEMORY(&expected_dst6, pkt.dst_ip_bin.v6, 16);
}

static void test_parse_packet_truncated_frames(void) {
  uint8_t frame[512] = {0};
  struct packet pkt;

  TEST_ASSERT_FALSE(parse_packet(frame, 0, &pkt));
  TEST_ASSERT_FALSE(parse_packet(frame, 13, &pkt));

  size_t eth_vlan_len = build_vlan_frame(frame, 100, ETH_P_IP);
  TEST_ASSERT_FALSE(parse_packet(frame, eth_vlan_len - 1, &pkt));

  size_t eth_len = build_eth_header(frame, ETH_P_IP);
  build_ipv4_header(frame + eth_len, 5, 20 + 20 + 5, IPPROTO_TCP, 0, "1.1.1.1",
                    "2.2.2.2");
  TEST_ASSERT_FALSE(parse_packet(frame, eth_len + 10, &pkt));
  TEST_ASSERT_FALSE(parse_packet(frame, eth_len + 20 + 10, &pkt));

  size_t eth6_len = build_eth_header(frame, ETH_P_IPV6);
  build_ipv6_header(frame + eth6_len, 20 + 5, IPPROTO_TCP, "::1", "::2");
  TEST_ASSERT_FALSE(parse_packet(frame, eth6_len + 20, &pkt));
}

static void test_parse_packet_non_tcp(void) {
  uint8_t frame[512];
  struct packet pkt;

  size_t eth_len = build_eth_header(frame, ETH_P_IP);
  size_t ip_len = build_ipv4_header(frame + eth_len, 5, 20 + 8, IPPROTO_UDP, 0,
                                    "1.1.1.1", "2.2.2.2");
  TEST_ASSERT_FALSE(parse_packet(frame, eth_len + ip_len + 8, &pkt));

  ip_len = build_ipv4_header(frame + eth_len, 5, 20 + 8, IPPROTO_ICMP, 0,
                             "1.1.1.1", "2.2.2.2");
  TEST_ASSERT_FALSE(parse_packet(frame, eth_len + ip_len + 8, &pkt));

  size_t eth6_len = build_eth_header(frame, ETH_P_IPV6);
  size_t ip6_len =
      build_ipv6_header(frame + eth6_len, 8, IPPROTO_UDP, "::1", "::2");
  TEST_ASSERT_FALSE(parse_packet(frame, eth6_len + ip6_len + 8, &pkt));
}

static void test_parse_packet_non_ip_ethertypes(void) {
  uint8_t frame[512];
  struct packet pkt;

  size_t eth_len = build_eth_header(frame, ETH_P_ARP);
  memset(frame + eth_len, 0, 28);
  TEST_ASSERT_FALSE(parse_packet(frame, eth_len + 28, &pkt));

  eth_len = build_eth_header(frame, 0x1234);
  memset(frame + eth_len, 0, 30);
  TEST_ASSERT_FALSE(parse_packet(frame, eth_len + 30, &pkt));
}

static void test_parse_packet_ipv4_fragments(void) {
  uint8_t frame[512];
  struct packet pkt;

  size_t eth_len = build_eth_header(frame, ETH_P_IP);
  size_t ip_len = build_ipv4_header(frame + eth_len, 5, 20 + 20, IPPROTO_TCP,
                                    0x2000, "1.1.1.1", "2.2.2.2");
  build_tcp_header(frame + eth_len + ip_len, 100, 200, 1, 5);
  TEST_ASSERT_FALSE(parse_packet(frame, eth_len + ip_len + 20, &pkt));

  ip_len = build_ipv4_header(frame + eth_len, 5, 20 + 20, IPPROTO_TCP, 100,
                             "1.1.1.1", "2.2.2.2");
  TEST_ASSERT_FALSE(parse_packet(frame, eth_len + ip_len + 20, &pkt));
}

static void test_parse_packet_invalid_header_fields(void) {
  uint8_t frame[512];
  struct packet pkt;

  size_t eth_len = build_eth_header(frame, ETH_P_IP);
  size_t ip_len = build_ipv4_header(frame + eth_len, 5, 20 + 20, IPPROTO_TCP, 0,
                                    "1.1.1.1", "2.2.2.2");
  build_tcp_header(frame + eth_len + ip_len, 100, 200, 1, 5);

  frame[eth_len] = 0x55;
  TEST_ASSERT_FALSE(parse_packet(frame, eth_len + ip_len + 20, &pkt));

  frame[eth_len] = 0x44;
  TEST_ASSERT_FALSE(parse_packet(frame, eth_len + ip_len + 20, &pkt));

  frame[eth_len] = 0x45;
  frame[eth_len + ip_len + 12] = 0x40;
  TEST_ASSERT_FALSE(parse_packet(frame, eth_len + ip_len + 20, &pkt));
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_http_host);
  RUN_TEST(test_tls_sni_hex);
  RUN_TEST(test_tls_sni_hex_stream);
  RUN_TEST(test_parse_packet_ipv4_valid_tcp);
  RUN_TEST(test_parse_packet_ipv4_ethernet_padding);
  RUN_TEST(test_parse_packet_ipv4_options);
  RUN_TEST(test_parse_packet_vlan_single_tag);
  RUN_TEST(test_parse_packet_vlan_double_tag);
  RUN_TEST(test_parse_packet_ipv6_valid_tcp);
  RUN_TEST(test_parse_packet_ipv6_extension_header);
  RUN_TEST(test_parse_packet_truncated_frames);
  RUN_TEST(test_parse_packet_non_tcp);
  RUN_TEST(test_parse_packet_non_ip_ethertypes);
  RUN_TEST(test_parse_packet_ipv4_fragments);
  RUN_TEST(test_parse_packet_invalid_header_fields);
  return UNITY_END();
}
