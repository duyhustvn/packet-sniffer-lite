# packet-sniffer-lite

Small Linux learning project for low-level packet parsing with `AF_PACKET`.

It captures raw Ethernet frames, then manually parses:

- Ethernet, including basic 802.1Q / 802.1AD VLAN tags
- IPv4 and IPv6
- TCP
- HTTP/1.x `Host:` headers on port 80
- TLS ClientHello SNI on port 443

HTTPS payload is encrypted, so this program does not read HTTP requests inside
TLS. It only extracts the hostname from the plaintext SNI extension when the
client sends it. Encrypted ClientHello can hide this value.

## Docs

- [TLS ClientHello SNI payload walkthrough](docs/tls-sni-payload.md)

## Build

```sh
cmake -S . -B build
cmake --build build
```

Run parser tests:

```sh
ctest --test-dir build --output-on-failure
```

## Run

Raw packet sockets require root or `CAP_NET_RAW`.

```sh
sudo ./build/packet-sniffer-lite -i eth0
```

Use verbose mode when debugging capture. It prints every parsed TCP segment
with payload, even when no hostname is found:

```sh
sudo ./build/packet-sniffer-lite -v -i eth0
```

Without `-i`, it listens on all packet-visible interfaces:

```sh
sudo ./build/packet-sniffer-lite
```

Generate quick test traffic:

```sh
curl http://example.com/
curl https://example.com/
```

If you are on WSL, generate traffic from another WSL shell and bypass proxy
environment variables during testing:

```sh
curl --noproxy '*' http://example.com/
curl --noproxy '*' https://example.com/
```

If `-v` shows TCP packets but no `HTTP` or `TLS-SNI` line, the capture works
and the remaining issue is parsing or traffic shape. Common causes are proxy
ports, TCP segmentation, HTTPS without plaintext SNI, or testing traffic from
Windows apps instead of WSL processes.

Example output:

```text
HTTP 192.168.1.20:53122 -> 93.184.216.34:80 host=example.com
TLS-SNI 192.168.1.20:53124 -> 93.184.216.34:443 host=example.com
```

## Learning Roadmap

1. Start in `src/main.c` to see how `socket(AF_PACKET, SOCK_RAW, ...)` receives
   raw frames.
2. Read `src/packet_parser.c` to follow Ethernet -> IP -> TCP offsets.
3. Read `src/http_parser.c` to see why HTTP Host is simple plaintext parsing.
4. Read `src/tls_sni_parser.c` to see the TLS ClientHello layout.
5. Add a classic BPF filter so the kernel only delivers TCP 80/443 packets.
6. Add TCP stream reassembly keyed by source IP, source port, destination IP,
   and destination port. The current parser only extracts hostnames when the
   HTTP header or TLS ClientHello is contained in one TCP segment.

## Current Limits

- No TCP reassembly yet.
- IPv4 fragments are ignored.
- IPv6 fragment headers are skipped structurally, but fragmented TCP payload is
  not reassembled.
- No promiscuous mode setup.
- No kernel BPF filter yet.
