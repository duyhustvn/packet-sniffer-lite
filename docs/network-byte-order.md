# Network byte order và IP string

Tài liệu này giải thích các kiểu chuyển đổi nền tảng khi parse packet trong C.
Có hai nhóm chuyển đổi rất dễ bị nhầm:

```text
network byte order <-> host byte order
binary IP           <-> string IP
```

Chúng giải quyết hai vấn đề khác nhau. `ntohs()` không làm cùng việc với
`inet_ntop()`.

## Network byte order và host byte order

Packet trên mạng lưu các số nhiều byte theo `network byte order`, tức
big-endian.

Ví dụ TCP port `443` có giá trị hex là:

```text
0x01bb
```

Trong packet, hai byte này nằm theo thứ tự:

```text
01 bb
```

Nhưng CPU của máy đang chạy chương trình có thể dùng byte order khác, thường là
little-endian trên x86/x86_64. Vì vậy, khi đọc một field số từ packet và muốn
dùng nó như số bình thường để in, so sánh, cộng trừ, hoặc tính offset, cần đổi
từ network byte order sang host byte order.

Các hàm thường dùng:

| Hàm | Ý nghĩa | Dùng cho |
| --- | --- | --- |
| `ntohs(x)` | network to host short | số 16-bit |
| `ntohl(x)` | network to host long | số 32-bit |
| `htons(x)` | host to network short | số 16-bit |
| `htonl(x)` | host to network long | số 32-bit |

Trong tên hàm:

```text
n = network
h = host
s = short, 16-bit
l = long, 32-bit
```

Ví dụ khi đọc TCP header:

```c
uint16_t src_port = ntohs(tcp_header->th_sport);
uint16_t dst_port = ntohs(tcp_header->th_dport);
uint32_t seq = ntohl(tcp_header->th_seq);
uint32_t ack = ntohl(tcp_header->th_ack);
```

Ví dụ khi đọc IPv4 header:

```c
uint16_t total_len = ntohs(ip_header->tot_len);
uint16_t frag_off = ntohs(ip_header->frag_off);
```

Dùng chiều ngược lại khi tự ghi số vào packet hoặc buffer theo định dạng
network:

```c
tcp_header->th_dport = htons(443);
tcp_header->th_seq = htonl(seq);
```

Quy tắc nhớ:

```text
Đọc số từ packet để dùng trong code: ntohs / ntohl
Ghi số từ code vào packet:           htons / htonl
```

## Binary IP và string IP

Địa chỉ IP trong packet không phải string. Nó là bytes binary:

```text
IPv4 = 32 bit  = 4 bytes
IPv6 = 128 bit = 16 bytes
```

Ví dụ IPv4:

```text
192.168.1.10
```

trong packet là 4 byte:

```text
c0 a8 01 0a
```

Còn string `"192.168.1.10"` là các ký tự ASCII:

```text
'1' '9' '2' '.' '1' '6' '8' '.' '1' '.' '1' '0' '\0'
```

Vì vậy, binary IP và string IP là hai dạng biểu diễn khác nhau của cùng một
địa chỉ.

## `inet_ntop()` và `inet_pton()`

`inet_ntop()` đổi IP từ binary sang string:

```text
network to presentation
```

Ví dụ:

```c
char ip_str[INET_ADDRSTRLEN];

if (inet_ntop(AF_INET, &ip_header->ip_src, ip_str, sizeof(ip_str)) == NULL) {
    return false;
}

printf("%s\n", ip_str);
```

`inet_pton()` đổi IP từ string sang binary:

```text
presentation to network
```

Ví dụ:

```c
struct in_addr addr;

if (inet_pton(AF_INET, "192.168.1.10", &addr) != 1) {
    return false;
}
```

Với IPv6 thì dùng `AF_INET6` và buffer string `INET6_ADDRSTRLEN`:

```c
char ip6_str[INET6_ADDRSTRLEN];

if (inet_ntop(AF_INET6, &ip6_header->ip6_src, ip6_str, sizeof(ip6_str)) == NULL) {
    return false;
}
```

Kích thước string thường dùng:

| Loại IP | Binary size | String buffer |
| --- | ---: | ---: |
| IPv4 | 4 bytes | `INET_ADDRSTRLEN` |
| IPv6 | 16 bytes | `INET6_ADDRSTRLEN` |

`INET6_ADDRSTRLEN` thường là `46`, vì cần đủ chỗ cho dạng text IPv6 dài nhất
và byte kết thúc chuỗi `'\0'`.

## Lỗi hay nhầm

Không dùng `ntohl()` trước khi gọi `inet_ntop()`.

Sai:

```c
uint32_t ip = ntohl(ip_header->ip_src.s_addr);
inet_ntop(AF_INET, &ip, ip_str, sizeof(ip_str));
```

Đúng:

```c
inet_ntop(AF_INET, &ip_header->ip_src, ip_str, sizeof(ip_str));
```

Lý do: `inet_ntop()` cần binary IP ở network byte order, đúng như IP đang nằm
trong packet.

Không dùng `inet_ntop()` để convert port, TCP sequence number, length, hoặc
field số khác. Những field đó dùng `ntohs()` hoặc `ntohl()`.

Ví dụ:

```c
uint16_t port = ntohs(tcp_header->th_dport);
uint32_t seq = ntohl(tcp_header->th_seq);
```

Không dùng `ntohs()` hoặc `ntohl()` để tạo IP string. Muốn in IP thì dùng
`inet_ntop()`.

## Quy tắc nhớ nhanh

```text
IP binary -> IP string: inet_ntop()
IP string -> IP binary: inet_pton()

16-bit number từ packet -> số trong code: ntohs()
32-bit number từ packet -> số trong code: ntohl()

16-bit number trong code -> packet: htons()
32-bit number trong code -> packet: htonl()
```

Trong packet parser, các field thường cần `ntohs()`:

```text
IPv4 total length
IPv4 fragment offset
TCP source port
TCP destination port
UDP source port
UDP destination port
UDP length
TLS record length
```

Các field thường cần `ntohl()`:

```text
TCP sequence number
TCP acknowledgment number
```

Các field IP address thì dùng `inet_ntop()` khi cần in/log:

```text
IPv4 source address
IPv4 destination address
IPv6 source address
IPv6 destination address
```
