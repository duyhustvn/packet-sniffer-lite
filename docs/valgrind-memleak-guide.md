# Hướng dẫn sử dụng Valgrind để kiểm tra rò rỉ bộ nhớ (Memory Leak) và lỗi vùng nhớ

Trong lập trình C/C++, việc quản lý bộ nhớ thủ công (`malloc`, `calloc`, `realloc`, `free`) rất dễ phát sinh lỗi rò rỉ bộ nhớ (**Memory Leak**), truy cập vùng nhớ không hợp lệ (**Invalid Read/Write**), hoặc sử dụng biến chưa khởi tạo (**Uninitialized Values**).

**Valgrind** (cụ thể là công cụ mặc định **Memcheck**) là công cụ tiêu chuẩn hàng đầu trên Linux để phát hiện và định vị chính xác vị trí các lỗi này.

---

## 1. Cài đặt Valgrind

Trên các bản phân phối Linux họ Debian/Ubuntu:

```bash
sudo apt update
sudo apt install valgrind -y
```

Kiểm tra phiên bản sau khi cài đặt:
```bash
valgrind --version
```

---

## 2. Biên dịch mã nguồn kèm cờ Debug (`-g`)

Để Valgrind có thể hiển thị **tên file** và **số dòng code** chính xác tại nơi cấp phát hoặc gây ra lỗi bộ nhớ, bạn cần biên dịch chương trình với cờ `-g` (và nên dùng `-O0` hoặc chế độ `Debug`).

Với dự án sử dụng CMake:

```bash
# Cấu hình build ở chế độ Debug
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug

# Tiến hành biên dịch
cmake --build build
```

> [!TIP]
> Không nên dùng mức tối ưu hóa cao (như `-O2` hoặc `-O3`) khi chạy Valgrind vì trình biên dịch có thể inline hàm hoặc loại bỏ biến, làm thông tin dòng code trong stack trace bị sai lệch.

---

## 3. Cú pháp lệnh kiểm tra Memory Leak

### Lệnh khuyến nghị đầy đủ nhất:

```bash
valgrind --leak-check=full \
         --show-leak-kinds=all \
         --track-origins=yes \
         --verbose \
         ./build/tests/test_flow
```

### Chi tiết các tham số quan trọng:

| Tham số | Ý nghĩa |
| :--- | :--- |
| `--leak-check=full` | Yêu cầu báo cáo chi tiết từng khối bộ nhớ bị rò rỉ (kèm call stack đầy đủ). |
| `--show-leak-kinds=all` | Hiển thị tất cả 4 loại leak: `definite`, `indirect`, `possible`, `reachable`. |
| `--track-origins=yes` | Khi gặp lỗi dùng biến chưa khởi tạo, Valgrind sẽ truy vết ngược lại nơi biến đó được tạo ra trên stack/heap. |
| `--verbose` / `-v` | In thêm thông tin tiến trình và các module liên quan. |
| `--log-file=valgrind.log` | *(Tùy chọn)* Xuất toàn bộ kết quả kiểm tra ra tệp thay vì in ra màn hình terminal. |

---

## 4. Cách đọc và phân tích báo cáo của Valgrind

Khi chương trình kết thúc, Valgrind sẽ in phần tổng kết thống kê bộ nhớ:

```text
==12345== HEAP SUMMARY:
==12345==     in use at exit: 1,024 bytes in 1 blocks
==12345==   total heap usage: 5 allocs, 4 frees, 4,096 bytes allocated
==12345== 
==12345== 1,024 bytes in 1 blocks are definitely lost in loss record 1 of 1
==12345==    at 0x4848899: malloc (in /usr/libexec/valgrind/vgpreload_memcheck-amd64-linux.so)
==12345==    by 0x109156: upsert (flow.c:52)
==12345==    by 0x1093A4: test_upsert (test_flow.c:25)
==12345==    by 0x1095B0: main (test_flow.c:80)
==12345== 
==12345== LEAK SUMMARY:
==12345==    definitely lost: 1,024 bytes in 1 blocks
==12345==    indirectly lost: 0 bytes in 0 blocks
==12345==      possibly lost: 0 bytes in 0 blocks
==12345==    still reachable: 0 bytes in 0 blocks
==12345==         suppressed: 0 bytes in 0 blocks
```

### 4.1. Phân loại trong `LEAK SUMMARY`

1. **`definitely lost` (Bắt buộc phải sửa)**:
   - Bộ nhớ chắc chắn bị rò rỉ. Không còn con trỏ nào trỏ tới khối nhớ này nữa, chương trình hoàn toàn mất khả năng giải phóng nó.
2. **`indirectly lost`**:
   - Rò rỉ gián tiếp. Xảy ra khi một cấu trúc cha (ví dụ Node cha trong cây/danh sách) bị `definitely lost`, kéo theo các con trỏ bên trong nó bị mất dấu. Sửa lỗi `definitely lost` ở cha sẽ giải quyết được lỗi này.
3. **`possibly lost`**:
   - Nghi vấn rò rỉ. Valgrind thấy vẫn có con trỏ trỏ vào vùng nhớ, nhưng con trỏ trỏ vào *giữa* khối nhớ thay vì đầu khối (offset pointer).
4. **`still reachable`**:
   - Bộ nhớ chưa được `free()` tại thời điểm chương trình thoát, nhưng vẫn còn con trỏ hợp lệ trỏ tới. Điều này xảy ra khi quên giải phóng các biến toàn cục hoặc dữ liệu trước khi `exit()`.

> [!NOTE]
> Khi toàn bộ bộ nhớ được giải phóng sạch sẽ, Valgrind sẽ báo:  
> **`All heap blocks were freed -- no leaks are possible`**

---

### 4.2. Các lỗi bộ nhớ phổ biến khác Valgrind phát hiện

#### A. Invalid read / write of size X (Truy cập bộ nhớ không hợp lệ)
Xảy ra khi bạn đọc hoặc ghi vào vùng nhớ đã bị `free()` (use-after-free) hoặc vượt quá kích thước mảng/buffer (buffer overflow):
```text
==12345== Invalid write of size 1
==12345==    at 0x109200: extract_http_host (http_parser.c:45)
==12345==  Address 0x4a58040 is 0 bytes after a block of size 64 alloc'd
```

#### B. Conditional jump or move depends on uninitialised value(s)
Xảy ra khi câu lệnh điều kiện (`if`, `switch`, `while`) sử dụng biến rác chưa được gán giá trị:
```text
==12345== Conditional jump or move depends on uninitialised value(s)
==12345==    at 0x1091A0: process_frame (frame.c:43)
```

---

## 5. Áp dụng thực tế cho dự án `packet-sniffer-lite`

### 5.1. Kiểm tra bộ nhớ trên các Unit Test

Chạy Valgrind trên binary test của bảng băm Flow và parser:

```bash
# Kiểm tra test flow (cấp phát Flow bằng malloc trong flow.c)
valgrind --leak-check=full --show-leak-kinds=all ./build/tests/test_flow

# Kiểm tra test parsers
valgrind --leak-check=full --show-leak-kinds=all ./build/tests/test_parsers
```

### 5.2. Kiểm tra bộ nhớ trên ứng dụng chính (`packet-sniffer-lite`)

Vì chương trình sniffer cần raw socket (`AF_PACKET`) và chạy trong vòng lặp vô hạn `while(1)`:

> [!WARNING]
> **Không thể chạy `valgrind ./binary` thường khi binary đã được gán `setcap`:**  
> Linux có cơ chế bảo mật ngăn chặn công cụ instrumentation/debug (như Valgrind) thực thi các file có gắn cờ đặc quyền (`setcap` hoặc `setuid`) từ tài khoản thường nhằm chống leo thang đặc quyền (Privilege Escalation).  
> Bạn sẽ gặp lỗi: `Warning: Can't execute setuid/setgid/setcap executable ... Permission denied`.
> 
> **Cách xử lý:** Luôn chạy trực tiếp với `sudo valgrind` (hoặc gỡ `setcap` bằng `sudo setcap -r ./build/packet-sniffer-lite` trước khi chạy `sudo valgrind`).

1. Chạy Valgrind với quyền `sudo`:
   ```bash
   sudo valgrind --leak-check=full --show-leak-kinds=all ./build/packet-sniffer-lite -i wlp0s20f3
   ```
2. Mở một terminal khác và tạo lưu lượng mạng thử nghiệm:
   ```bash
   curl http://example.com/
   curl https://example.com/
   ```
3. Quay lại terminal của Valgrind và bấm tổ hợp phím **`Ctrl + C`** để gửi tín hiệu `SIGINT`. Valgrind sẽ chặn tín hiệu, kết thúc tiến trình và in ra toàn bộ bảng tổng kết rò rỉ bộ nhớ.

---

## 6. Mẹo giải phóng sạch bộ nhớ (Best Practices)

- Đối với bảng băm `uthash` (như `Flow *flows` trong `src/flow.c`), cần viết hàm dọn dẹp trước khi thoát ứng dụng:
  ```c
  void free_all_flows(Flow **flows) {
    Flow *current, *tmp;
    HASH_ITER(hh, *flows, current, tmp) {
      HASH_DEL(*flows, current);
      free(current);
    }
  }
  ```
- Khởi tạo mọi mảng/biến đệm trên stack bằng `{0}` (ví dụ: `char host[HOST_MAX_LEN] = {0};`) để tránh lỗi `uninitialised value`.
