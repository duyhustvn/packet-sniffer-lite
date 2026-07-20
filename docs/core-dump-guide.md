# Hướng dẫn tạo và phân tích file Core Dump khi chương trình bị crash trên Linux

Core dump (bản chụp bộ nhớ) là một tệp ghi lại trạng thái bộ nhớ hoạt động của chương trình tại thời điểm bị crash (ví dụ: khi gặp lỗi `Segmentation fault` - `SIGSEGV`, `SIGABRT`, ...). Tệp này cực kỳ hữu ích để gỡ lỗi và tìm ra nguyên nhân chính xác gây lỗi.

Dưới đây là các bước chi tiết để cấu hình và lấy file core dump trên hệ điều hành Linux.

---

## Bước 1: Cho phép sinh file Core Dump (`ulimit`)

Theo mặc định, Linux thường giới hạn kích thước file core dump bằng `0` (nghĩa là không ghi file core dump khi crash). Bạn cần thay đổi giới hạn này.

### 1. Kiểm tra giới hạn hiện tại
Chạy lệnh sau trong terminal của bạn:
```bash
ulimit -c
```
*Nếu kết quả trả về là `0`, tính năng ghi core dump đang bị tắt.*

> [!NOTE]
> Lệnh `ulimit` là một shell builtin (lệnh tích hợp sẵn của shell như bash, zsh), do đó nó không hỗ trợ tùy chọn `--help` (lệnh `ulimit --help` sẽ báo lỗi). Để xem trợ giúp của ulimit, hãy dùng `help ulimit` (trong Bash) hoặc `man zshbuiltins` (trong Zsh).

### 2. Kích hoạt core dump cho session hiện tại
Để cho phép sinh file core dump không giới hạn dung lượng trong terminal hiện tại, hãy chạy:
```bash
ulimit -c unlimited
```

### 3. Cấu hình vĩnh viễn (Khuyên dùng)
Nếu muốn cấu hình này tự động áp dụng mỗi khi bạn mở terminal mới:
- **Cho tài khoản người dùng hiện tại**: Thêm dòng `ulimit -c unlimited` vào cuối file cấu hình shell của bạn (ví dụ: `~/.bashrc` hoặc `~/.zshrc`).
- **Cho toàn hệ thống**: Chỉnh sửa file `/etc/security/limits.conf` và thêm hai dòng sau vào cuối file:
  ```text
  * soft core unlimited
  * hard core unlimited
  ```

---

## Bước 2: Cấu hình nơi lưu và định dạng tên file Core Dump

Bạn cần kiểm tra xem hệ thống Linux của mình đang xử lý core dump theo cơ chế nào bằng cách đọc file cấu hình `core_pattern`:
```bash
cat /proc/sys/kernel/core_pattern
```

Kết quả trả về thường thuộc 2 trường hợp sau:

### Trường hợp A: Sử dụng hệ thống quản lý tập trung (`systemd-coredump` hoặc `apport`)
Nếu kết quả bắt đầu bằng dấu pipe (`|`), ví dụ:
`|/lib/systemd/systemd-coredump %P %u %g %s %t %c` hoặc `|/usr/share/apport/apport ...`

Điều này có nghĩa là khi crash, hệ thống sẽ chuyển dữ liệu cho một dịch vụ để lưu trữ tập trung chứ không sinh file `core` trực tiếp trong thư mục làm việc của bạn.

> [!IMPORTANT]
> Lệnh liệt kê core dump trong hệ thống `systemd` là `coredumpctl`, không phải `coredumplist`.

#### Cách sử dụng `coredumpctl` (trên Ubuntu, Debian, Fedora... hiện đại):
1. **Liệt kê danh sách các vụ crash gần đây**:
   ```bash
   coredumpctl list
   # Hoặc lọc theo tên chương trình:
   coredumpctl list packet-sniffer-lite
   ```
2. **Debug trực tiếp vụ crash bằng GDB**:
   ```bash
   coredumpctl gdb [PID_của_tiến_trình]
   # Ví dụ: coredumpctl gdb 515052
   ```
3. **Xuất file core dump ra ngoài**:
   Nếu bạn muốn lấy file core vật lý để mang đi nơi khác debug:
   ```bash
   coredumpctl dump [PID] --output=core.bin
   ```

---

### Trường hợp B: Ghi trực tiếp ra file vật lý trong thư mục hiện tại
Nếu kết quả chỉ chứa các ký tự định dạng, ví dụ: `core` hoặc `core.%p`.

Để cấu hình hệ thống tự động lưu file core dump trực tiếp vào thư mục hiện tại khi chạy chương trình với định dạng tên dễ đọc, bạn chạy lệnh sau dưới quyền `root` hoặc `sudo`:

```bash
sudo sysctl -w kernel.core_pattern="core.%e.%p.%t"
```
Hoặc:
```bash
echo "core.%e.%p.%t" | sudo tee /proc/sys/kernel/core_pattern
```

Trong đó các ký tự định dạng có ý nghĩa:
- `%e`: Tên của chương trình thực thi (executable filename).
- `%p`: ID của tiến trình bị crash (PID).
- `%t`: Thời điểm crash (UNIX timestamp).
- `%s`: Signal gây ra crash (ví dụ: 11 đối với SIGSEGV).

> [!IMPORTANT]
> **Lưu ý bảo mật về `setcap` / `setuid` (Nguyên nhân phổ biến nhất khiến không sinh file core):**
> 
> Nếu chương trình của bạn cần quyền mạng đặc biệt và bạn sử dụng lệnh `setcap` (ví dụ: `sudo setcap cap_net_raw,cap_net_admin=eip ...`), Linux sẽ kích hoạt cơ chế bảo mật để ngăn sinh file core dump nhằm tránh rò rỉ dữ liệu nhạy cảm của tiến trình có đặc quyền.
> 
> Nếu hệ thống của bạn cấu hình `fs.suid_dumpable = 2` (Safe mode) mà `core_pattern` của bạn là **đường dẫn tương đối** (như `core.%e.%p.%t`), Linux sẽ **từ chối sinh file core**.
> 
> **Cách xử lý:**
> Bạn hãy cấu hình tạm thời `fs.suid_dumpable` về chế độ gỡ lỗi `1` bằng lệnh sau:
> ```bash
> sudo sysctl -w fs.suid_dumpable=1
> ```

---

## Bước 3: Biên dịch chương trình với thông tin Debug

Để file core dump có ích khi phân tích, chương trình của bạn phải được biên dịch kèm theo **ký hiệu gỡ lỗi (debug symbols)**.

- **Biên dịch trực tiếp bằng GCC/Clang**: Thêm cờ `-g` và khuyến khích tắt tối ưu hóa bằng `-O0`:
  ```bash
  gcc -g -O0 main.c -o packet-sniffer-lite
  ```
- **Sử dụng Makefile**: Đảm bảo cờ biên dịch `CFLAGS` chứa `-g -O0` (ví dụ chạy: `DEBUG=1 make`).
- **Sử dụng CMake**: Build ở chế độ Debug:
  Để đảm bảo các cờ debug được cấu hình chính xác và không bị ảnh hưởng bởi cache cấu hình cũ của CMake, khuyến cáo bạn nên xóa thư mục build cũ và cấu hình tường minh:
  ```bash
  rm -rf build
  cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
  cmake --build build
  ```

---

## Bước 4: Debug file Core Dump bằng GDB

Khi chương trình bị crash, một file core dump (ví dụ: `core.packet-sniffer-.528348`) sẽ được tạo ra trong thư mục hiện tại (hoặc được quản lý bởi `coredumpctl`).

Để phân tích lỗi:

1. **Mở GDB chỉ định file thực thi và file core dump**:
   ```bash
   gdb <đường_dẫn_file_thực_thi> <đường_dẫn_file_core>
   
   # Ví dụ thực tế:
   gdb ./build/packet-sniffer-lite ./core.packet-sniffer-.528348
   ```

2. **Các lệnh hữu ích trong GDB để tìm lỗi**:
   - **`bt`** (hoặc **`backtrace`**): Hiển thị danh sách các hàm được gọi (call stack) dẫn đến vị trí bị crash. Đây là lệnh quan trọng nhất.
   - **`frame <số>`**: Di chuyển con trỏ debug đến một frame cụ thể trong call stack để kiểm tra trạng thái tại hàm đó (ví dụ: `frame 0` hoặc `frame 1`).
   - **`p <tên_biến>`** (hoặc **`print <tên_biến>`**): In ra giá trị của biến tại thời điểm crash.
   - **`info locals`**: Liệt kê giá trị của tất cả các biến cục bộ trong hàm hiện tại.
   - **`info args`**: Xem giá trị các tham số truyền vào hàm hiện tại.
   - **`q`** (hoặc **`quit`**): Thoát khỏi GDB.
