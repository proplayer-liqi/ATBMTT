# Trao đổi khoá Diffie–Hellman — Cài đặt và demo

Bài tập nhóm môn **An toàn và bảo mật thông tin**. Chương trình tự cài đặt giao thức trao đổi khoá Diffie–Hellman (DH) từ đầu bằng Python, gồm:

- chạy từng bước trên bộ số nhỏ, khớp với ví dụ tính tay;
- trao đổi khoá 2048 bít, rồi dùng khoá đó mã hoá và giải mã tệp ảnh hoặc văn bản;
- minh hoạ tấn công người đứng giữa (MITM) và cách phòng chống;
- thử phá DH bằng cách giải logarit rời rạc;
- đo thời gian chạy và chạy bộ kiểm thử đối chiếu với chuẩn RFC/NIST.

Ký hiệu trong chương trình theo slide bài giảng: **q** (số nguyên tố), **α** (căn nguyên thuỷ), **x_A, x_B** (khoá riêng), **y_A, y_B** (khoá công khai), **K_AB** (khoá chung).

---

## 1. Yêu cầu môi trường

| Thành phần | Yêu cầu |
|---|---|
| Python | **3.8 trở lên** (đã thử trên 3.11, 3.12, 3.13) |
| Thư viện bắt buộc | **Không có.** Phần thuật toán chỉ dùng thư viện chuẩn của Python |
| Thư viện tuỳ chọn | `cryptography`, chỉ dùng trong bộ kiểm thử để **đối chiếu** kết quả |
| OpenSSL (tuỳ chọn) | Dùng trong bộ kiểm thử để so tham số nhóm RFC |
| Terminal | Nên dùng Windows Terminal, terminal của VS Code, hoặc Terminal trên macOS/Linux để hiển thị màu và tiếng Việt |

## 2. Cài đặt

```bash
# 1. Giải nén SourceCode_...zip rồi mở terminal tại thư mục dh-project
cd dh-project

# 2. (Tuỳ chọn) cài thư viện dùng để đối chiếu trong bộ kiểm thử
pip install -r requirements.txt
```

> Trên Windows dùng lệnh `python`. Trên macOS/Linux, nếu `python` không chạy thì dùng `python3`.

## 3. Cách chạy

### 3.1. Menu tương tác (dùng khi thuyết trình)

```bash
python main.py
```

```
1. Ví dụ số nhỏ — in từng bước (khớp ví dụ tính tay)
2. Trao đổi khoá 2048 bít + mã hoá / giải mã tệp
3. Tấn công người đứng giữa (MITM) và cách phòng chống
4. Thử phá DH: giải logarit rời rạc, khoá công khai giả
5. Đo thời gian chạy theo kích thước khoá / dữ liệu
6. Sinh tham số mới (số nguyên tố an toàn q, căn nguyên thuỷ α)
7. Chạy bộ kiểm thử (tự viết + đối chiếu chuẩn)
0. Thoát
```

Giữa các bước, chương trình dừng lại chờ nhấn **Enter** để người trình bày kịp giải thích.

### 3.2. Chạy thẳng một chức năng

| Lệnh | Chức năng |
|---|---|
| `python main.py small --preset 1` | Ví dụ giáo trình: q = 353, α = 3, x_A = 97, x_B = 233 → K = 160 |
| `python main.py small --preset 2` | Ví dụ trong báo cáo: q = 23, α = 5, x_A = 6, x_B = 15 → K = 2 |
| `python main.py small --preset 3` | Tự nhập q, α, x_A, x_B (dùng để chạy **ví dụ của thầy trên lớp**) |
| `python main.py exchange` | Trao đổi khoá + chọn tệp cần mã hoá |
| `python main.py exchange --file data/sample.png` | Mã hoá / giải mã thẳng một tệp với nhóm MODP 2048 bít |
| `python main.py mitm` | Tấn công MITM (Phần A), có xác thực (B), phiên hợp lệ (C) |
| `python main.py attack` | Phá DLP từ 16 đến 40 bít, ngoại suy lên 2048 bít, thử khoá công khai giả |
| `python main.py bench` | Đo thời gian DH theo độ dài q và thời gian mã hoá theo kích thước dữ liệu |
| `python main.py params --bits 128` | Sinh số nguyên tố an toàn q và căn nguyên thuỷ α mới |
| `python main.py test` | Chạy toàn bộ 19 ca kiểm thử |

Tuỳ chọn thêm cho mọi lệnh:

- `--no-pause`: không dừng chờ Enter, dùng khi quay video;
- `--no-color`: tắt màu.

### 3.3. Kết quả sinh ra (thư mục `output/`)

| Tệp | Nội dung |
|---|---|
| `sample.png.dhenc` | Ảnh sau khi mã hoá (không mở xem được) |
| `decrypted_sample.png` | Ảnh Bob giải mã ra (giống hệt ảnh gốc) |
| `test_report.txt` | Kết quả bộ kiểm thử, dùng để dán vào báo cáo |
| `attack_times.csv` | Thời gian phá DLP theo số bít, dùng để vẽ biểu đồ |
| `benchmark_dh.csv`, `benchmark_cipher.csv` | Số liệu đo hiệu năng |

## 4. Cấu trúc mã nguồn

Phần **thuật toán** (`dhcrypto/`) được tách riêng khỏi phần **giao diện** (`app/`, `main.py`).

```
dh-project/
├── main.py                  # điểm khởi chạy: menu + tham số dòng lệnh
├── dhcrypto/                # ===== PHẦN THUẬT TOÁN (tự cài đặt) =====
│   ├── modmath.py           # bình phương và nhân, Euclid mở rộng, nghịch đảo modulo
│   ├── primes.py            # Miller–Rabin, sinh số nguyên tố, số nguyên tố an toàn
│   ├── primitive_root.py    # kiểm tra / tìm căn nguyên thuỷ α
│   ├── groups.py            # bộ số nhỏ + nhóm chuẩn RFC 2409/3526/7919
│   ├── dh.py                # giao thức DH: sinh khoá, kiểm tra khoá công khai, tính K
│   ├── sha256.py            # hàm băm SHA-256 (FIPS 180-4)
│   ├── kdf.py               # HMAC-SHA256, HKDF: biến K thành khoá mã hoá + khoá MAC
│   ├── chacha20.py          # mã dòng ChaCha20 (RFC 8439) để mã hoá dữ liệu
│   ├── file_cipher.py       # mã hoá / giải mã tệp (ChaCha20 + HMAC)
│   ├── rsa_sign.py          # chữ ký RSA để xác thực khoá công khai DH (chống MITM)
│   ├── attacks.py           # vét cạn, Baby-step Giant-step (giải logarit rời rạc)
│   └── protocol.py          # mô phỏng phiên Alice – Bob – Mallory
├── app/                     # ===== PHẦN GIAO DIỆN =====
│   ├── ui.py                # màu, bảng, nhập liệu
│   └── demos.py             # các chức năng demo trong menu
├── tests/
│   └── run_tests.py         # 19 ca kiểm thử: tự viết + đối chiếu chuẩn
├── data/                    # sample.png, sample.txt: dữ liệu mẫu để mã hoá
└── tools/
    ├── derive_rfc_groups.py # tính lại các số nguyên tố RFC từ công thức (cần mpmath)
    └── make_sample_image.py # tạo ảnh mẫu data/sample.png
```

## 5. Luồng xử lý chính

```
Tham số công khai (q, α)
   Alice: chọn x_A → y_A = α^x_A mod q ──── y_A ───▶ Bob
   Bob:   chọn x_B → y_B = α^x_B mod q ◀─── y_B ──── Alice
   Kiểm tra khoá nhận được: 1 < y < q − 1 và y^r ≡ 1 (mod q)
   Alice: K = y_B^x_A mod q          Bob: K = y_A^x_B mod q        (K giống nhau)
   K ──HKDF-SHA256──▶ (khoá mã hoá 256 bít, khoá MAC 256 bít)
   Alice: bản mã = ChaCha20(tệp), tag = HMAC(bản mã) ──▶ Bob kiểm tra tag, giải mã
```

**Chống MITM (chế độ có xác thực):**

1. Mỗi bên có cặp khoá RSA dài hạn và biết trước khoá công khai RSA của nhau, giống chứng chỉ trong TLS.
2. Khi gửi y, mỗi bên ký số lên y.
3. Mallory không có khoá riêng RSA của Alice nên không ký giả được, và bị phát hiện.

## 6. Phần tự viết và phần dùng thư viện

| Thành phần | Tự viết | Thư viện dùng (và lý do) |
|---|---|---|
| Lũy thừa modulo, Miller–Rabin, sinh số nguyên tố, căn nguyên thuỷ, DH | ✔ | — |
| SHA-256, HMAC, HKDF, ChaCha20, chữ ký RSA | ✔ | — |
| Số ngẫu nhiên | — | `secrets` (thư viện chuẩn, sinh số ngẫu nhiên an toàn) |
| Đối chiếu kết quả **trong bộ kiểm thử** | — | `pow`, `hashlib`, `hmac`, `cryptography`, OpenSSL |
| Hằng số nhóm RFC | ✔ tính lại từ công thức trong RFC | `mpmath` (chỉ trong `tools/`, để tính số π, e đủ chính xác) |

## 7. Bộ kiểm thử (`python main.py test`)

| Mã | Loại | Nội dung |
|---|---|---|
| TC01–TC02 | Tự viết | Ví dụ tính tay: (353, 3, 97, 233) → K = 160; (23, 5, 6, 15) → K = 2 |
| TC03–TC04 | Tự viết | K_A = K_B trên 300 bộ số nhỏ và 20 cặp khoá 2048 bít |
| TC05 | Tự viết | Từ chối khoá công khai xấu: 0, 1, q − 1, ≥ q, ngoài nhóm con |
| TC06 | Tự viết | Kiểm tra căn nguyên thuỷ khớp định nghĩa |
| TC07–TC08 | Tự viết | Mã hoá / giải mã tệp đúng; phát hiện dữ liệu bị sửa hoặc sai khoá |
| TC09–TC11 | Tự viết | Chữ ký RSA; MITM thành công khi không xác thực, bị chặn khi có xác thực |
| TC12 | Tự viết | Vét cạn và BSGS giải đúng logarit rời rạc |
| TC13–TC14 | Đối chiếu | `mod_pow` so với `pow()`; Miller–Rabin so với chia thử, số Carmichael |
| TC15 | Đối chiếu | Nhóm RFC 3526/7919 trùng với OpenSSL |
| TC16 | Đối chiếu | y_A và K trùng với thư viện `cryptography` |
| TC17–TC19 | Đối chiếu | SHA-256 (FIPS 180-4), HMAC (RFC 4231), HKDF (RFC 5869), ChaCha20 (RFC 8439) |

Nếu máy chưa cài `cryptography`, ca TC16 hiện **BỎ QUA**; các ca khác vẫn chạy.

## 8. Xử lý sự cố

- **Lỗi font hoặc ký tự lạ trên Windows:** dùng Windows Terminal hoặc terminal của VS Code. Có thể chạy `chcp 65001` trước khi chạy chương trình.
- **Màu hiển thị thành ký tự `[31m`:** thêm `--no-color`.
- **Chương trình dừng chờ Enter:** đây là chủ ý, để thuyết trình. Thêm `--no-pause` để chạy liền.

## 9. Ghi chú

- Đây là chương trình phục vụ học tập. Chữ ký RSA dùng cách đệm rút gọn, chưa đạt chuẩn RSA-PSS. Hệ thống thật nên dùng thư viện mật mã đã được kiểm định.
- Nhóm đã dùng công cụ AI (Claude) hỗ trợ viết mã nguồn. Nội dung cụ thể được khai báo trong phụ lục của báo cáo.
