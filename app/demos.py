"""
demos.py — Các chức năng demo của chương trình (phần GIAO DIỆN).

Mọi phép tính mật mã đều gọi sang thư viện dhcrypto/ do nhóm tự viết.
"""
import csv
import math
import os
import time

from dhcrypto import groups as G
from dhcrypto.attacks import brute_force_dlog, bsgs_dlog, make_dlp_instance
from dhcrypto.dh import (InvalidPublicKey, compute_shared_secret,
                         generate_keypair, validate_public_key)
from dhcrypto.file_cipher import encrypt_bytes
from dhcrypto.kdf import derive_session_keys
from dhcrypto.modmath import mod_pow, mod_pow_trace
from dhcrypto.primes import gen_safe_prime, is_probable_prime
from dhcrypto.primitive_root import (check_primitive_root, find_primitive_root,
                                     power_table, prime_factors)
from dhcrypto.protocol import run_session
from dhcrypto.sha256 import sha256_hex

from . import ui
from .ui import c

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(ROOT, "data")
OUT_DIR = os.path.join(ROOT, "output")


def _ensure_out():
    os.makedirs(OUT_DIR, exist_ok=True)


# ===========================================================================
# 1. Ví dụ số nhỏ, in từng bước
# ===========================================================================
def _print_trace(base, exp, mod, label):
    """In bảng thuật toán bình phương và nhân cho base^exp mod mod."""
    result, steps = mod_pow_trace(base, exp, mod)
    ui.info(f"{label}: tính {base}^{exp} mod {mod}   (số mũ {exp} = {bin(exp)[2:]} ở hệ nhị phân)")
    rows = []
    for s in steps:
        rows.append([s["i"], s["bit"], f"{base}^{2 ** s['i']} ≡ {s['power']}",
                     "nhân vào" if s["used"] else "bỏ qua", s["result"]])
    ui.table(["i", "bít", f"{base}^(2^i) mod {mod}", "thao tác", "kết quả tích luỹ"], rows,
             [">", ">", "<", "<", ">"])
    used = [f"{base}^{2 ** s['i']}" for s in steps if s["used"]]
    ui.info(f"⇒ {base}^{exp} = " + " · ".join(used) + f" ≡ {c(result, 'bold')} (mod {mod})")
    return result


def _ask_small_params():
    while True:
        q = ui.ask_int("Nhập số nguyên tố q (nên < 100000 để in từng bước)", 353, 5)
        if is_probable_prime(q):
            break
        ui.fail(f"{q} không phải số nguyên tố.")
    while True:
        alpha = ui.ask_int("Nhập α", find_primitive_root(q), 2, q - 1)
        if check_primitive_root(alpha, q)[0]:
            break
        ui.fail(f"{alpha} không phải căn nguyên thuỷ modulo {q}. "
                f"Gợi ý: căn nguyên thuỷ nhỏ nhất là {find_primitive_root(q)}.")
    xa = ui.ask_int("Nhập khoá riêng x_A", None, 2, q - 2)
    xb = ui.ask_int("Nhập khoá riêng x_B", None, 2, q - 2)
    return G.DHGroup("Tham số tự nhập", q, alpha, sample_xA=xa, sample_xB=xb)


def demo_small(preset: int = None):
    ui.title("1. VÍ DỤ SỐ NHỎ — CHẠY TỪNG BƯỚC (khớp ví dụ tính tay)")
    if preset is None:
        preset = ui.choose("Chọn bộ số", [
            "Ví dụ giáo trình Stallings: q = 353, α = 3, x_A = 97, x_B = 233",
            "Ví dụ trong báo cáo: q = 23, α = 5, x_A = 6, x_B = 15",
            "Tự nhập q, α, x_A, x_B (ví dụ của thầy trên lớp)",
        ])
    grp = {1: G.TEXTBOOK, 2: G.SMALL_23}.get(preset) or _ask_small_params()
    q, alpha, xa, xb = grp.q, grp.alpha, grp.sample_xA, grp.sample_xB

    # --- Bước 1 ---------------------------------------------------------
    ui.section("Bước 1. Thoả thuận tham số công khai q và α")
    ui.info(f"q = {q}  →  Miller–Rabin: " + (c("số nguyên tố", "green") if is_probable_prime(q) else c("hợp số", "red")))
    factors = prime_factors(q - 1)
    ui.info(f"q − 1 = {q - 1} có các ước nguyên tố: {', '.join(map(str, factors))}")
    is_root, steps = check_primitive_root(alpha, q, factors)
    ui.info(f"Kiểm tra α = {alpha} là căn nguyên thuỷ: cần α^((q−1)/f) ≠ 1 với mọi ước nguyên tố f")
    ui.table(["f", "(q−1)/f", f"{alpha}^((q−1)/f) mod {q}", "kết luận"],
             [[f, e, v, "≠ 1 ✔" if v != 1 else "= 1 ✘"] for f, e, v in steps], [">", ">", ">", "<"])
    (ui.ok if is_root else ui.fail)(f"α = {alpha} {'LÀ' if is_root else 'KHÔNG phải'} căn nguyên thuỷ modulo {q}")
    if q <= 60:
        tbl = power_table(alpha, q)
        ui.info(f"Bảng {alpha}^k mod {q} (đi qua đủ các số 1..{q - 1}, thứ tự 'lộn xộn'):")
        ui.table(["k"] + [str(k) for k, _ in tbl], [[f"{alpha}^k"] + [str(v) for _, v in tbl]])
    ui.pause()

    # --- Bước 2, 3 ------------------------------------------------------
    ui.section("Bước 2. Alice chọn khoá riêng x_A và tính khoá công khai y_A = α^x_A mod q")
    ui.info(f"{ui.actor('Alice')} chọn bí mật x_A = {c(xa, 'bold')}")
    ya = _print_trace(alpha, xa, q, "y_A")
    ui.pause()
    ui.section("Bước 3. Bob chọn khoá riêng x_B và tính khoá công khai y_B = α^x_B mod q")
    ui.info(f"{ui.actor('Bob')} chọn bí mật x_B = {c(xb, 'bold')}")
    yb = _print_trace(alpha, xb, q, "y_B")
    ui.pause()

    # --- Bước 4 ---------------------------------------------------------
    ui.section("Bước 4. Trao đổi khoá công khai qua kênh không an toàn")
    ui.info(f"{ui.actor('Alice')} ──── y_A = {ya} ───▶ {ui.actor('Bob')}")
    ui.info(f"{ui.actor('Alice')} ◀─── y_B = {yb} ──── {ui.actor('Bob')}")
    ui.info(f"{ui.actor('Eve')} nghe lén biết: q = {q}, α = {alpha}, y_A = {ya}, y_B = {yb}  (KHÔNG biết x_A, x_B)")
    ui.pause()

    # --- Bước 5 ---------------------------------------------------------
    ui.section("Bước 5. Mỗi bên tự tính khoá chung K_AB")
    ka = _print_trace(yb, xa, q, f"{ui.actor('Alice')} K = y_B^x_A mod q")
    print()
    kb = _print_trace(ya, xb, q, f"{ui.actor('Bob')} K = y_A^x_B mod q")
    direct = mod_pow(alpha, xa * xb, q)
    ui.info(f"Kiểm chứng: α^(x_A·x_B) mod q = {alpha}^{xa * xb} mod {q} = {direct}")
    (ui.ok if ka == kb == direct else ui.fail)(
        f"Alice và Bob có CÙNG khoá K_AB = {c(ka, 'bold', 'green')}" if ka == kb else "Hai khoá KHÁC nhau!")
    ui.pause()

    # --- Bước 6 ---------------------------------------------------------
    ui.section("Bước 6. Eve thử tìm x_A bằng cách giải logarit rời rạc (vét cạn)")
    t0 = time.perf_counter()
    x_found, n_steps = brute_force_dlog(alpha, ya, q)
    dt = time.perf_counter() - t0
    ui.info(f"{ui.actor('Eve')} thử x = 1, 2, 3, … đến khi {alpha}^x ≡ {ya} (mod {q}): "
            f"tìm được x = {x_found} sau {n_steps} lần thử ({dt * 1000:.2f} ms)")
    ui.info(f"{ui.actor('Eve')} tính được K = y_B^x mod q = {mod_pow(yb, x_found, q)}")
    ui.note(f"Với q nhỏ ({q.bit_length()} bít) việc này tức thì. Với q 2048 bít, số lần thử ~ 2^2047 → bất khả thi.")

    ui.section("Tổng kết")
    ui.table(["Đại lượng", "Giá trị", "Ai biết"], [
        ["q, α", f"{q}, {alpha}", "Công khai"],
        ["x_A", xa, "Chỉ Alice"],
        ["x_B", xb, "Chỉ Bob"],
        ["y_A = α^x_A mod q", ya, "Công khai"],
        ["y_B = α^x_B mod q", yb, "Công khai"],
        ["K_AB", ka, "Alice và Bob"],
    ])
    return {"q": q, "alpha": alpha, "xA": xa, "xB": xb, "yA": ya, "yB": yb, "K": ka}


# ===========================================================================
# In sự kiện của phiên trao đổi khoá
# ===========================================================================
def print_event(e):
    style = {"secret": ("dim",), "attack": ("red",), "ok": ("green",), "fail": ("red", "bold"),
             "send": ("bold",)}.get(e.kind, ())
    mark = {"ok": "✔ ", "fail": "✘ ", "secret": "🔒 ", "attack": "⚠ "}.get(e.kind, "")
    print(f"  {ui.actor(e.actor):<20} {c(mark + e.text, *style)}")
    d = e.data
    pad = " " * 13
    if "x" in d:
        print(pad + c(f"x = {ui.short_int(d['x'])}", "dim"))
    if "y" in d:
        print(pad + f"y = {ui.short_int(d['y'])}")
    if "k" in d:
        print(pad + f"K = {ui.short_int(d['k'])}   mã xác nhận: {c(d.get('sas', ''), 'bold')}")
    if "k1" in d:
        print(pad + c(f"K₁ (với Alice) = {ui.short_int(d['k1'])}", "red"))
        print(pad + c(f"K₂ (với Bob)   = {ui.short_int(d['k2'])}", "red"))
    if "cipher_preview" in d:
        print(pad + f"bản mã (24 byte đầu, hex): {d['cipher_preview']}…  tổng {d['size']:,} byte")
    if "plain_preview" in d:
        txt = d["plain_preview"].decode("utf-8", errors="replace")
        if any(ch in txt for ch in "\x00\x89") or "PNG" in txt[:5]:
            txt = f"<dữ liệu nhị phân, bắt đầu bằng {d['plain_preview'][:8].hex()}>"
        print(pad + c(f"Mallory đọc được: \"{txt}\"", "red", "bold"))


def _choose_group(default_idx=4):
    labels = [f"{g.name:<16} — {g.source}" for g in G.RFC_GROUPS]
    labels.append("Ví dụ giáo trình q = 353 (số nhỏ, chỉ để minh hoạ)")
    i = ui.choose("Chọn nhóm tham số", labels, default_idx)
    return G.RFC_GROUPS[i - 1] if i <= len(G.RFC_GROUPS) else G.TEXTBOOK


def _choose_data():
    i = ui.choose("Chọn dữ liệu cần gửi", [
        "Ảnh mẫu data/sample.png",
        "Văn bản mẫu data/sample.txt",
        "Nhập đường dẫn một tệp bất kỳ",
        "Gõ trực tiếp một tin nhắn",
    ], 1)
    if i == 1:
        path = os.path.join(DATA_DIR, "sample.png")
    elif i == 2:
        path = os.path.join(DATA_DIR, "sample.txt")
    elif i == 3:
        path = ui.ask("Đường dẫn tệp").strip('"')
    else:
        text = ui.ask("Tin nhắn", "Xin chào Bob, đây là thông điệp bí mật của Alice.")
        return text.encode("utf-8"), "message.txt"
    with open(path, "rb") as f:
        return f.read(), os.path.basename(path)


# ===========================================================================
# 2. Trao đổi khoá thật (2048 bít) + mã hoá / giải mã tệp
# ===========================================================================
def demo_exchange(group=None, data=None, filename=None):
    ui.title("2. TRAO ĐỔI KHOÁ + MÃ HOÁ / GIẢI MÃ TỆP")
    group = group or _choose_group()
    if data is None:
        data, filename = _choose_data()
    _ensure_out()

    ui.section("Phiên trao đổi khoá và truyền dữ liệu")
    t0 = time.perf_counter()
    res = run_session(group, data, filename, emit=print_event)
    dt = time.perf_counter() - t0
    if not res.ok:
        ui.fail(res.error)
        return res

    enc_path = os.path.join(OUT_DIR, filename + ".dhenc")
    dec_path = os.path.join(OUT_DIR, "decrypted_" + res.received_name)
    with open(enc_path, "wb") as f:
        f.write(res.blob)
    with open(dec_path, "wb") as f:
        f.write(res.received)

    ui.section("Kiểm tra kết quả")
    h1, h2 = sha256_hex(data), sha256_hex(res.received)
    ui.table(["", "Giá trị"], [
        ["K_AB của Alice == K_AB của Bob", "ĐÚNG" if res.alice.shared == res.bob.shared else "SAI"],
        ["Mã xác nhận Alice / Bob", f"{res.alice.sas} / {res.bob.sas}"],
        ["Tệp đã mã hoá", os.path.relpath(enc_path, ROOT)],
        ["Tệp Bob giải mã ra", os.path.relpath(dec_path, ROOT)],
        ["SHA-256 tệp gốc", h1[:32] + "…"],
        ["SHA-256 tệp giải mã", h2[:32] + "…"],
        ["Tổng thời gian", f"{dt:.3f} giây"],
    ])
    (ui.ok if h1 == h2 else ui.fail)("Giải mã khôi phục ĐÚNG bản rõ ban đầu" if h1 == h2 else "Bản giải mã KHÁC bản gốc!")
    ui.note("Thử mở tệp .dhenc bằng trình xem ảnh/văn bản: không đọc được vì đã bị mã hoá.")
    return res


# ===========================================================================
# 3. Tấn công người đứng giữa và cách phòng chống
# ===========================================================================
DEFAULT_TRANSFER = "Bob ơi, chuyển giúp mình 5.000.000đ vào tài khoản 0123456789 nhé. — Alice"


def _tamper(plain: bytes) -> bytes:
    return plain.replace("0123456789".encode(), "9876543210".encode())


def demo_mitm(group=None, message=None, interactive=True):
    ui.title("3. TẤN CÔNG NGƯỜI ĐỨNG GIỮA (MITM) VÀ CÁCH PHÒNG CHỐNG")
    group = group or G.MODP_2048
    message = (message or DEFAULT_TRANSFER).encode("utf-8")

    ui.section("Phần A — DH gốc (không xác thực), Mallory chen vào giữa")
    res = run_session(group, message, "tin_nhan.txt", mitm=True, auth=False, tamper=_tamper, emit=print_event)
    print()
    ui.table(["", "Nội dung"], [
        ["Alice gửi", message.decode()],
        ["Mallory đọc trộm", res.mallory.stolen[0][2].decode()],
        ["Bob nhận được", res.received.decode()],
    ])
    ui.fail("Bob nhận tin ĐÃ BỊ SỬA số tài khoản mà không hề biết (HMAC vẫn đúng vì Mallory có khoá K₂).")
    ui.info("Cách nhận biết thủ công: hai bên gọi điện đọc MÃ XÁC NHẬN (băm của khoá chung) cho nhau:")
    ui.table(["Bên", "Mã xác nhận"], [["Alice (khoá K₁)", res.alice.sas], ["Bob (khoá K₂)", res.bob.sas]])
    ui.fail("Hai mã KHÁC nhau → có người đứng giữa!")
    if interactive:
        ui.pause()

    ui.section("Phần B — DH có xác thực: mỗi bên KÝ SỐ (RSA) lên khoá công khai của mình")
    res2 = run_session(group, message, "tin_nhan.txt", mitm=True, auth=True, tamper=_tamper, emit=print_event)
    if not res2.ok:
        ui.ok("Mallory không có khoá riêng RSA của Alice nên không ký giả được M → tấn công bị CHẶN.")
    if interactive:
        ui.pause()

    ui.section("Phần C — DH có xác thực, KHÔNG có Mallory (phiên hợp lệ)")
    res3 = run_session(group, message, "tin_nhan.txt", mitm=False, auth=True, emit=print_event)
    if res3.ok:
        ui.ok(f"Bob nhận đúng: \"{res3.received.decode()}\"")
    return res, res2, res3


# ===========================================================================
# 4. Phá bài toán logarit rời rạc + khoá công khai giả
# ===========================================================================
def demo_attack(bit_list=(16, 20, 24, 28, 32, 36, 40), brute_limit_bits=24):
    ui.title("4. THỬ PHÁ DIFFIE–HELLMAN: GIẢI LOGARIT RỜI RẠC")
    ui.info("Tạo bài toán: q là số nguyên tố an toàn n bít, α căn nguyên thuỷ, y = α^x mod q. Tìm x.")
    rows, csv_rows = [], []
    last = None
    for bits in bit_list:
        q, alpha, x, y = make_dlp_instance(bits)
        if bits <= brute_limit_bits:
            t0 = time.perf_counter()
            xb, nb = brute_force_dlog(alpha, y, q)
            tb = time.perf_counter() - t0
            brute = f"{nb:,} bước / {tb:.3f}s"
        else:
            xb, tb, brute = None, None, "bỏ qua (quá lâu)"
        t0 = time.perf_counter()
        xs, ns = bsgs_dlog(alpha, y, q)
        ts = time.perf_counter() - t0
        correct = mod_pow(alpha, xs, q) == y
        rows.append([bits, q, x, xs, "✔" if correct else "✘", brute, f"{ns:,} bước / {ts:.3f}s"])
        csv_rows.append([bits, q, x, xs, tb if tb is not None else "", ts])
        last = (bits, ts)
        print(f"    … xong {bits} bít", flush=True)
    ui.table(["bít", "q", "x bí mật", "x tìm được", "đúng?", "Vét cạn", "Baby-step Giant-step"],
             rows, [">", ">", ">", ">", "^", ">", ">"])

    # Ngoại suy: BSGS tốn ~ 2^(n/2) bước
    bits0, t_last = last
    per_step = t_last / (2 ** (bits0 / 2))
    ui.section("Ngoại suy thời gian Baby-step Giant-step cho q lớn")
    est = []
    for n in (64, 128, 256, 1024, 2048):
        seconds_log10 = math.log10(per_step) + (n / 2) * math.log10(2)
        years_log10 = seconds_log10 - math.log10(3600 * 24 * 365)
        est.append([n, f"≈ 2^{n // 2} bước", f"≈ 10^{years_log10:.0f} năm" if years_log10 > 0 else f"≈ {10 ** seconds_log10:.1f} giây"])
    ui.table(["bít của q", "số bước", "thời gian (máy này)"], est, [">", ">", ">"])
    ui.note("Thuật toán tốt nhất hiện nay (Number Field Sieve) nhanh hơn BSGS nhiều, nhưng với q 2048 bít")
    ui.note("vẫn có độ an toàn tương đương 112 bít (NIST SP 800-57), tức cỡ 2^112 phép tính → ngoài tầm với.")
    _ensure_out()
    path = os.path.join(OUT_DIR, "attack_times.csv")
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["bits", "q", "x", "x_found", "brute_seconds", "bsgs_seconds"])
        w.writerows(csv_rows)
    ui.ok(f"Đã lưu số liệu vào {os.path.relpath(path, ROOT)} (dùng vẽ biểu đồ trong báo cáo)")

    # Khoá công khai giả
    ui.section("Tấn công khoá công khai giả (y = 1, y = q − 1) và cách kiểm tra")
    grp = G.MODP_2048
    victim = generate_keypair(grp)
    rows = []
    for label, fake in [("y = 1", 1), ("y = q − 1", grp.q - 1), ("y = 0", 0)]:
        k_no_check = mod_pow(fake, victim.private, grp.q)
        try:
            validate_public_key(grp, fake)
            verdict = "chấp nhận"
        except InvalidPublicKey:
            verdict = c("TỪ CHỐI", "green", "bold")
        rows.append([label, ui.short_int(k_no_check, 6), verdict])
    ui.table(["Khoá giả", "K nếu KHÔNG kiểm tra", "Có kiểm tra"], rows)
    ui.note("Không kiểm tra: K chỉ có thể là 0, 1 hoặc q − 1 → kẻ tấn công đoán ngay được khoá.")


# ===========================================================================
# 5. Đo hiệu năng
# ===========================================================================
def demo_benchmark(runs=5, sizes=(1_000, 10_000, 100_000, 500_000)):
    ui.title("5. ĐO THỜI GIAN CHẠY")
    _ensure_out()
    ui.section("Thời gian Diffie–Hellman theo độ dài q (trung bình %d lần)" % runs)
    rows, csv_rows = [], []
    for grp in [G.MODP_768, G.MODP_1024, G.MODP_1536, G.MODP_2048, G.MODP_3072]:
        t_gen = t_shared = t_builtin = 0.0
        for _ in range(runs):
            t0 = time.perf_counter()
            a = generate_keypair(grp)
            b = generate_keypair(grp)
            t1 = time.perf_counter()
            k1 = compute_shared_secret(grp, a.private, b.public, validate=False)
            t2 = time.perf_counter()
            k2 = pow(a.public, b.private, grp.q)        # hàm có sẵn — CHỈ để so sánh
            t3 = time.perf_counter()
            assert k1 == k2
            t_gen += (t1 - t0) / 2
            t_shared += t2 - t1
            t_builtin += t3 - t2
        r = [grp.bits, t_gen / runs * 1000, t_shared / runs * 1000, t_builtin / runs * 1000]
        rows.append([r[0], f"{r[1]:.2f}", f"{r[2]:.2f}", f"{r[3]:.2f}"])
        csv_rows.append(r)
        print(f"    … xong {grp.bits} bít", flush=True)
    ui.table(["bít của q", "sinh cặp khoá (ms)", "tính K (ms)", "pow() có sẵn (ms)"], rows, [">"] * 4)
    with open(os.path.join(OUT_DIR, "benchmark_dh.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["bits", "keygen_ms", "shared_ms", "builtin_pow_ms"])
        w.writerows(csv_rows)

    ui.section("Thời gian mã hoá / giải mã dữ liệu theo kích thước (ChaCha20 + HMAC tự viết)")
    k_enc, k_mac = derive_session_keys(b"benchmark-key")
    from dhcrypto.file_cipher import decrypt_bytes
    rows, csv_rows = [], []
    for n in sizes:
        data = os.urandom(n)
        t0 = time.perf_counter()
        blob = encrypt_bytes(k_enc, k_mac, data)
        t1 = time.perf_counter()
        _, back = decrypt_bytes(k_enc, k_mac, blob)
        t2 = time.perf_counter()
        assert back == data
        rows.append([f"{n:,}", f"{(t1 - t0) * 1000:.1f}", f"{(t2 - t1) * 1000:.1f}", f"{n / (t1 - t0) / 1e6:.2f}"])
        csv_rows.append([n, t1 - t0, t2 - t1])
    ui.table(["kích thước (byte)", "mã hoá (ms)", "giải mã (ms)", "tốc độ (MB/s)"], rows, [">"] * 4)
    with open(os.path.join(OUT_DIR, "benchmark_cipher.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["bytes", "encrypt_seconds", "decrypt_seconds"])
        w.writerows(csv_rows)
    ui.ok("Đã lưu output/benchmark_dh.csv và output/benchmark_cipher.csv")
    ui.note("Nhận xét: thời gian DH tăng nhanh theo độ dài q (khoảng bậc 3); phần mã hoá dữ liệu")
    ui.note("tỉ lệ tuyến tính với kích thước. Bản tự viết bằng Python chậm hơn thư viện viết bằng C.")


# ===========================================================================
# 6. Sinh tham số mới
# ===========================================================================
def demo_params(bits=None):
    ui.title("6. SINH THAM SỐ MỚI: SỐ NGUYÊN TỐ AN TOÀN q VÀ CĂN NGUYÊN THUỶ α")
    if bits is None:
        bits = ui.ask_int("Số bít của q (16–512; trên 256 có thể mất vài chục giây)", 64, 16, 1024)
    ui.info(f"Đang tìm số nguyên tố an toàn q = 2r + 1 dài {bits} bít (r cũng nguyên tố)…")
    counter = {"n": 0}

    def progress(n):
        counter["n"] = n
        if n % 200 == 0:
            print(".", end="", flush=True)

    t0 = time.perf_counter()
    q = gen_safe_prime(bits, progress)
    dt = time.perf_counter() - t0
    print()
    r = (q - 1) // 2
    ui.ok(f"Tìm được sau {counter['n']:,} lần thử, {dt:.2f} giây")
    ui.info(f"q = {q}")
    ui.info(f"r = (q − 1)/2 = {r}")
    alpha = find_primitive_root(q, [2, r])
    _, steps = check_primitive_root(alpha, q, [2, r])
    ui.info(f"q − 1 = 2·r nên chỉ cần kiểm tra 2 ước nguyên tố. Căn nguyên thuỷ nhỏ nhất α = {alpha}:")
    ui.table(["f", f"α^((q−1)/f) mod q", "kết luận"],
             [[ui.short_int(f), ui.short_int(v), "≠ 1 ✔" if v != 1 else "= 1 ✘"] for f, _, v in steps])
    grp = G.DHGroup(f"Tự sinh {bits} bít", q, alpha)
    a, b = generate_keypair(grp), generate_keypair(grp)
    ka = compute_shared_secret(grp, a.private, b.public)
    kb = compute_shared_secret(grp, b.private, a.public)
    ui.info(f"Thử trao đổi khoá: K_Alice = {ui.short_int(ka)}")
    ui.info(f"                   K_Bob   = {ui.short_int(kb)}")
    (ui.ok if ka == kb else ui.fail)("Hai khoá trùng nhau" if ka == kb else "Hai khoá khác nhau!")
    return grp
