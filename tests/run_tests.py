"""
run_tests.py — Bộ kiểm thử của nhóm.

Gồm hai loại:
  * TỰ VIẾT  : ca kiểm thử do nhóm tự thiết kế (ví dụ tính tay, tính chất, ca lỗi…)
  * ĐỐI CHIẾU: so với test vector chuẩn (FIPS 180-4, RFC 4231, RFC 5869, RFC 8439,
               RFC 3526/7919) hoặc với thư viện chuẩn (hashlib, hmac, cryptography,
               OpenSSL). Thư viện chuẩn CHỈ được dùng ở đây để đối chiếu.

Chạy:  python -m tests.run_tests      hoặc     python main.py test
Kết quả được in ra màn hình và lưu vào output/test_report.txt
"""
import hashlib
import hmac as std_hmac
import os
import random
import secrets
import shutil
import subprocess
import sys
import time
import warnings

# Thư viện cryptography cảnh báo FFDH "deprecated" — chỉ dùng để đối chiếu nên ẩn cảnh báo
warnings.filterwarnings("ignore", message=".*Diffie-Hellman over finite fields.*")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from dhcrypto import groups as G                                     # noqa: E402
from dhcrypto.attacks import brute_force_dlog, bsgs_dlog, make_dlp_instance  # noqa: E402
from dhcrypto.chacha20 import chacha20_block, chacha20_xor           # noqa: E402
from dhcrypto.dh import (InvalidPublicKey, compute_shared_secret,     # noqa: E402
                         generate_keypair, shared_secret_bytes, validate_public_key)
from dhcrypto.file_cipher import IntegrityError, decrypt_bytes, encrypt_bytes  # noqa: E402
from dhcrypto.kdf import derive_session_keys, hkdf, hmac_sha256      # noqa: E402
from dhcrypto.modmath import mod_inverse, mod_pow                     # noqa: E402
from dhcrypto.primes import is_probable_prime, miller_rabin           # noqa: E402
from dhcrypto.primitive_root import is_primitive_root, power_table    # noqa: E402
from dhcrypto.protocol import run_session                             # noqa: E402
from dhcrypto.rsa_sign import generate_rsa_keypair, sign, verify      # noqa: E402
from dhcrypto.sha256 import sha256_hex                                # noqa: E402

from app import ui                                                    # noqa: E402


class Skip(Exception):
    """Ca kiểm thử bị bỏ qua (ví dụ máy không có OpenSSL)."""


TESTS = []


def _import(module_name, names):
    """Nhập thư viện dùng để đối chiếu; nếu máy không có (hoặc cài hỏng) thì trả về None."""
    try:
        mod = __import__(module_name, fromlist=names)
        return [getattr(mod, n) for n in names]
    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException:          # gồm cả lỗi "panic" của bản cryptography cài hỏng
        return None


def case(code, kind, desc):
    def deco(fn):
        TESTS.append((code, kind, desc, fn))
        return fn
    return deco


def check(cond, msg="sai kết quả"):
    if not cond:
        raise AssertionError(msg)


# ===========================================================================
# CA TỰ VIẾT
# ===========================================================================
@case("TC01", "Tự viết", "Ví dụ giáo trình q=353, α=3, x_A=97, x_B=233 → y_A=40, y_B=248, K=160")
def tc01():
    g = G.TEXTBOOK
    a, b = generate_keypair(g, 97), generate_keypair(g, 233)
    check(a.public == 40 and b.public == 248, f"y_A={a.public}, y_B={b.public}")
    ka = compute_shared_secret(g, a.private, b.public)
    kb = compute_shared_secret(g, b.private, a.public)
    check(ka == kb == 160, f"K_A={ka}, K_B={kb}")
    return "y_A=40, y_B=248, K=160 (khớp tính tay)"


@case("TC02", "Tự viết", "Ví dụ trong báo cáo q=23, α=5, x_A=6, x_B=15 → y_A=8, y_B=19, K=2")
def tc02():
    g = G.SMALL_23
    a, b = generate_keypair(g, 6), generate_keypair(g, 15)
    check((a.public, b.public) == (8, 19))
    check(compute_shared_secret(g, a.private, b.public) == compute_shared_secret(g, b.private, a.public) == 2)
    return "y_A=8, y_B=19, K=2 (khớp tính tay)"


@case("TC03", "Tự viết", "Tính chất K_A = K_B = α^(x_A·x_B) mod q trên 300 bộ số nhỏ ngẫu nhiên")
def tc03():
    rng = random.Random(2026)
    primes = [p for p in range(50, 5000) if is_probable_prime(p)]
    for _ in range(300):
        q = rng.choice(primes)
        alpha = next(a for a in range(2, q) if is_primitive_root(a, q))
        g = G.DHGroup("tmp", q, alpha)
        xa, xb = rng.randrange(2, q - 1), rng.randrange(2, q - 1)
        a, b = generate_keypair(g, xa), generate_keypair(g, xb)
        ka = compute_shared_secret(g, xa, b.public, validate=False)
        kb = compute_shared_secret(g, xb, a.public, validate=False)
        check(ka == kb == mod_pow(alpha, xa * xb, q), f"q={q}, x_A={xa}, x_B={xb}")
    return "300/300 bộ đúng"


@case("TC04", "Tự viết", "20 cặp khoá ngẫu nhiên trên nhóm MODP 2048 bít: hai bên ra cùng K")
def tc04():
    g = G.MODP_2048
    for _ in range(20):
        a, b = generate_keypair(g), generate_keypair(g)
        check(compute_shared_secret(g, a.private, b.public) == compute_shared_secret(g, b.private, a.public))
    return "20/20 cặp khớp"


@case("TC05", "Tự viết", "Khoá công khai không hợp lệ (0, 1, q−1, ≥ q, ngoài nhóm con) bị từ chối")
def tc05():
    g = G.MODP_2048
    non_member = next(y for y in range(3, 100) if mod_pow(y, g.order, g.q) != 1)
    bad = {"0": 0, "1": 1, "q−1": g.q - 1, "q": g.q, "q+5": g.q + 5, f"{non_member} (ngoài nhóm con)": non_member}
    for name, y in bad.items():
        try:
            validate_public_key(g, y)
        except InvalidPublicKey:
            continue
        raise AssertionError(f"không từ chối y = {name}")
    validate_public_key(g, generate_keypair(g).public)        # khoá hợp lệ phải được chấp nhận
    return f"từ chối {len(bad)}/{len(bad)} giá trị xấu, chấp nhận khoá hợp lệ"


@case("TC06", "Tự viết", "Căn nguyên thuỷ: tiêu chuẩn α^((q−1)/f) ≠ 1 khớp định nghĩa (bảng lũy thừa)")
def tc06():
    count = 0
    for q in [7, 11, 13, 23, 29, 37, 53, 101, 353]:
        for alpha in range(2, q):
            by_definition = len({v for _, v in power_table(alpha, q)}) == q - 1
            check(is_primitive_root(alpha, q) == by_definition, f"q={q}, α={alpha}")
            count += 1
    return f"{count} trường hợp khớp"


@case("TC07", "Tự viết", "Mã hoá rồi giải mã tệp văn bản và ảnh bằng khoá DH; SHA-256 trước/sau trùng nhau")
def tc07():
    g = G.MODP_2048
    a, b = generate_keypair(g), generate_keypair(g)
    ka = shared_secret_bytes(g, compute_shared_secret(g, a.private, b.public))
    kb = shared_secret_bytes(g, compute_shared_secret(g, b.private, a.public))
    enc_a, mac_a = derive_session_keys(ka)
    enc_b, mac_b = derive_session_keys(kb)
    for name in ("sample.txt", "sample.png"):
        with open(os.path.join(ROOT, "data", name), "rb") as f:
            data = f.read()
        blob = encrypt_bytes(enc_a, mac_a, data, name)
        check(data not in blob, "bản mã chứa nguyên bản rõ")
        got_name, back = decrypt_bytes(enc_b, mac_b, blob)
        check(got_name == name and sha256_hex(back) == sha256_hex(data), f"{name} giải mã sai")
    return "sample.txt và sample.png khôi phục đúng"


@case("TC08", "Tự viết", "Dữ liệu bị sửa 1 bít hoặc dùng sai khoá → phát hiện (HMAC sai)")
def tc08():
    k_enc, k_mac = derive_session_keys(b"khoa-dung")
    blob = bytearray(encrypt_bytes(k_enc, k_mac, b"Noi dung bi mat", "a.txt"))
    blob[30] ^= 0x01
    try:
        decrypt_bytes(k_enc, k_mac, bytes(blob))
        raise AssertionError("không phát hiện dữ liệu bị sửa")
    except IntegrityError:
        pass
    blob[30] ^= 0x01
    w_enc, w_mac = derive_session_keys(b"khoa-sai")
    try:
        decrypt_bytes(w_enc, w_mac, bytes(blob))
        raise AssertionError("giải mã được bằng khoá sai")
    except IntegrityError:
        pass
    return "phát hiện cả hai trường hợp"


@case("TC09", "Tự viết", "Chữ ký RSA: ký/kiểm tra đúng; sửa thông điệp hoặc chữ ký → kiểm tra thất bại")
def tc09():
    k = generate_rsa_keypair(1024)
    s = sign(k, b"y_A = 12345")
    check(verify(k.public, b"y_A = 12345", s), "chữ ký đúng bị từ chối")
    check(not verify(k.public, b"y_A = 12346", s), "chấp nhận thông điệp bị sửa")
    check(not verify(k.public, b"y_A = 12345", s ^ 1), "chấp nhận chữ ký bị sửa")
    other = generate_rsa_keypair(1024)
    check(not verify(other.public, b"y_A = 12345", s), "chấp nhận chữ ký với khoá khác")
    return "4/4 tình huống đúng"


@case("TC10", "Tự viết", "MITM khi KHÔNG xác thực: Mallory đọc và sửa được tin; mã xác nhận hai bên khác nhau")
def tc10():
    msg = "chuyển vào tài khoản 0123456789".encode()
    r = run_session(G.MODP_2048, msg, mitm=True, auth=False,
                    tamper=lambda p: p.replace(b"0123456789", b"9876543210"))
    check(r.ok and r.mallory.stolen[0][2] == msg, "Mallory không đọc được")
    check(b"9876543210" in r.received, "Mallory không sửa được")
    check(r.alice.sas != r.bob.sas and r.alice.shared != r.bob.shared, "mã xác nhận lẽ ra phải khác")
    return "tấn công thành công như lý thuyết"


@case("TC11", "Tự viết", "MITM khi CÓ xác thực (ký RSA lên khoá DH): phiên bị huỷ, không lộ dữ liệu")
def tc11():
    r = run_session(G.MODP_2048, b"bi mat", mitm=True, auth=True)
    check(not r.ok and "KHÔNG hợp lệ" in r.error, "không phát hiện tấn công")
    check(r.mallory.stolen == [], "dữ liệu vẫn bị lộ")
    r2 = run_session(G.MODP_2048, b"bi mat", mitm=False, auth=True)
    check(r2.ok and r2.received == b"bi mat", "phiên hợp lệ bị từ chối nhầm")
    return "phát hiện MITM; phiên hợp lệ vẫn chạy"


@case("TC12", "Tự viết", "Phá DLP: vét cạn và Baby-step Giant-step giải đúng 20 bài 20 bít, kết quả trùng nhau")
def tc12():
    for _ in range(20):
        q, alpha, x, y = make_dlp_instance(20)
        xb, _ = brute_force_dlog(alpha, y, q)
        xs, _ = bsgs_dlog(alpha, y, q)
        check(xb == xs == x, f"q={q}: x={x}, vét cạn={xb}, BSGS={xs}")
    return "20/20 bài giải đúng"


# ===========================================================================
# ĐỐI CHIẾU VỚI CHUẨN / THƯ VIỆN CHUẨN
# ===========================================================================
@case("TC13", "Đối chiếu", "mod_pow tự viết so với hàm pow() có sẵn trên 1000 bộ ngẫu nhiên (đến 2048 bít)")
def tc13():
    rng = random.Random(1)
    edge = [(5, 0, 7), (0, 5, 7), (5, 3, 1), (2, 10, 1024)]
    for b, e, m in edge:
        check(mod_pow(b, e, m) == pow(b, e, m), f"{b}^{e} mod {m}")
    for i in range(1000):
        bits = 2048 if i % 50 == 0 else rng.choice([8, 32, 64, 256, 512])
        m = rng.getrandbits(bits) | 1
        b, e = rng.getrandbits(bits), rng.getrandbits(bits)
        check(mod_pow(b, e, m) == pow(b, e, m))
    return "1004/1004 khớp"


@case("TC14", "Đối chiếu", "Miller–Rabin so với chia thử (n < 20000), số Carmichael, số nguyên tố Mersenne")
def tc14():
    def trial(n):
        return n > 1 and all(n % d for d in range(2, int(n ** 0.5) + 1))
    for n in range(20000):
        check(miller_rabin(n) == trial(n), f"sai tại n = {n}")
    for n in [561, 1105, 1729, 2465, 2821, 6601, 8911, 41041, 825265, 321197185]:   # Carmichael
        check(not miller_rabin(n), f"nhận nhầm số Carmichael {n}")
    for p in [2 ** 61 - 1, 2 ** 89 - 1, 2 ** 127 - 1, 2 ** 521 - 1]:
        check(miller_rabin(p), "bỏ sót số nguyên tố Mersenne")
    check(not miller_rabin(2 ** 128 + 1), "nhận nhầm F7 = 2^128 + 1")
    inv_ok = all(mod_inverse(a, 10007) == pow(a, -1, 10007) for a in range(1, 2000))
    check(inv_ok, "mod_inverse sai")
    return "đúng toàn bộ (kèm nghịch đảo modulo so với pow(a, -1, m))"


@case("TC15", "Đối chiếu", "Nhóm RFC 2409/3526/7919 tính lại từ công thức: là số nguyên tố an toàn + trùng OpenSSL")
def tc15():
    for g in G.RFC_GROUPS:
        check(miller_rabin(g.q, 5) and miller_rabin(g.order, 5), f"{g.name} không phải số nguyên tố an toàn")
        check(mod_pow(g.alpha, g.order, g.q) == 1, f"{g.name}: α không sinh nhóm con cấp r")
    if not shutil.which("openssl"):
        return "số nguyên tố an toàn ✔ (máy không có OpenSSL nên bỏ qua phần so khớp)"
    imported = _import("cryptography.hazmat.primitives.serialization", ["load_pem_parameters"])
    if imported is None:
        return "số nguyên tố an toàn ✔ (thiếu thư viện cryptography nên bỏ qua phần so khớp)"
    load_pem_parameters, = imported
    matched = []
    for name, g in [("modp_1536", G.MODP_1536), ("modp_2048", G.MODP_2048),
                    ("modp_3072", G.MODP_3072), ("ffdhe2048", G.FFDHE_2048)]:
        out = subprocess.run(["openssl", "genpkey", "-genparam", "-algorithm", "DH",
                              "-pkeyopt", f"group:{name}"], capture_output=True, timeout=30)
        if out.returncode != 0:
            continue
        nums = load_pem_parameters(out.stdout).parameter_numbers()
        check(nums.p == g.q and nums.g == g.alpha, f"{g.name} khác OpenSSL")
        matched.append(name)
    check(matched, "không so được với nhóm nào của OpenSSL")
    return "trùng OpenSSL: " + ", ".join(matched)


@case("TC16", "Đối chiếu", "Khoá chung DH tự tính trùng với thư viện chuẩn cryptography (cùng q, α, x_A, x_B)")
def tc16():
    imported = _import("cryptography.hazmat.primitives.asymmetric", ["dh"])
    if imported is None:
        raise Skip("chưa cài thư viện cryptography (pip install cryptography)")
    dh, = imported
    for g in (G.MODP_2048, G.FFDHE_2048, G.MODP_3072):
        pn = dh.DHParameterNumbers(g.q, g.alpha)
        a, b = generate_keypair(g), generate_keypair(g)
        priv_a = dh.DHPrivateNumbers(a.private, dh.DHPublicNumbers(a.public, pn)).private_key()
        pub_b = dh.DHPublicNumbers(b.public, pn).public_key()
        k_lib = int.from_bytes(priv_a.exchange(pub_b), "big")
        check(k_lib == compute_shared_secret(g, a.private, b.public), f"{g.name}: khác thư viện")
        check(priv_a.public_key().public_numbers().y == a.public, f"{g.name}: y_A khác thư viện")
    return "y_A và K trùng thư viện trên MODP2048, FFDHE2048, MODP3072"


@case("TC17", "Đối chiếu", "SHA-256: test vector FIPS 180-4 + so với hashlib trên dữ liệu ngẫu nhiên")
def tc17():
    vectors = {
        b"": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        b"abc": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq":
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    }
    for m, h in vectors.items():
        check(sha256_hex(m) == h, f"sai với vector {m[:10]!r}")
    for n in [1, 55, 56, 63, 64, 65, 1000, 12345]:
        d = os.urandom(n)
        check(sha256_hex(d) == hashlib.sha256(d).hexdigest(), f"khác hashlib với {n} byte")
    return "3 vector FIPS + 8 độ dài ngẫu nhiên khớp"


@case("TC18", "Đối chiếu", "HMAC-SHA256 (RFC 4231) và HKDF (RFC 5869, Test Case 1) + so với thư viện hmac")
def tc18():
    check(hmac_sha256(b"Jefe", b"what do ya want for nothing?").hex() ==
          "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", "sai RFC 4231 TC2")
    okm = hkdf(bytes([0x0B]) * 22, 42, bytes(range(13)), bytes(range(0xF0, 0xFA)))
    check(okm.hex() == "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
          "sai RFC 5869 TC1")
    for n in [0, 10, 64, 100]:
        k, m = os.urandom(n), os.urandom(200)
        check(hmac_sha256(k, m) == std_hmac.new(k, m, "sha256").digest(), "khác thư viện hmac")
    return "khớp RFC 4231, RFC 5869 và thư viện hmac"


@case("TC19", "Đối chiếu", "ChaCha20: test vector RFC 8439 §2.3.2 + so với thư viện cryptography")
def tc19():
    block = chacha20_block(bytes(range(32)), 1, bytes.fromhex("000000090000004a00000000"))
    check(block.hex() == ("10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
                          "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"), "sai RFC 8439")
    imported = _import("cryptography.hazmat.primitives.ciphers", ["Cipher", "algorithms"])
    if imported is None:
        return "khớp RFC 8439 (bỏ qua phần so với thư viện)"
    Cipher, algorithms = imported
    for n in [1, 64, 65, 1000, 50000]:
        key, nonce, data = os.urandom(32), os.urandom(12), os.urandom(n)
        ref = Cipher(algorithms.ChaCha20(key, (1).to_bytes(4, "little") + nonce), None).encryptor().update(data)
        check(chacha20_xor(key, nonce, data) == ref, f"khác thư viện với {n} byte")
    return "khớp RFC 8439 và thư viện cryptography"


# ===========================================================================
def main():
    ui.title("BỘ KIỂM THỬ — Diffie–Hellman (tự viết + đối chiếu chuẩn)")
    rows, report = [], []
    passed = failed = skipped = 0
    for code, kind, desc, fn in TESTS:
        t0 = time.perf_counter()
        try:
            detail = fn() or ""
            status = "ĐẠT"
            passed += 1
        except Skip as exc:
            status, detail = "BỎ QUA", str(exc)
            skipped += 1
        except Exception as exc:
            status, detail = "KHÔNG ĐẠT", f"{type(exc).__name__}: {exc}"
            failed += 1
        dt = time.perf_counter() - t0
        colour = {"ĐẠT": ("green", "bold"), "BỎ QUA": ("yellow",), "KHÔNG ĐẠT": ("red", "bold")}[status]
        print(f"  {code}  {ui.c(f'{status:<9}', *colour)} {dt:6.2f}s  [{kind}] {desc}")
        print(ui.c(f"                              → {detail}", "gray"))
        report.append(f"{code}\t{status}\t{dt:.2f}s\t{kind}\t{desc}\t{detail}")
    print()
    summary = f"Tổng: {len(TESTS)} ca — ĐẠT {passed}, KHÔNG ĐẠT {failed}, BỎ QUA {skipped}"
    (ui.ok if failed == 0 else ui.fail)(summary)

    os.makedirs(os.path.join(ROOT, "output"), exist_ok=True)
    with open(os.path.join(ROOT, "output", "test_report.txt"), "w", encoding="utf-8") as f:
        f.write("Mã\tKết quả\tThời gian\tLoại\tNội dung\tChi tiết\n")
        f.write("\n".join(report) + "\n" + summary + "\n")
    ui.note("Đã lưu output/test_report.txt")
    return failed == 0


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
