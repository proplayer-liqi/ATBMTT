"""
Tạo ảnh mẫu data/sample.png (không cần thư viện ngoài) để demo mã hoá tệp ảnh.
Ảnh: nền chuyển màu, khung và chữ "DH" ghép từ các ô vuông.
"""
import os
import struct
import zlib

W, H = 480, 300
FONT = {  # chữ D và H dạng lưới 5x7
    "D": ["1110", "1001", "1001", "1001", "1001", "1001", "1110"],
    "H": ["1001", "1001", "1001", "1111", "1001", "1001", "1001"],
}


def pixel(x, y):
    r = int(40 + 120 * x / W)
    g = int(90 + 100 * y / H)
    b = int(200 - 80 * x / W)
    # khung
    if x < 8 or y < 8 or x >= W - 8 or y >= H - 8:
        return (255, 255, 255)
    # chữ DH
    cell = 22
    ox, oy = 120, 70
    for idx, ch in enumerate("DH"):
        bx = ox + idx * cell * 5
        cx, cy = (x - bx) // cell, (y - oy) // cell
        if 0 <= cy < 7 and 0 <= cx < 4 and FONT[ch][cy][cx] == "1":
            return (255, 220, 60)
    return (r, g, b)


def write_png(path):
    raw = b"".join(b"\x00" + b"".join(bytes(pixel(x, y)) for x in range(W)) for y in range(H))

    def chunk(tag, data):
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

    png = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", W, H, 8, 2, 0, 0, 0))
    png += chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b"")
    with open(path, "wb") as f:
        f.write(png)


if __name__ == "__main__":
    out = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "sample.png")
    write_png(out)
    print("Đã tạo", out, os.path.getsize(out), "byte")
