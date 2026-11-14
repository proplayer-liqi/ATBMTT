"""
ui.py — Các hàm hiển thị cho giao diện dòng lệnh (màu, bảng, nhập liệu).
Không chứa thuật toán mật mã.
"""
import os
import sys

# Bật hiển thị tiếng Việt và mã màu ANSI trên Windows
try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stdin.reconfigure(encoding="utf-8")
except Exception:
    pass
if os.name == "nt":
    os.system("")

USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
PAUSE = True          # tắt bằng tham số --no-pause


def set_options(color=None, pause=None):
    global USE_COLOR, PAUSE
    if color is not None:
        USE_COLOR = color
    if pause is not None:
        PAUSE = pause


_CODES = {
    "bold": "1", "dim": "2", "red": "31", "green": "32", "yellow": "33",
    "blue": "34", "magenta": "35", "cyan": "36", "gray": "90",
}


def c(text, *styles):
    if not USE_COLOR or not styles:
        return str(text)
    return "\033[" + ";".join(_CODES[s] for s in styles) + "m" + str(text) + "\033[0m"


ACTOR_STYLE = {
    "Alice": ("blue", "bold"),
    "Bob": ("green", "bold"),
    "Mallory": ("red", "bold"),
    "Eve": ("magenta", "bold"),
    "Kênh": ("gray",),
}


def actor(name):
    return c(f"[{name}]", *ACTOR_STYLE.get(name, ("bold",)))


def title(text):
    line = "═" * max(60, len(text) + 4)
    print()
    print(c(line, "cyan"))
    print(c(f"  {text}", "cyan", "bold"))
    print(c(line, "cyan"))


def section(text):
    print()
    print(c(f"▶ {text}", "yellow", "bold"))


def ok(text):
    print(c("  ✔ ", "green", "bold") + text)


def fail(text):
    print(c("  ✘ ", "red", "bold") + text)


def info(text):
    print("  " + text)


def note(text):
    print(c("  " + text, "gray"))


def short_int(n: int, keep: int = 12) -> str:
    """Rút gọn số lớn: 1234567...890123 (2048 bít)."""
    s = str(n)
    if len(s) <= 2 * keep + 3:
        return s
    return f"{s[:keep]}…{s[-keep:]} ({n.bit_length()} bít)"


def table(headers, rows, align=None):
    """In bảng có khung đơn giản."""
    rows = [[str(x) for x in r] for r in rows]
    widths = [len(h) for h in headers]
    for r in rows:
        for i, cell in enumerate(r):
            widths[i] = max(widths[i], len(cell))
    align = align or ["<"] * len(headers)

    def fmt(cells, style=None):
        out = []
        for i, cell in enumerate(cells):
            out.append(f"{cell:{align[i]}{widths[i]}}")
        line = " │ ".join(out)
        return "  │ " + (c(line, style) if style else line) + " │"

    border = "─┼─".join("─" * w for w in widths)
    print("  ┌─" + "─┬─".join("─" * w for w in widths) + "─┐")
    print(fmt(headers, "bold"))
    print("  ├─" + border + "─┤")
    for r in rows:
        print(fmt(r))
    print("  └─" + "─┴─".join("─" * w for w in widths) + "─┘")


def pause(msg="Nhấn Enter để tiếp tục..."):
    if PAUSE:
        try:
            input(c(f"  {msg}", "dim"))
        except EOFError:
            pass


def ask(prompt, default=None):
    suffix = f" [{default}]" if default is not None else ""
    try:
        s = input(c(f"  ? {prompt}{suffix}: ", "bold")).strip()
    except EOFError:                      # hết dữ liệu nhập (ví dụ chạy bằng script) -> thoát
        print()
        raise SystemExit(0)
    return s if s else (str(default) if default is not None else "")


def ask_int(prompt, default=None, low=None, high=None):
    while True:
        s = ask(prompt, default)
        try:
            v = int(s, 0)
        except ValueError:
            fail("Vui lòng nhập một số nguyên.")
            continue
        if (low is not None and v < low) or (high is not None and v > high):
            fail(f"Giá trị phải trong khoảng [{low}, {high}].")
            continue
        return v


def choose(prompt, options, default=1):
    """options: danh sách (nhãn). Trả về chỉ số (bắt đầu từ 1)."""
    for i, label in enumerate(options, 1):
        print(f"    {c(str(i), 'cyan', 'bold')}. {label}")
    return ask_int(prompt, default, 1, len(options))
