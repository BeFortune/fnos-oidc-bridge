#!/usr/bin/env python3
"""生成 fpk 所需的占位图标(纯 stdlib,手写 PNG)。"""
import struct, zlib, os

W = H = 256
# 背景:靛蓝 #4F46E5;前景:白色钥匙形(圆环 + 柄)
BG = (79, 70, 229, 255)
FG = (255, 255, 255, 255)
CLR = (0, 0, 0, 0)

def in_ring(cx, cy, r_out, r_in, x, y):
    d2 = (x - cx) ** 2 + (y - cy) ** 2
    return r_in ** 2 <= d2 <= r_out ** 2

def in_disc(cx, cy, r, x, y):
    return (x - cx) ** 2 + (y - cy) ** 2 <= r ** 2

def in_rect(x0, y0, x1, y1, x, y):
    return x0 <= x <= x1 and y0 <= y <= y1

px = []
for y in range(H):
    for x in range(W):
        corner = 40
        # 方形背景 + 大圆角(四角留透明)
        inside_bg = True
        if (x < corner and y < corner and (corner - x) ** 2 + (corner - y) ** 2 > corner ** 2):
            inside_bg = False
        if (x > W - corner and y < corner and (x - (W - corner)) ** 2 + (corner - y) ** 2 > corner ** 2):
            inside_bg = False
        if (x < corner and y > H - corner and (corner - x) ** 2 + (y - (H - corner)) ** 2 > corner ** 2):
            inside_bg = False
        if (x > W - corner and y > H - corner and (x - (W - corner)) ** 2 + (y - (H - corner)) ** 2 > corner ** 2):
            inside_bg = False

        color = BG if inside_bg else CLR
        if inside_bg:
            # 钥匙:圆环(环心在 128,104,外径44内径26) + 柄(矩形) + 齿
            if in_ring(128, 104, 44, 26, x, y):
                color = FG
            elif in_rect(120, 140, 136, 196, x, y):
                color = FG
            elif in_rect(136, 172, 160, 186, x, y):
                color = FG
            elif in_rect(136, 190, 152, 204, x, y):
                color = FG
        px.append(color)

def png_chunk(tag, data):
    c = struct.pack(">I", len(data)) + tag + data
    return c + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

raw = b""
for y in range(H):
    raw += b"\x00" + b"".join(struct.pack("4B", *px[y * W + x]) for x in range(W))

ihdr = struct.pack(">IIBBBBB", W, H, 8, 6, 0, 0, 0)
png = (b"\x89PNG\r\n\x1a\n"
       + png_chunk(b"IHDR", ihdr)
       + png_chunk(b"IDAT", zlib.compress(raw, 9))
       + png_chunk(b"IEND", b""))

out_dir = os.path.join(os.path.dirname(__file__), "..", "fpk")
for name in ("ICON.PNG", "ICON_256.PNG"):
    with open(os.path.join(out_dir, name), "wb") as f:
        f.write(png)
print("icons written:", os.listdir(out_dir))
