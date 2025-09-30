# CTF Forensics Write‑up — Khôi phục thứ đã hiển thị cuối cùng trên màn hình (DWM dump)

**Thử thách**: *Recover what was last on the screen.*  
Một nhà khoa học đang RDP vào máy Windows. Một cửa sổ lạ lóe lên rồi phiên bị khóa, nhưng EDR đã thu được một file **`dwm.exe.dmp`**. Hỏi: **Lúc đó trên màn hình có gì?**

---

## Ý tưởng & Nền tảng kỹ thuật

- **dwm.exe (Desktop Window Manager)** là compositor của Windows: nó giữ **GPU surface** của các cửa sổ rồi ghép (compose) thành khung hình hiển thị.
- Những surface này **không phải** dạng file ảnh nén (PNG/JPEG) để có thể “carve” trực tiếp. Chúng là **buffer thô** dạng **BGRA 8‑bit** (4 byte/pixel).
- Mỗi hàng (row) thường có **pitch/stride** **≥ `width*4`** do **padding/alignment** (hay gặp căn theo 256 B). Nếu dựng ảnh mà **không tôn trọng pitch**, ta sẽ thấy sọc/nghiêng/ảnh rách.

**Mục tiêu**: Tìm đúng *offset* nơi surface nằm trong dump, xác định **`width × height`**, **`pitch`**, và **thứ tự kênh** (BGRA) để dựng lại thành PNG.

---

## Quy trình giải (tóm tắt)

1. **Quét thô (coarse sweep)**: nhảy theo bước lớn trong file dump, thử nhanh một số độ phân giải phổ biến và cả BGRA/RGBA để *“đánh hơi”* xem có mẩu ảnh nào xuất hiện không.
2. **Ghim neo (anchor)**: chỉ cần **một ảnh rách/torn** là đủ chứng minh có surface + suy ra **độ phân giải** và **vùng offset xấp xỉ**.
3. **Tái dựng tập trung (focused reconstruction)**: viết script đọc theo **`pitch*height`**, mỗi hàng **chỉ copy `width*4`** byte đầu (bỏ padding), **BGRA→RGBA** (đặt alpha=255), rồi lưu PNG.
4. **Quét tinh quanh neo**: dịch offset **±512 KiB** với bước **4 KiB**, thử vài **pitch** (ví dụ `W*4 ± 256`) → xuất hàng loạt PNG → **lọc rác** → **lướt xem** đến khi thấy ảnh hoàn chỉnh.
5. **Kết quả**: ảnh hộp thoại (ransom dialog) hiện rõ → đọc **flag**.

---

## Bước 1 — Quét thô để tìm “dấu vân tay”

Script Python dưới đây quét file theo **bước 16 MiB**, thử các độ phân giải hay gặp và hai thứ tự kênh **BGRA/RGBA**. Công cụ chuyển đổi dùng **ImageMagick** (`convert`).

```python
#!/usr/bin/env python3
# initial_sweep.py — quét thô “cắt lát” raw để tìm dấu vết screenshot

import os, subprocess
src = "dwm.exe.dmp"
outdir = "raw_candidates"
os.makedirs(outdir, exist_ok=True)

# thử vài độ phân giải desktop phổ biến
sizes = [(1366,768),(1024,768),(1920,1080),(1600,900)]
step = 16 * 1024 * 1024  # nhảy 16 MiB
L = os.path.getsize(src)
idx = 0

def try_slice(offset, w, h, fmt, idx):
    size = w * h * 4
    with open(src, "rb") as f:
        f.seek(offset)
        buf = f.read(size)
    if len(buf) != size:
        return False
    raw = f"{outdir}/slice_{idx:05d}_{w}x{h}_{fmt}_off{offset}.raw"
    png = raw.replace(".raw", ".png")
    open(raw, "wb").write(buf)
    try:
        subprocess.run(["convert", "-size", f"{w}x{h}", "-depth", "8", f"{fmt}:{raw}", png],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        os.remove(raw)
        print("made", png)
        return True
    except Exception:
        try: os.remove(raw)
        except: pass
        return False

for offset in range(0, L, step):
    for (w,h) in sizes:
        for fmt in ("bgra","rgba"):
            try_slice(offset, w, h, fmt, idx)
            idx += 1

print("initial sweep done; check raw_candidates/")
```

> **Kỳ vọng**: đa số là rác, nhưng chỉ cần **một ảnh rách** (viền hộp thoại, menu bar, v.v.) là đủ **chứng minh có surface** và **gợi ý W×H + vùng offset**.

---

## Bước 2 — Tái dựng có trọng tâm (repack surface)

Từ ảnh rách, suy ra độ phân giải **1024×768**. Với `W=1024`, `W*4 = 4096` B, nhưng do căn dòng theo 256 B, ta sẽ thử **3840, 4096, 4352**.

Script dưới đây đọc **`pitch*H`** byte từ `offset`, với **mỗi hàng chỉ lấy `W*4`** byte đầu; chuyển **BGRA→RGBA**, ép **alpha=255** rồi ghi PNG.

```python
#!/usr/bin/env python3
# repack_surface.py — đọc pitch*height tại offset, mỗi hàng copy width*4,
# BGRA -> RGBA, alpha = 255, lưu PNG.

import sys
from PIL import Image

def repack_and_save(src, offset, W, H, pitch, out):
    need = pitch * H
    with open(src, "rb") as f:
        f.seek(offset)
        buf = f.read(need)
    if len(buf) != need:
        print("FAIL: short read")
        return False

    rowbytes = W * 4
    tight = bytearray(W * H * 4)
    for y in range(H):
        row = buf[y * pitch : y * pitch + rowbytes]
        if len(row) < rowbytes:
            print("FAIL: short row")
            return False
        # BGRA -> RGBA, alpha = 255
        for x in range(0, rowbytes, 4):
            b = row[x+0]
            g = row[x+1]
            r = row[x+2]
            idx = (y * rowbytes) + x
            tight[idx + 0] = r
            tight[idx + 1] = g
            tight[idx + 2] = b
            tight[idx + 3] = 255

    Image.frombytes("RGBA", (W, H), bytes(tight)).save(out, optimize=True)
    return True

if __name__ == "__main__":
    if len(sys.argv) != 7:
        print("usage: repack_surface.py dump offset width height pitch out.png")
        sys.exit(1)
    src = sys.argv[1]
    offset = int(sys.argv[2])      # nhập số thập phân, không phải 0x...
    W = int(sys.argv[3])
    H = int(sys.argv[4])
    pitch = int(sys.argv[5])
    out = sys.argv[6]
    ok = repack_and_save(src, offset, W, H, pitch, out)
    print("OK" if ok else "FAIL")
```

**Cài đặt phụ thuộc**:
```bash
python3 -m pip install pillow
# và ImageMagick nếu dùng script quét thô:
# sudo apt install imagemagick
```

---

## Bước 3 — Quét tinh quanh offset mốc

Dịch offset **±512 KiB**, bước **4 KiB**, thử 3 giá trị `pitch` ở trên; dựng ảnh hàng loạt, xóa ảnh quá nhỏ (< 20 KB) để giảm rác; sau đó liệt kê **20 ảnh lớn nhất** (thường là ảnh “đúng”) để mở xem.

```bash
BASE=16777216         # offset neo từ quét thô
SPAN=524288           # ±512 KiB
STEP=4096             # bước 4 KiB
W=1024; H=768
PITCHES=(3840 4096 4352)

mkdir -p png_1024x768_scan
for off in $(seq $((BASE - SPAN)) $STEP $((BASE + SPAN))); do
  for p in "${PITCHES[@]}"; do
    out=png_1024x768_scan/cand_off${off}_p${p}.png
    python3 repack_surface.py dwm.exe.dmp $off $W $H $p $out >/dev/null 2>&1 || true
    # lọc PNG rác quá nhỏ
    [ -f "$out" ] && [ $(stat -c%s "$out") -lt 20000 ] && rm -f "$out"
  done
done

# gợi ý 20 file lớn nhất để bạn xem trước
ls -S png_1024x768_scan/*.png | head -20
```

> **Mẹo**: nếu màu bị lệch (tông xanh/đỏ đảo), có thể do thứ tự kênh. DWM thường là **BGRA**, nên đoạn repack đã đổi về RGBA sẵn.

---

## Kết quả

Khi lướt qua các ảnh đã dựng, phần sọc/tearing biến mất dần khi `pitch` & `offset` đúng. Ảnh hộp thoại tống tiền hiện rõ trong file ví dụ:

```
png_1024x768_scan/cand_off17158144_p4096.png
```

**Flag thu được**:  
```
sun{r3m0t3_pwn4g3_QQ}
```

---

## Pitfall & Ghi chú thực chiến

- **Sai pitch** → ảnh sọc/nghiêng/rách. Hãy ưu tiên dò pitch trước khi phán sai kênh.
- **Sai thứ tự kênh** → màu kỳ lạ. DWM thường **BGRA**.
- **Sai W×H** → ảnh méo, không nhận ra UI. Hãy thử vài độ phân giải desktop phổ biến.
- **Offset không thẳng** (trường hợp hiếm) → cần phương pháp khác (plugin Volatility, trích handle surface, v.v.). Bài này là buffer thô liên tiếp nên cách trên là tối ưu.

---

## Tóm lược một lệnh‑chạy‑là‑ra (One‑shot)

```bash
# 1) Quét thô để "ngửi" offset & W×H (tùy chọn, có ImageMagick)
python3 initial_sweep.py

# 2) Khi đã nghi 1024x768 và có offset neo (vd BASE=16777216),
# quét tinh quanh neo và dựng hàng loạt PNG:
BASE=16777216; SPAN=524288; STEP=4096; W=1024; H=768
PITCHES=(3840 4096 4352)
mkdir -p png_1024x768_scan
for off in $(seq $((BASE - SPAN)) $STEP $((BASE + SPAN))); do
  for p in "${PITCHES[@]}"; do
    python3 repack_surface.py dwm.exe.dmp $off $W $H $p png_1024x768_scan/cand_off${off}_p${p}.png       >/dev/null 2>&1 || true
  done
done
ls -S png_1024x768_scan/*.png | head -20
```

---

### Kết luận

- Với dump **DWM**, “*last on screen*” khả dĩ là **screenshot** đang nằm trong **surface BGRA** có **pitch**.  
- Quy trình nhanh: **quét thô → ghim neo → repack có pitch → quét tinh → soi kết quả**.  
- Áp dụng vào bài này, ta khôi phục được **ransom dialog** và đọc **flag**: `sun{r3m0t3_pwn4g3_QQ}`.
