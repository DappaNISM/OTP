#!/usr/bin/env python3
"""Solver captcha Segari pakai ddddocr (butuh Python 3.13 + ddddocr).

Dipakai otp.py lewat subprocess karena python utama (3.15) belum punya
wheel onnxruntime.

Pakai:
  py -3.13 solve_cap.py gambar.png
Output: teks captcha di stdout (tanpa newline tambahan selain print).
"""
import sys


def main():
    if len(sys.argv) < 2:
        print("")
        return
    path = sys.argv[1]
    try:
        import ddddocr
    except ImportError:
        print("")
        return
    ocr = ddddocr.DdddOcr(show_ad=False)
    with open(path, "rb") as f:
        img = f.read()
    try:
        print(ocr.classification(img) or "")
    except Exception:
        print("")


if __name__ == "__main__":
    main()
