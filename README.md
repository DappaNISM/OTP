# OTP Termux

Pengirim OTP WhatsApp minimalis. Satu file, tanpa browser, jalan di Termux.

## Pasang

```bash
pkg update -y && pkg install -y python
pip install requests
```

## Pakai

```bash
python otp.py
```

Muncul menu:

```
  1. Single Number
  2. Bulk Number (maks 10)

  pilih [1/2] :
```

**Pilihan 1** — masukkan satu nomor:

```
  nomor WhatsApp : 081511624778
  target OTP per nomor [15] :
```

**Pilihan 2** — masukkan beberapa nomor dipisah koma:

```
  nomor : 081511624778,08212398494,085697218463
  target OTP per nomor [15] :
```

Setelah itu script langsung jalan sendiri sampai target tercapai.
Satu worker per nomor, semua nomor jalan paralel.

Berhenti: `Ctrl+C`

Info endpoint:

```bash
python otp.py --list
```

## Output

```
[+] 21:35:22 SENT      total=1
[+] 21:35:23 SENT      total=2
[~] 21:35:25 COOLDOWN  total=2
[~] 21:36:18 COOLDOWN  total=2
```

Tiga status saja, tanpa nama layanan:

- `[+] SENT` — server menyatakan terkirim
- `[~] COOLDOWN` — sedang jeda, otomatis dilewati
- `[x] FAIL` — ditolak

**`SENT` bukan jaminan masuk WhatsApp.** Hitung sendiri di HP.

Di akhir muncul ringkasan:

```
====================================================
  15 terkirim dalam 1240s
====================================================
```

## Batas nyata

Jeda berasal dari **nomor telepon**, bukan IP. Ganti IP atau proxy tidak
menghapusnya. Nomor yang sama akan tetap kena limit di server masing-masing.

Perkiraan: **15-25 OTP per jam**.

## Konfigurasi

Email bisa diganti lewat environment:

```bash
OTP_EMAIL=email@kamu.com python otp.py 30
```

## Jalan di background (Termux)

```bash
pkg install -y termux-api
nohup python otp.py 30 > otp.log 2>&1 &
tail -f otp.log
```

Hentikan: `pkill -f otp.py`

## Isi folder

```
otp.py             skrip utama
README.md          file ini
requirements.txt   dependensi
```
