# Keamanan `cms-api`

Dokumen ini adalah pasangan dari `SECURITY.md` di repo `cms-app`. Semua
temuan di bagian **"Belum Bisa Diperbaiki dari Sini"** dokumen itu
ditutup di sini. Setiap perbaikan di bawah diverifikasi lewat uji
fungsional (bukan sekadar cek sintaks) terhadap D1 in-memory.

## Prinsip yang dipakai

1. **Otorisasi hanya dari token yang diverifikasi server.** `cmsId` dan
   `role` tidak pernah dibaca dari query string atau body — selalu dari
   payload token HMAC yang tanda tangannya dicek ulang tiap request.
   Frontend boleh tetap mengirim `cmsId`; backend mengabaikannya.
2. **Kredensial tidak pernah keluar dari server.** Tabel `users` diblokir
   total dari `/api`; tidak ada endpoint yang mengembalikan `passwordHash`.
3. **Allowlist, bukan blocklist** — untuk tag HTML, atribut, skema URL,
   nama tabel, dan nama kolom yang boleh ditulis.
4. **Fail-closed.** Kalau `SESSION_SECRET` belum di-set (atau terlalu
   pendek), permintaan ditolak — termasuk captcha, yang memakai secret
   yang sama untuk menandatangani soalnya (lihat `signToken`).
5. **Pesan error tidak membocorkan internal.** Hanya `HttpError` yang
   pesannya sampai ke klien; error lain jadi "Terjadi kesalahan di server."
   dan hanya masuk log Worker.

## Kontrak 6 prinsip (dari `cms-app/SECURITY.md`), ditafsirkan untuk backend

`cms-app/SECURITY.md` menulis 6 prinsip dari sudut pandang frontend yang
merender DOM. Repo ini murni JSON API — tidak pernah merender HTML sama
sekali — jadi beberapa prinsip perlu padanan eksplisit di sini supaya
audit berikutnya tidak perlu menafsir ulang tiap kali.

| # | Prinsip asli (frontend) | Berlaku langsung? | Padanan/pemenuhan di backend ini |
|---|---|---|---|
| 1 | Escape di titik render, bukan di titik input (`escHtml()`/`esc()`) | **Tidak langsung** — backend tidak punya "titik render", cuma JSON | Padanannya: sanitasi dijalankan ulang di **titik sajikan** (`GET /public?view=artikel`, baris `post.konten = sanitizeHtml(post.konten)`), bukan cuma di titik simpan. Prinsipnya sama: jangan percaya bahwa data yang tersimpan sudah aman, verifikasi ulang tepat sebelum keluar |
| 2 | Allowlist, bukan blocklist, untuk HTML mentah | **Berlaku langsung** | `ALLOWED_TAGS` + `safeUrl()` (tolak semua skema URL kecuali `http/https/mailto` eksplisit) |
| 3 | Raw HTML harus eksplisit & sempit (`rawKeys`, `type:'raw'`) | **Tidak berlaku** — backend tidak pernah mengeluarkan penanda "field ini boleh HTML mentah"; satu-satunya field HTML (`post.konten`) SELALU lewat `sanitizeHtml()`, tidak ada jalur raw sama sekali | Padanan yang backend memang punya: `WRITABLE_COLUMNS` — allowlist eksplisit & sempit untuk *field mana saja* yang boleh ditulis klien per tabel, sisanya dibuang oleh `pickColumns()` |
| 4 | Jangan percaya klien untuk otorisasi; verifikasi dari token sesi | **Berlaku langsung, ini rumah aturannya** | `cmsId`/`role` selalu dari `requireSession()` (HMAC terverifikasi), bukan query string |
| 5 | Captcha hanya berarti kalau diverifikasi server | **Berlaku langsung, ini rumah aturannya** | `verifyMathCaptcha()` — soal+jawaban ditandatangani HMAC (`typ:'captcha'`), diverifikasi ulang di server; fail-closed kalau `SESSION_SECRET` kosong |
| 6 | Kredensial tidak pernah bentuk yang bisa dibaca ulang | **Berlaku langsung, ini rumah aturannya** | PBKDF2-SHA256 + salt, `verifyPassword()` waktu-konstan, tidak ada endpoint yang mengembalikan hash |

Ringkasnya: #4, #5, #6 memang ditujukan untuk backend dan dipenuhi apa
adanya di sini. #1 dan #3 ditulis untuk frontend yang merender DOM;
backend memenuhi *semangatnya* (verifikasi ulang di titik keluar,
allowlist eksplisit & sempit) lewat mekanisme yang sepadan, bukan lewat
`escHtml()`/`rawKeys` yang memang tidak relevan untuk API JSON. #2 berlaku
identik di kedua sisi dan sengaja diterapkan dua kali (frontend saat
merender, backend saat menyimpan & menyajikan) sebagai lapisan berlapis.

## Yang diperbaiki

| # | Temuan (dari `cms-app/SECURITY.md`) | Perbaikan di sini |
|---|---|---|
| KRITIS 1 | `GET /api?table=users&cmsId=X` mengembalikan username + password semua pengguna satu CMS, tanpa perlu login | `users` & `komentar` masuk `BLOCKED_TABLES` → `403` apa pun tokennya. Autentikasi pindah ke `POST /public?view=login` yang mencocokkan di server dan hanya mengembalikan token + data tampilan |
| KRITIS 1b | Password plaintext di database | `users.passwordHash` — PBKDF2-SHA256, salt 16 byte per user, 210.000 iterasi (rekomendasi OWASP untuk SHA-256; Argon2id tidak tersedia native di runtime Workers), dibandingkan secara waktu-konstan |
| KRITIS 2 | IDOR: `cmsId` diambil dari `localStorage` klien, backend memercayainya | `cmsId` selalu dari `session.cid` (token). Diuji: akun "wawan" memalsukan `cmsId` milik "siti" di query → daftar artikel tetap kosong, GET by id `404`, DELETE tidak menghapus apa pun |
| TINGGI 3 | Captcha hanya widget frontend, tidak diverifikasi | `verifyMathCaptcha()` memverifikasi soal+jawaban bertanda tangan server sebelum kredensial diproses, di login maupun registrasi — lihat "Perubahan arsitektur captcha" di bawah |
| TINGGI 4 | Lockout login cuma di frontend (kosmetik) | Tabel `rate_limit` di D1: login 5 gagal/akun & 20/IP per 15 menit → blokir 15 menit; registrasi 5/IP per jam; komentar 10/user per jam. Blokir ditegakkan **sebelum** password dicocokkan, jadi password benar pun ditolak selama terkunci |
| SEDANG 5 | Sanitasi HTML hanya di frontend | `sanitizeHtml()` server-side (allowlist tag+atribut, buang `on*`, tolak skema `javascript:`/`data:`/`vbscript:` termasuk yang ter-encode entity) dipanggil saat **menyimpan** dan saat **menyajikan** lewat `/public` — baris lama yang terlanjur kotor ikut bersih saat dibaca |
| Tambahan | `INSERT INTO ${table} (${Object.keys(body)})` merakit **nama kolom** dari body klien — injeksi SQL lewat nama kolom | `WRITABLE_COLUMNS` per tabel; `pickColumns()` membuang sisanya. `id`, `cmsId`, `views` selalu ditentukan server |
| Tambahan | `Access-Control-Allow-Origin: *` | Allowlist origin lewat `ALLOWED_ORIGINS` + `Vary: Origin` |
| Tambahan | Enumerasi username lewat beda waktu respons | Verifikasi password tetap dijalankan terhadap hash dummy saat user tidak ada; pesan error login digabung jadi satu ("Kode CMS, username, atau password salah") |
| Tambahan | Komentar bisa dipalsukan identitasnya | `nama` & `userId` diambil dari token + tabel `users`; field `nama`/`userId` di body diabaikan. Kolom `email` bebas-ketik dihapus dari skema |
| Tambahan | `post.status`, `slug`, URL cover tidak divalidasi | `status` dipaksa ke `draft|publish`, `slug` wajib lolos `SLUG_RE`, `coverImage`/`avatarUrl` lewat `safeUrl()`, semua teks dipotong panjang maksimum |
| Tambahan | Pemilik CMS bisa menyunting field administratif | Owner hanya boleh `nama`, `bio`, `avatarUrl`. `status` khusus superadmin; `kodeCms` tidak bisa diubah siapa pun lewat PATCH (tautan publik tidak boleh patah) |

## Perubahan arsitektur captcha (Turnstile → matematika kustom)

Versi sebelumnya memverifikasi captcha lewat Cloudflare Turnstile
(`verifyTurnstile()` memanggil `siteverify`). Diganti dengan captcha
matematika kustom (`generateMathCaptcha()`/`verifyMathCaptcha()`) karena:

- **Tanpa dependensi pihak ketiga.** Tidak ada panggilan keluar ke
  `challenges.cloudflare.com` dari server maupun klien, dan tidak ada
  script eksternal (`turnstile/v0/api.js`) di frontend yang bisa
  ter-block ad-blocker atau gagal dimuat.
- **Tanpa secret tambahan.** Soal ("a + b = ?") dan jawabannya
  ditandatangani HMAC dengan `SESSION_SECRET` yang sudah ada
  (`signToken`/`verifyToken`, `typ:'captcha'`) — tidak perlu
  `TURNSTILE_SECRET_KEY` maupun tabel/state baru.
- **Percobaan dibatasi** lewat `rate_limit` yang sama dipakai
  login/registrasi (kunci `captcha:ip:<ip>`, maks 10 percobaan/15
  menit lalu terkunci 15 menit) — bukan cuma diverifikasi sekali tanpa
  batas percobaan.
- **Kesadaran keterbatasan:** ini captcha matematika sederhana, bukan
  pertahanan anti-bot canggih seperti Turnstile (tidak ada analisis
  perilaku/fingerprint). Cukup untuk menyaring form-spam otomatis
  generik; bukan untuk melawan penyerang yang menargetkan aplikasi ini
  secara spesifik. Trade-off ini diterima sadar demi menghilangkan
  ketergantungan pihak ketiga.

## Batas yang masih ada (sadar, bukan kelupaan)

- **Token tidak bisa dicabut satu per satu.** Token HMAC bersifat
  *stateless* dan berlaku 12 jam. Untuk mencabut semua sesi sekaligus:
  ganti `SESSION_SECRET`. Kalau nanti butuh pencabutan per-sesi, tambahkan
  tabel `session` (atau KV) berisi `jti` yang dicek tiap request.
- **Token disimpan di `localStorage`** (mengikuti arsitektur frontend saat
  ini). Artinya XSS yang lolos tetap bisa mencuri token. Cookie
  `HttpOnly; Secure; SameSite=Strict` lebih aman, tapi menuntut frontend
  dan backend berada di satu domain induk. Karena itu sanitasi HTML di
  atas jadi penting, bukan opsional.
- **Tidak ada moderasi komentar.** Komentar langsung `approved`. Kolom
  `status` sudah ada kalau nanti mau dimoderasi.
- **`rate_limit` tidak dibersihkan otomatis.** Jalankan berkala (mis. Cron
  Trigger):
  `DELETE FROM rate_limit WHERE blockedUntil < <now-ms> AND windowStart < <now-ms - 86400000>;`
- **Tidak ada reset password.** Kalau pengguna lupa password, satu-satunya
  jalan sekarang adalah superadmin men-generate hash baru
  (`node tools/hash-password.mjs`) dan meng-update barisnya lewat
  `wrangler d1 execute`.
- **Belum ada logging/alert percobaan login gagal** di luar penghitung
  rate limit.

## Uji ulang

Uji fungsional yang saya pakai menjalankan Worker sungguhan di atas D1
tiruan (SQLite in-memory) dan memeriksa 44 asersi — hashing, isolasi
CMS/IDOR, pemalsuan token, sanitasi HTML, injeksi nama kolom, identitas
komentar, lockout, dan CORS. Kalau nanti ada perubahan di `worker.js`,
jalankan ulang uji itu sebelum deploy.
