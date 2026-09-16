# Konversi POS → CMS Multi-User (v3: penamaan `cms` + URL publik rapi)

Ringkasan perubahan dari `pos-api-main` + `pos-app-main` menjadi platform
CMS multi-user. Dokumen ini adalah revisi kedua: v1 memakai SSR 1-origin,
v2 memecahnya jadi microservices + query routing, dan v3 (dokumen ini)
menyeragamkan penamaan ke `cms` serta merapikan URL publik.

## Keputusan arsitektur yang masih berlaku

1. **1 user = 1 CMS**, isolasi data penuh — persis pola toko di versi
   POS, hanya kontennya diganti dari produk/transaksi menjadi artikel.
2. **2 repo/layanan terpisah** (microservices):

```
cms-api/   <- repo ini — BACKEND MURNI (Cloudflare Worker + D1, JSON only)
  worker.js
  schema.sql
  wrangler.toml
cms-app/   <- FRONTEND MURNI (static SPA, dideploy sendiri, mis. GitHub Pages)
  index.html
  engine.js, db.js, auth.js, dataset.js
  pages/*.js (termasuk pages/public.js)
```

## Perubahan v3 — satu istilah: `cms`

Sebelumnya istilah bercampur: `tenant` (warisan pola multi-tenant POS),
`toko` (warisan domain POS), dan `blog` (nama produk versi v1/v2). Semua
diseragamkan menjadi **`cms`**, di seluruh lapisan, tanpa sisa:

| Lama (v2)              | Baru (v3)            | Tempat                        |
|------------------------|----------------------|-------------------------------|
| tabel `tenants`        | tabel `cms`          | schema.sql, worker.js, db.js  |
| kolom `tenantId`       | kolom `cmsId`        | schema.sql, worker.js, db.js  |
| kolom `kodeToko`       | kolom `kodeCms`      | schema.sql, worker.js, auth.js|
| query `?tenantId=`     | query `?cmsId=`      | endpoint `/api`               |
| `view=blog`            | `view=profile`       | endpoint `/public`            |
| rute `?page=tenant`    | rute `?cms`          | cms-app (halaman superadmin)  |
| `pages/tenant.js`      | `pages/cms.js`       | cms-app                       |
| `db.allTenants()` dst. | `db.allCms()` dst.   | db.js                         |
| sesi `blogSession`     | sesi `cmsSession`    | auth.js (localStorage)        |
| "Piawai Blog"          | "Piawai CMS"         | index.html, judul halaman     |

Konsekuensi: **sesi login lama otomatis tidak terbaca** (key localStorage
berubah) — pengguna cukup masuk ulang. Database lama juga tidak kompatibel;
jalankan `schema.sql` yang baru (lihat Deploy).

## Perubahan v3 — URL yang rapi, satu aturan untuk semua rute

Di v2, URL berbentuk pasangan key=value yang panjang:
`...?page=artikel&user=<kode>&slug=<slug>`. Di v3, **semua** rute memakai
query string yang diisi **segmen mirip path**:

| Halaman              | URL v3                                   |
|----------------------|------------------------------------------|
| Beranda              | `cms.piawai.id/`                         |
| Profil CMS (publik)  | `cms.piawai.id/?profile/<kodeCms>`       |
| Artikel (publik)     | `cms.piawai.id/?user/<kodeCms>/<slug>`   |
| Masuk                | `cms.piawai.id/?login`                   |
| Daftar               | `cms.piawai.id/?register`                |
| Dasbor               | `cms.piawai.id/?dashboard`               |
| Tulis artikel baru   | `cms.piawai.id/?editor`                  |
| Edit artikel         | `cms.piawai.id/?editor/<idArtikel>`      |
| Artikel saya         | `cms.piawai.id/?postingan`               |
| Edit profil sendiri  | `cms.piawai.id/?profil`                  |
| Kelola CMS (superadmin) | `cms.piawai.id/?cms`                  |

Rute admin IKUT bentuk yang sama — bukan lagi `?page=dashboard`. Sempat
dipertimbangkan membiarkannya beda (toh tidak dibagikan/diindeks), tapi
dua aturan URL dalam satu aplikasi lebih mahal diingat dan gampang salah
dipakai ketimbang satu aturan seragam.

Yang **tidak** berubah: ini tetap query string murni — path selalu `/`,
jadi hosting statis apa pun (GitHub Pages, Cloudflare Pages, Netlify)
tetap menyajikan `index.html` yang sama **tanpa konfigurasi rewrite apa
pun**. Yang diubah hanya *isi* query-nya, supaya alamat enak dibaca dan
dibagikan. Alasan lengkap kenapa query string (bukan path sungguhan)
tetap dipakai ada di bagian berikutnya.

**Aturannya seragam:** segmen pertama = nama rute, segmen berikutnya =
nilai parameter sesuai urutan di `ROUTE_PARAM_KEYS`. Satu-satunya
pengecualian terdaftar di `ROUTE_PREFIX`: rute `artikel` memakai prefiks
`user`, supaya alamat artikel terbaca sebagai milik seorang penulis
(`?user/wawan/judul`, bukan `?artikel/wawan/judul`).

Implementasinya terpusat di `cms-app/engine.js`: `ROUTE_PARAM_KEYS`,
`ROUTE_PREFIX`, `parseLocationParams()` (URL → params),
`buildQueryString()` (params → URL), dan `web.href()` (pembangun href
untuk semua halaman). Tidak ada berkas lain yang merakit URL sendiri,
jadi kalau format URL diubah lagi, cukup berkas ini yang disentuh.

**Tautan lama tetap terbuka.** `parseLocationParams()` masih menerima
bentuk `?page=x&param=y`, jadi bookmark atau tautan yang sudah terlanjur
tersebar sebelum v3 tidak mati — hanya tidak lagi diproduksi.

## Kenapa query string, bukan path?

Karena frontend & backend adalah 2 origin/domain berbeda (bukan 1 Worker
lagi), tidak ada server yang bisa melakukan path-rewrite bersama untuk
keduanya. Hosting statis untuk frontend juga TIDAK BISA me-rewrite path
sembarang ke 1 file secara native — satu-satunya trik yang ada (redirect
404 → query string → `pushState`) pada akhirnya tetap lewat query string
juga. Karena itu, baik komunikasi API (`cms-app` → `cms-api`) maupun
routing halaman di dalam `cms-app`, semuanya konsisten pakai query string.

**Konsekuensi yang disadari & diterima:**
- SSR sungguhan (HTML dirender di server) **tidak ada**. Backend cuma
  JSON (`/public?view=...`); yang merender HTML adalah `cms-app` di klien
  (lihat `pages/public.js`). Pengindeksan mesin pencari bergantung pada
  kemampuan Google/dst. menjalankan JavaScript.
- Form komentar **wajib JS** (fetch ke `/public?view=komentar`), karena
  hosting statis tidak punya server untuk memproses `<form method="POST">`.

## Deploy

**Backend (`cms-api`):**
```
wrangler d1 create <NAMA_DB>       # isi database_id ke wrangler.toml
wrangler d1 execute <NAMA_DB> --file=schema.sql
wrangler deploy
```

Untuk database yang SUDAH berjalan (ada isi yang tidak boleh hilang),
JANGAN jalankan `schema.sql` — berkas itu diawali `DROP TABLE`. Pakai
berkas migrasi yang hanya menambah tabel `halaman` & `menu`:
```
wrangler d1 execute <NAMA_DB> --file=migration_halaman_menu.sql
```
Catat URL yang dihasilkan (mis. `https://cms-api.<akun>.workers.dev`).

**Frontend (`cms-app`):**
Isi `API_BASE` di `db.js` dengan URL backend di atas, lalu deploy folder
ini ke hosting statis pilihan. Untuk memakai `cms.piawai.id`, arahkan
subdomain tersebut ke hosting statis itu (custom domain di GitHub Pages /
Cloudflare Pages / Netlify) — tidak ada aturan rewrite yang perlu diatur.

## Fitur baru: landing page & menu yang dikelola admin

Situs ini sekarang adalah **halaman muka `piawai.id`** untuk tiga
aplikasi PkM — CMS Piawai, LMS Piawai, dan POS Piawai — sekaligus tetap
menjadi platform CMS multi-penulis seperti sebelumnya. Dua peran itu
sengaja dipisah rapi, bukan dicampur:

| | Dikelola oleh | Tabel | Tampil di |
|---|---|---|---|
| Halaman situs | superadmin | `halaman` | `/` dan `?laman/<slug>` |
| Menu & submenu | superadmin | `menu` | bilah navigasi |
| Artikel | tiap penulis | `post` | `?artikel` & `?user/<kode>/<slug>` |

**Kenapa `halaman` tidak ber-`cmsId`?** Karena isinya adalah wajah situs
itu sendiri, bukan tulisan seseorang. Kalau diberi `cmsId`, pertanyaan
"halaman milik siapa yang tampil di `/`" tidak punya jawaban pasti
begitu ada penulis kedua.

**Slug `beranda` dikunci.** Halaman berslug `beranda` adalah yang
dirender di alamat utama. Slug-nya tidak bisa diganti, tidak bisa
di-draft, dan tidak bisa dihapus (`HOME_SLUG` di `worker.js`) — tanpa
kunci itu, satu klik "Hapus" membuat halaman depan kosong tanpa cara
mengembalikannya selain SQL manual. Judul dan isinya tetap bebas diubah.

**Submenu dibatasi satu tingkat.** Dropdown bertingkat-tingkat susah
dipakai di layar sentuh, dan CSS navigasi yang ada memang dirancang untuk
satu tingkat. Backend menolak submenu-dari-submenu, menu yang menjadi
induk bagi dirinya sendiri, dan pemindahan menu beranak menjadi submenu.

**Target menu di-allowlist, bukan teks bebas** (lihat `normalizeMenu`):
tipe `halaman` wajib menunjuk slug yang benar-benar ada, tipe `rute`
hanya boleh salah satu nama rute frontend yang terdaftar, tipe `url`
hanya menerima `http://`/`https://`. Alasannya sederhana: menu rusak
biasanya baru ketahuan setelah dikeluhkan pengunjung.

**Menghapus ikut merapikan.** Menghapus halaman ikut menghapus menu yang
menunjuknya; menghapus menu induk ikut menghapus submenunya. Keduanya
mencegah sisa data yang tidak mungkin terlihat tapi tetap bisa
membingungkan saat disunting.

### Cara memakai (superadmin)

1. Masuk sebagai superadmin, buka **Kelola Halaman** → buat halaman
   (mis. slug `tentang`), isi kontennya, set status **Publish**.
2. Buka **Kelola Menu** → **+ Menu Baru**: isi label, pilih tipe
   `Halaman`, isi target dengan slug tadi, atur urutan.
3. Untuk submenu: buat dulu satu menu bertipe **Induk** (mis. "Produk
   PkM"), lalu pada menu anak pilih induk tersebut di field **Induk**.
4. Halaman depan disunting lewat baris berslug `beranda` di Kelola
   Halaman — judul dan isinya bebas, slug-nya terkunci.

Seed awal sudah menyertakan halaman `beranda`, `tentang`, `cms-piawai`,
`lms-piawai`, `pos-piawai` serta menu Beranda / Produk PkM (3 submenu) /
Artikel / Penulis / Tentang, supaya situs tidak kosong pada deploy
pertama. Semuanya boleh diubah atau dihapus lewat panel admin.

## Pemetaan skema (POS → CMS)

| POS                          | CMS                                      |
|-------------------------------|------------------------------------------|
| `tenants` (toko)              | `cms` (akun CMS/penulis) — kolom `kodeCms` RANGKAP: kode login **dan** slug di URL publik |
| `users` (kasir/gudang/owner)  | `users` (penulis/owner/superadmin)       |
| `produk`, `lokasi`, `distribusi`, `transaksi`, `kontak`, `akun`, `jurnal`, dst. | **dihapus** |
| — | `post` (artikel) — baru |
| — | `komentar` (komentar publik per artikel) — baru |
| — | `halaman` (halaman statis situs, termasuk landing page) — baru |
| — | `menu` (navigasi publik + submenu satu tingkat) — baru |

## Endpoint backend (`cms-api`, semua query string)

- `GET/POST/PATCH/DELETE /api?table=&id=&cmsId=` — CRUD generik
  (aturan isolasi per-CMS tetap sama seperti versi POS). Tabel yang
  dikenal: `post`, `cms`, serta `halaman` & `menu` (khusus superadmin).
- `GET /public?view=home` — daftar CMS aktif (dipakai halaman Penulis).
- `GET /public?view=halaman&slug=<slug>` — satu halaman statis; tanpa
  `slug` mengembalikan halaman depan (`beranda`).
- `GET /public?view=menu` — pohon menu publik (induk + `children`).
- `GET /public?view=artikel-list` — 50 artikel publish terbaru dari
  SEMUA penulis, lengkap dengan `kodeCms` & nama penulisnya.
- `GET /public?view=profile&user=<kodeCms>` — profil + daftar artikel publish.
- `GET /public?view=artikel&user=<kodeCms>&slug=<slug>` — artikel + komentar.
- `GET /public?view=captcha` — soal captcha matematika baru (`{challenge, token}`), panggil sebelum login/registrasi.
- `POST /public?view=login` — `{kodeCms,username,password,captchaToken,captchaAnswer}` → `{token,expiresAt,user}`.
- `POST /public?view=register` — `{kodeCms,namaCms,bio,ownerName,username,password,captchaToken,captchaAnswer}` → `{token,expiresAt,user}`.
- `POST /public?view=komentar&user=<kodeCms>&slug=<slug>` — kirim komentar (butuh Bearer token).

Catatan: endpoint backend TIDAK ikut memakai bentuk "rapi" seperti URL
publik frontend. Backend adalah kontrak API antar-layanan — `view=profile`
sebagai pasangan key=value lebih mudah di-parse, di-log, dan diletakkan di
belakang API gateway ketimbang segmen posisional.

## Rute frontend (`cms-app`)

Publik: beranda `/` (landing page buatan admin), `?laman/<slug>`
(halaman statis lain), `?artikel` (daftar artikel semua penulis),
`?penulis` (daftar penulis), `?profile/<kodeCms>`,
`?user/<kodeCms>/<slug>` — semuanya di `pages/public.js`.

Admin (butuh login): `?login`, `?register`, `?dashboard`, `?editor`
(+ `/<idArtikel>` untuk mengedit), `?postingan`, `?profil` (edit profil
CMS sendiri), `?cms` (kelola semua CMS), `?halaman` (kelola halaman
situs), `?menu` (kelola menu/submenu) — tiga terakhir khusus superadmin.

Perhatikan pasangan rute yang sengaja dibedakan: `?artikel` adalah
DAFTAR artikel lintas-penulis, sedangkan SATU artikel tetap beralamat
`?user/<kodeCms>/<slug>`. Keduanya tidak bentrok karena rute artikel
tunggal memang sudah memakai prefiks `user` (lihat `ROUTE_PREFIX` di
`cms-app/engine.js`).

Perhatikan pasangan nama yang sengaja dibedakan: `?profile/<kodeCms>`
adalah halaman PUBLIK yang dilihat pengunjung, sedangkan `?profil`
adalah FORM EDIT halaman tersebut, khusus pemiliknya.

Catatan `robots.txt`: karena rute ada di query string, aturan lama
bergaya path (`Disallow: /dashboard`) tidak cocok dengan URL apa pun dan
sudah diganti bentuk query (`Disallow: /?dashboard`). `Allow: /?profile`
sengaja dicantumkan karena `Disallow: /?profil` juga mencocoki awalan
URL profil publik; aturan yang lebih panjang menang, jadi halaman publik
tetap boleh diindeks.

Tidak ada konsep "reserved slug" (kata terlarang untuk `kodeCms`) —
`kodeCms` tidak pernah jadi nama rute, dia selalu jadi nilai di dalam
query string publik, jadi tidak mungkin bentrok dengan rute admin.

## Yang SENGAJA belum digarap

- **Konten artikel = HTML mentah** (sama seperti sebelumnya).
- **Moderasi komentar**: kolom `status` di tabel `komentar` (default
  `approved`) belum ada UI moderasi.
- **`sitemap.xml`**: tanpa SSR, generatornya perlu jalan di sisi build/CI
  frontend (query `/public?view=home` + per-CMS), bukan di Worker.
- Keamanan `cmsId` di query string masih pola yang sama (lihat catatan
  di `worker.js`) — belum pakai sesi/JWT server-side.
- CORS backend masih `Access-Control-Allow-Origin: *` — untuk produksi,
  sebaiknya dibatasi ke domain frontend yang sebenarnya.
