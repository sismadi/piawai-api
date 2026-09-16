-- ============================================================
-- schema.sql — Skema Cloudflare D1 untuk PLATFORM CMS MULTI-USER
-- VERSI TER-HARDENING (lihat SECURITY.md & worker.js).
-- ============================================================
-- Perubahan dari versi sebelumnya:
--   * users.password (plaintext) -> users.passwordHash (PBKDF2-SHA256)
--   * users(cmsId, username) kini UNIQUE — mencegah dua akun identik
--     dalam satu CMS yang membuat hasil login ambigu.
--   * komentar.userId (wajib) — komentar hanya dari pengguna login,
--     identitasnya tertelusur; kolom `email` bebas-ketik dihapus.
--   * tabel baru rate_limit — penegakan lockout login/registrasi/komentar
--     di server (frontend-only lockout tidak menghentikan bot).
-- ============================================================

DROP TABLE IF EXISTS menu;
DROP TABLE IF EXISTS halaman;
DROP TABLE IF EXISTS rate_limit;
DROP TABLE IF EXISTS komentar;
DROP TABLE IF EXISTS post;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS cms;

-- ---------------------------------------------------------------
-- cms — tabel global. kodeCms = slug URL publik + kode login.
-- ---------------------------------------------------------------
CREATE TABLE cms (
  id        TEXT PRIMARY KEY,
  kodeCms   TEXT UNIQUE NOT NULL,
  nama      TEXT NOT NULL,
  bio       TEXT,
  avatarUrl TEXT,
  status    TEXT NOT NULL DEFAULT 'aktif',   -- aktif | nonaktif
  createdAt TEXT NOT NULL
);

-- ---------------------------------------------------------------
-- users — akun login per-CMS. TIDAK PERNAH dapat dibaca lewat /api
-- (lihat BLOCKED_TABLES di worker.js); hanya endpoint login/register
-- yang menyentuhnya, dan keduanya tidak pernah mengembalikan hash.
-- ---------------------------------------------------------------
CREATE TABLE users (
  id           TEXT PRIMARY KEY,
  cmsId        TEXT NOT NULL,
  username     TEXT NOT NULL,
  passwordHash TEXT NOT NULL,   -- format: pbkdf2$sha256$<iter>$<salt>$<hash>
  name         TEXT NOT NULL,
  role         TEXT NOT NULL DEFAULT 'owner',  -- superadmin | owner | penulis
  createdAt    TEXT NOT NULL
);
CREATE INDEX idx_users_cms ON users(cmsId);
CREATE UNIQUE INDEX idx_users_cms_username ON users(cmsId, username);

-- ---------------------------------------------------------------
-- post — artikel; slug unik PER CMS.
-- ---------------------------------------------------------------
CREATE TABLE post (
  id           TEXT PRIMARY KEY,
  cmsId        TEXT NOT NULL,
  slug         TEXT NOT NULL,
  judul        TEXT NOT NULL,
  ringkasan    TEXT,
  konten       TEXT NOT NULL DEFAULT '',   -- HTML, sudah di-sanitize server-side
  coverImage   TEXT,
  kategori     TEXT,
  tags         TEXT,
  status       TEXT NOT NULL DEFAULT 'draft',  -- draft | publish
  views        INTEGER DEFAULT 0,
  publishedAt  TEXT,
  createdAt    TEXT NOT NULL,
  updatedAt    TEXT NOT NULL
);
CREATE INDEX idx_post_cms ON post(cmsId);
CREATE UNIQUE INDEX idx_post_cms_slug ON post(cmsId, slug);
CREATE INDEX idx_post_cms_status ON post(cmsId, status, publishedAt);

-- ---------------------------------------------------------------
-- komentar — hanya dari pengguna yang login. `nama` & `userId` diisi
-- server dari token sesi, bukan dari body request.
-- ---------------------------------------------------------------
CREATE TABLE komentar (
  id        TEXT PRIMARY KEY,
  cmsId     TEXT NOT NULL,
  postId    TEXT NOT NULL,
  userId    TEXT NOT NULL,
  nama      TEXT NOT NULL,
  isi       TEXT NOT NULL,
  status    TEXT NOT NULL DEFAULT 'approved', -- approved | pending
  createdAt TEXT NOT NULL
);
CREATE INDEX idx_komentar_cms ON komentar(cmsId);
CREATE INDEX idx_komentar_post ON komentar(postId);
CREATE INDEX idx_komentar_user ON komentar(userId);

-- ---------------------------------------------------------------
-- rate_limit — penghitung percobaan per kunci (mis. "login:ip:1.2.3.4",
-- "login:acc:wawan:wawan", "komentar:<userId>"). Dibersihkan berkala:
--   DELETE FROM rate_limit WHERE blockedUntil < <now-ms> AND windowStart < <now-ms - 86400000>;
-- ---------------------------------------------------------------
-- ---------------------------------------------------------------
-- halaman — halaman statis SITUS (bukan milik satu CMS): landing page
-- dan halaman pendukungnya, dikelola superadmin.
--
-- Kenapa TIDAK ber-`cmsId` seperti `post`? Karena isinya adalah wajah
-- situs itu sendiri (piawai.id), bukan tulisan seorang penulis. Kalau
-- diberi cmsId, halaman depan situs jadi "milik" salah satu penulis dan
-- pertanyaan "halaman siapa yang tampil di /" tidak punya jawaban yang
-- pasti begitu ada penulis kedua.
--
-- slug 'beranda' ISTIMEWA: itulah yang dirender di URL "/" (lihat
-- resolveHome di cms-app/pages/public.js). Slug ini dikunci di worker.js
-- — tidak bisa diganti atau dihapus, supaya halaman depan tidak pernah
-- kosong karena salah klik.
-- ---------------------------------------------------------------
CREATE TABLE halaman (
  id         TEXT PRIMARY KEY,
  slug       TEXT UNIQUE NOT NULL,
  judul      TEXT NOT NULL,
  ringkasan  TEXT,
  konten     TEXT NOT NULL DEFAULT '',        -- HTML, sudah di-sanitize server-side
  coverImage TEXT,
  status     TEXT NOT NULL DEFAULT 'draft',   -- draft | publish
  urutan     INTEGER NOT NULL DEFAULT 0,
  createdAt  TEXT NOT NULL,
  updatedAt  TEXT NOT NULL
);
CREATE INDEX idx_halaman_status ON halaman(status, urutan);

-- ---------------------------------------------------------------
-- menu — navigasi publik situs. Mendukung SATU tingkat submenu lewat
-- `parentId` (menu induk -> anak). Dibatasi satu tingkat di worker.js:
-- dropdown bertingkat-tingkat susah dipakai di layar sentuh, dan CSS
-- navigasi yang ada (.nav-parent/.nav-children di cms-app/style.css)
-- memang dirancang untuk satu tingkat saja.
--
-- `tipe` menentukan arti kolom `target`:
--   halaman -> target = slug di tabel `halaman`   (mis. 'tentang')
--   rute    -> target = nama rute bawaan frontend (mis. 'artikel-list')
--   url     -> target = URL absolut http/https ke situs luar
--   induk   -> tanpa target; hanya wadah untuk submenu di bawahnya
-- ---------------------------------------------------------------
CREATE TABLE menu (
  id        TEXT PRIMARY KEY,
  parentId  TEXT,                              -- NULL = menu tingkat atas
  label     TEXT NOT NULL,
  tipe      TEXT NOT NULL DEFAULT 'halaman',    -- halaman | rute | url | induk
  target    TEXT,
  urutan    INTEGER NOT NULL DEFAULT 0,
  status    TEXT NOT NULL DEFAULT 'aktif',      -- aktif | nonaktif
  createdAt TEXT NOT NULL,
  updatedAt TEXT NOT NULL
);
CREATE INDEX idx_menu_parent ON menu(parentId, urutan);

CREATE TABLE rate_limit (
  key          TEXT PRIMARY KEY,
  count        INTEGER NOT NULL DEFAULT 0,
  windowStart  INTEGER NOT NULL,
  blockedUntil INTEGER NOT NULL DEFAULT 0
);

-- ============================================================
-- SEED DATA DEMO
-- Password di bawah sudah DALAM BENTUK HASH PBKDF2-SHA256 (100.000
-- iterasi — batas maksimal yang didukung WebCrypto Cloudflare Workers).
-- Plaintext-nya hanya untuk demo lokal — GANTI SEBELUM
-- PRODUKSI, dan hapus baris demo ini di lingkungan sungguhan.
--   superadmin / Sup3rAdmin!2026
--   wawan      / Wawan!Demo2026
-- (Cara membuat hash baru ada di README.md bagian "Membuat hash password".)
-- ============================================================
INSERT INTO cms (id, kodeCms, nama, bio, avatarUrl, status, createdAt) VALUES
 ('system',   'superadmin', 'Sistem (Superadmin)', '-', NULL, 'aktif', datetime('now')),
 ('cms_demo', 'wawan',      'Wawan', 'Pracademic — praktisi & akademisi. Menulis soal software, riset, dan hal-hal di antaranya.', NULL, 'aktif', datetime('now'));

INSERT INTO users (id, cmsId, username, passwordHash, name, role, createdAt) VALUES
 ('usr_super', 'system',   'superadmin', 'pbkdf2$sha256$100000$oYpuW3kiXWshL5LW3AtR2Q$MBRtyakD2M8_6YZ4GDgOwXDCrW9rCpWcpIy4Gvrm-Sk', 'Super Admin', 'superadmin', datetime('now')),
 ('usr_owner', 'cms_demo', 'wawan',      'pbkdf2$sha256$100000$cDzAvxJlnyReoWcKbPyw-Q$3N-07IxVjQ43SOSbMjQc3o7be_0OR_tpipp7akIdsUc',      'Wawan',       'owner',      datetime('now'));

INSERT INTO post (id, cmsId, slug, judul, ringkasan, konten, kategori, tags, status, views, publishedAt, createdAt, updatedAt) VALUES
 ('pst_1', 'cms_demo', 'selamat-datang',
   'Selamat Datang di CMS Ini',
   'Artikel pertama sebagai contoh — bisa dihapus atau diedit kapan saja.',
   '<p>Ini adalah artikel contoh. Konten disimpan sebagai HTML, jadi Anda bisa menulis paragraf, <strong>teks tebal</strong>, tautan, dan elemen HTML dasar lainnya langsung di editor.</p><p>Selamat menulis!</p>',
   'Umum', 'perkenalan,cms', 'publish', 0, datetime('now'), datetime('now'), datetime('now')),
 ('pst_2', 'cms_demo', 'draft-catatan-riset',
   'Draft: Catatan Riset (belum tayang)',
   'Contoh artikel berstatus draft — tidak tampil di halaman publik sampai dipublish.',
   '<p>Isi draft di sini.</p>',
   'Riset', 'draft', 'draft', 0, NULL, datetime('now'), datetime('now'));

-- ============================================================
-- SEED HALAMAN & MENU — isi awal situs piawai.id.
-- Semuanya bisa diubah/ditambah lewat menu admin "Kelola Halaman" &
-- "Kelola Menu" (superadmin); seed ini hanya supaya situs tidak kosong
-- pada deploy pertama.
-- ============================================================
INSERT INTO halaman (id, slug, judul, ringkasan, konten, coverImage, status, urutan, createdAt, updatedAt) VALUES
 ('hal_beranda', 'beranda', 'Piawai — Tiga Aplikasi PkM dalam Satu Ekosistem',
  'Landing page resmi CMS Piawai, LMS Piawai, dan POS Piawai.',
  '<h2>Tiga aplikasi, satu ekosistem</h2><p>Piawai adalah kumpulan aplikasi hasil kegiatan <strong>Pengabdian kepada Masyarakat (PkM)</strong> yang dirancang ringan, gratis, dan bisa langsung dipakai UMKM, sekolah, maupun komunitas.</p><h3>CMS Piawai</h3><p>Platform menulis multi-penulis: setiap orang memperoleh satu CMS sendiri lengkap dengan halaman publik, artikel, dan komentar.</p><h3>LMS Piawai</h3><p>Ruang belajar daring sederhana untuk pelatihan, kelas, dan materi terstruktur tanpa biaya lisensi.</p><h3>POS Piawai</h3><p>Aplikasi kasir dan pencatatan stok untuk usaha kecil, berjalan di peramban tanpa perlu perangkat khusus.</p><p>Telusuri tulisan terbaru di halaman <a href="/?artikel">Artikel</a>, atau kenali para kontributornya di halaman <a href="/?penulis">Penulis</a>.</p>',
  NULL, 'publish', 0, datetime('now'), datetime('now')),
 ('hal_tentang', 'tentang', 'Tentang Piawai',
  'Latar belakang, tujuan, dan cara ikut berkontribusi.',
  '<p>Piawai lahir dari kegiatan pengabdian kepada masyarakat: memindahkan hasil riset dan praktik rekayasa perangkat lunak menjadi alat yang benar-benar dipakai sehari-hari.</p><p>Ketiga aplikasi dikembangkan terbuka, berjalan di atas layanan gratis, dan dirawat sebagai bahan ajar sekaligus produk nyata.</p><h3>Ikut menulis</h3><p>Siapa pun boleh mendaftar, mendapat satu CMS sendiri, lalu menulis artikel yang tampil di halaman Artikel situs ini.</p>',
  NULL, 'publish', 10, datetime('now'), datetime('now')),
 ('hal_cms', 'cms-piawai', 'CMS Piawai', 'Platform menulis multi-penulis.',
  '<p><strong>CMS Piawai</strong> memberi setiap pengguna satu CMS pribadi: profil publik, artikel dengan status draft/publish, serta komentar dari pembaca yang sudah masuk.</p><p>Dibangun tanpa dependensi pihak ketiga — frontend statis, backend Cloudflare Worker + D1.</p>',
  NULL, 'publish', 20, datetime('now'), datetime('now')),
 ('hal_lms', 'lms-piawai', 'LMS Piawai', 'Ruang belajar daring sederhana.',
  '<p><strong>LMS Piawai</strong> menata materi pelatihan menjadi kelas, modul, dan penilaian ringkas, cukup untuk kebutuhan pelatihan komunitas maupun kelas kampus.</p>',
  NULL, 'publish', 30, datetime('now'), datetime('now')),
 ('hal_pos', 'pos-piawai', 'POS Piawai', 'Kasir dan stok untuk usaha kecil.',
  '<p><strong>POS Piawai</strong> mencatat penjualan, stok, dan laporan harian langsung dari peramban — tanpa mesin kasir khusus dan tanpa biaya langganan.</p>',
  NULL, 'publish', 40, datetime('now'), datetime('now'));

INSERT INTO menu (id, parentId, label, tipe, target, urutan, status, createdAt, updatedAt) VALUES
 ('mnu_beranda', NULL,          'Beranda',     'rute',    'home',        0,  'aktif', datetime('now'), datetime('now')),
 ('mnu_produk',  NULL,          'Produk PkM',  'induk',   NULL,          10, 'aktif', datetime('now'), datetime('now')),
 ('mnu_cms',     'mnu_produk',  'CMS Piawai',  'halaman', 'cms-piawai',  0,  'aktif', datetime('now'), datetime('now')),
 ('mnu_lms',     'mnu_produk',  'LMS Piawai',  'halaman', 'lms-piawai',  10, 'aktif', datetime('now'), datetime('now')),
 ('mnu_pos',     'mnu_produk',  'POS Piawai',  'halaman', 'pos-piawai',  20, 'aktif', datetime('now'), datetime('now')),
 ('mnu_artikel', NULL,          'Artikel',     'rute',    'artikel-list', 20, 'aktif', datetime('now'), datetime('now')),
 ('mnu_penulis', NULL,          'Penulis',     'rute',    'penulis',     30, 'aktif', datetime('now'), datetime('now')),
 ('mnu_tentang', NULL,          'Tentang',     'halaman', 'tentang',     40, 'aktif', datetime('now'), datetime('now'));
