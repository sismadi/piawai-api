-- ============================================================
-- migration_halaman_menu.sql — TAMBAHAN fitur Halaman & Menu untuk
-- database yang SUDAH berjalan.
-- ============================================================
-- Bedanya dengan schema.sql: berkas ini TIDAK memuat DROP TABLE apa pun,
-- jadi CMS, pengguna, artikel, dan komentar yang sudah ada tetap utuh.
-- Jalankan sekali saja:
--   wrangler d1 execute <NAMA_DB> --file=migration_halaman_menu.sql
-- Database yang baru dibuat dari schema.sql TIDAK perlu berkas ini —
-- isinya sudah termasuk di sana.
--
-- SUDAH PERNAH menjalankan versi berkas ini yang TANPA kolom
-- `tataLetak`/`blok`? Jalankan `migration_halaman_blok.sql` alih-alih
-- berkas ini — CREATE TABLE di bawah akan dilewati (tabelnya sudah ada)
-- sehingga kedua kolom baru itu tidak pernah ikut terbuat.
--
-- `IF NOT EXISTS` dipakai di semua pernyataan supaya menjalankan ulang
-- berkas ini tidak menggagalkan migrasi di tengah jalan; seed di bagian
-- bawah memakai INSERT OR IGNORE dengan id tetap, jadi baris yang sudah
-- ada tidak tergandakan dan hasil suntingan admin tidak tertimpa.
-- ============================================================

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
CREATE TABLE IF NOT EXISTS halaman (
  id         TEXT PRIMARY KEY,
  slug       TEXT UNIQUE NOT NULL,
  judul      TEXT NOT NULL,
  ringkasan  TEXT,
  konten     TEXT NOT NULL DEFAULT '',        -- HTML, sudah di-sanitize server-side
  coverImage TEXT,
  -- tataLetak menentukan MANA dari dua kolom isi di bawah yang dipakai:
  --   'konten' -> kolom `konten` (HTML bebas) — cocok untuk halaman teks
  --               panjang seperti "Tentang" atau kebijakan privasi.
  --   'seksi'  -> kolom `blok` (JSON) — dirender lewat komponen hero /
  --               features / articleFull di cms-app/engine.js, cocok untuk
  --               landing page yang butuh tampilan berblok, bukan teks lurus.
  -- Dua kolom sengaja dipertahankan (bukan satu kolom serbaguna) supaya
  -- berganti tata letak tidak menghapus isi yang sudah susah-susah ditulis
  -- dalam bentuk yang lain.
  tataLetak  TEXT NOT NULL DEFAULT 'konten',  -- konten | seksi
  blok       TEXT,                            -- JSON array seksi, divalidasi di worker.js
  status     TEXT NOT NULL DEFAULT 'draft',   -- draft | publish
  urutan     INTEGER NOT NULL DEFAULT 0,
  createdAt  TEXT NOT NULL,
  updatedAt  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_halaman_status ON halaman(status, urutan);

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
CREATE TABLE IF NOT EXISTS menu (
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
CREATE INDEX IF NOT EXISTS idx_menu_parent ON menu(parentId, urutan);

INSERT OR IGNORE INTO halaman (id, slug, judul, ringkasan, konten, coverImage, tataLetak, blok, status, urutan, createdAt, updatedAt) VALUES
 ('hal_beranda', 'beranda', 'Piawai — Tiga Aplikasi PkM dalam Satu Ekosistem',
  'Landing page resmi CMS Piawai, LMS Piawai, dan POS Piawai.',
  '<h2>Tiga aplikasi, satu ekosistem</h2><p>Piawai adalah kumpulan aplikasi hasil kegiatan <strong>Pengabdian kepada Masyarakat (PkM)</strong> yang dirancang ringan, gratis, dan bisa langsung dipakai UMKM, sekolah, maupun komunitas.</p><h3>CMS Piawai</h3><p>Platform menulis multi-penulis: setiap orang memperoleh satu CMS sendiri lengkap dengan halaman publik, artikel, dan komentar.</p><h3>LMS Piawai</h3><p>Ruang belajar daring sederhana untuk pelatihan, kelas, dan materi terstruktur tanpa biaya lisensi.</p><h3>POS Piawai</h3><p>Aplikasi kasir dan pencatatan stok untuk usaha kecil, berjalan di peramban tanpa perlu perangkat khusus.</p><p>Telusuri tulisan terbaru di halaman <a href="/?artikel">Artikel</a>, atau kenali para kontributornya di halaman <a href="/?penulis">Penulis</a>.</p>',
  NULL, 'seksi', '[{"section": "hero", "title": "Tiga Aplikasi PkM dalam Satu Ekosistem", "tagline": "Gratis, ringan, siap pakai", "description": "CMS Piawai, LMS Piawai, dan POS Piawai — hasil kegiatan Pengabdian kepada Masyarakat yang dirancang untuk UMKM, sekolah, dan komunitas.", "badges": ["Tanpa Biaya Lisensi", "Berjalan di Peramban", "Kode Terbuka"], "imgClass": "di-piawai", "cta": {"text": "Mulai Menulis di CMS Piawai", "link": "register"}}, {"section": "features", "items": [{"icon": "di-pen", "title": "CMS Piawai", "content": "Platform menulis multi-penulis: setiap orang memperoleh satu CMS sendiri, lengkap dengan halaman publik, artikel, dan komentar.", "linkText": "Selengkapnya", "linkTarget": "laman/cms-piawai"}, {"icon": "di-edu", "title": "LMS Piawai", "content": "Ruang belajar daring sederhana untuk pelatihan, kelas, dan materi terstruktur tanpa biaya lisensi.", "linkText": "Selengkapnya", "linkTarget": "laman/lms-piawai"}, {"icon": "di-cart", "title": "POS Piawai", "content": "Aplikasi kasir dan pencatatan stok untuk usaha kecil, berjalan di peramban tanpa perangkat khusus.", "linkText": "Selengkapnya", "linkTarget": "laman/pos-piawai"}, {"icon": "di-buku", "title": "Artikel Terbuka", "content": "Tulisan para kontributor dapat dibaca siapa saja, dengan alamat yang rapi dan mudah dibagikan.", "linkText": "Baca artikel", "linkTarget": "artikel-list"}, {"icon": "di-person", "title": "Banyak Penulis", "content": "Setiap penulis punya ruang datanya sendiri — tulisan tidak tercampur antar-akun.", "linkText": "Lihat penulis", "linkTarget": "penulis"}, {"icon": "di-code", "title": "Dikembangkan Terbuka", "content": "Dibangun tanpa dependensi pihak ketiga dan dirawat sebagai bahan ajar sekaligus produk nyata."}]}, {"section": "articleFull", "subtitle": "Mulai Sekarang", "lines": ["Siapa pun boleh mendaftar, mendapat satu CMS sendiri, lalu menulis artikel yang tampil di halaman Artikel situs ini.", "link:Daftarkan CMS Anda:register", "---", "link:Sudah punya akun? Masuk di sini:login"]}]', 'publish', 0, datetime('now'), datetime('now')),
 ('hal_tentang', 'tentang', 'Tentang Piawai',
  'Latar belakang, tujuan, dan cara ikut berkontribusi.',
  '<p>Piawai lahir dari kegiatan pengabdian kepada masyarakat: memindahkan hasil riset dan praktik rekayasa perangkat lunak menjadi alat yang benar-benar dipakai sehari-hari.</p><p>Ketiga aplikasi dikembangkan terbuka, berjalan di atas layanan gratis, dan dirawat sebagai bahan ajar sekaligus produk nyata.</p><h3>Ikut menulis</h3><p>Siapa pun boleh mendaftar, mendapat satu CMS sendiri, lalu menulis artikel yang tampil di halaman Artikel situs ini.</p>',
  NULL, 'konten', NULL, 'publish', 10, datetime('now'), datetime('now')),
 ('hal_cms', 'cms-piawai', 'CMS Piawai', 'Platform menulis multi-penulis.',
  '<p><strong>CMS Piawai</strong> memberi setiap pengguna satu CMS pribadi: profil publik, artikel dengan status draft/publish, serta komentar dari pembaca yang sudah masuk.</p><p>Dibangun tanpa dependensi pihak ketiga — frontend statis, backend Cloudflare Worker + D1.</p>',
  NULL, 'konten', NULL, 'publish', 20, datetime('now'), datetime('now')),
 ('hal_lms', 'lms-piawai', 'LMS Piawai', 'Ruang belajar daring sederhana.',
  '<p><strong>LMS Piawai</strong> menata materi pelatihan menjadi kelas, modul, dan penilaian ringkas, cukup untuk kebutuhan pelatihan komunitas maupun kelas kampus.</p>',
  NULL, 'konten', NULL, 'publish', 30, datetime('now'), datetime('now')),
 ('hal_pos', 'pos-piawai', 'POS Piawai', 'Kasir dan stok untuk usaha kecil.',
  '<p><strong>POS Piawai</strong> mencatat penjualan, stok, dan laporan harian langsung dari peramban — tanpa mesin kasir khusus dan tanpa biaya langganan.</p>',
  NULL, 'konten', NULL, 'publish', 40, datetime('now'), datetime('now'));

INSERT OR IGNORE INTO menu (id, parentId, label, tipe, target, urutan, status, createdAt, updatedAt) VALUES
 ('mnu_beranda', NULL,          'Beranda',     'rute',    'home',        0,  'aktif', datetime('now'), datetime('now')),
 ('mnu_produk',  NULL,          'Produk PkM',  'induk',   NULL,          10, 'aktif', datetime('now'), datetime('now')),
 ('mnu_cms',     'mnu_produk',  'CMS Piawai',  'halaman', 'cms-piawai',  0,  'aktif', datetime('now'), datetime('now')),
 ('mnu_lms',     'mnu_produk',  'LMS Piawai',  'halaman', 'lms-piawai',  10, 'aktif', datetime('now'), datetime('now')),
 ('mnu_pos',     'mnu_produk',  'POS Piawai',  'halaman', 'pos-piawai',  20, 'aktif', datetime('now'), datetime('now')),
 ('mnu_artikel', NULL,          'Artikel',     'rute',    'artikel-list', 20, 'aktif', datetime('now'), datetime('now')),
 ('mnu_penulis', NULL,          'Penulis',     'rute',    'penulis',     30, 'aktif', datetime('now'), datetime('now')),
 ('mnu_tentang', NULL,          'Tentang',     'halaman', 'tentang',     40, 'aktif', datetime('now'), datetime('now'));
