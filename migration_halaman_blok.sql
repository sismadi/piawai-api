-- ============================================================
-- migration_halaman_blok.sql — HANYA untuk database yang sudah punya
-- tabel `halaman` & `menu` dari versi sebelumnya.
-- ============================================================
-- Menambahkan dua kolom yang dipakai landing page berbasis seksi
-- (hero / features / articleFull) dan mengisi halaman depan bawaan.
-- Database baru (schema.sql) maupun yang belum pernah dimigrasi sama
-- sekali (migration_halaman_menu.sql) TIDAK perlu berkas ini.
--
-- SQLite tidak punya "ADD COLUMN IF NOT EXISTS": menjalankan berkas ini
-- dua kali akan gagal dengan "duplicate column name" — itu aman
-- (tidak ada data yang berubah), cukup abaikan pesannya.
--   wrangler d1 execute <NAMA_DB> --file=migration_halaman_blok.sql
-- ============================================================

ALTER TABLE halaman ADD COLUMN tataLetak TEXT NOT NULL DEFAULT 'konten';
ALTER TABLE halaman ADD COLUMN blok TEXT;

-- Jadikan halaman depan bawaan memakai tata letak seksi. Kalau Anda sudah
-- menyunting sendiri halaman depannya, hapus dua pernyataan di bawah ini
-- sebelum menjalankan berkas ini.
UPDATE halaman SET tataLetak = 'seksi', blok = '[{"section": "hero", "title": "Tiga Aplikasi PkM dalam Satu Ekosistem", "tagline": "Gratis, ringan, siap pakai", "description": "CMS Piawai, LMS Piawai, dan POS Piawai — hasil kegiatan Pengabdian kepada Masyarakat yang dirancang untuk UMKM, sekolah, dan komunitas.", "badges": ["Tanpa Biaya Lisensi", "Berjalan di Peramban", "Kode Terbuka"], "imgClass": "di-piawai", "cta": {"text": "Mulai Menulis di CMS Piawai", "link": "register"}}, {"section": "features", "items": [{"icon": "di-pen", "title": "CMS Piawai", "content": "Platform menulis multi-penulis: setiap orang memperoleh satu CMS sendiri, lengkap dengan halaman publik, artikel, dan komentar.", "linkText": "Selengkapnya", "linkTarget": "laman/cms-piawai"}, {"icon": "di-edu", "title": "LMS Piawai", "content": "Ruang belajar daring sederhana untuk pelatihan, kelas, dan materi terstruktur tanpa biaya lisensi.", "linkText": "Selengkapnya", "linkTarget": "laman/lms-piawai"}, {"icon": "di-cart", "title": "POS Piawai", "content": "Aplikasi kasir dan pencatatan stok untuk usaha kecil, berjalan di peramban tanpa perangkat khusus.", "linkText": "Selengkapnya", "linkTarget": "laman/pos-piawai"}, {"icon": "di-buku", "title": "Artikel Terbuka", "content": "Tulisan para kontributor dapat dibaca siapa saja, dengan alamat yang rapi dan mudah dibagikan.", "linkText": "Baca artikel", "linkTarget": "artikel-list"}, {"icon": "di-person", "title": "Banyak Penulis", "content": "Setiap penulis punya ruang datanya sendiri — tulisan tidak tercampur antar-akun.", "linkText": "Lihat penulis", "linkTarget": "penulis"}, {"icon": "di-code", "title": "Dikembangkan Terbuka", "content": "Dibangun tanpa dependensi pihak ketiga dan dirawat sebagai bahan ajar sekaligus produk nyata."}]}, {"section": "articleFull", "subtitle": "Mulai Sekarang", "lines": ["Siapa pun boleh mendaftar, mendapat satu CMS sendiri, lalu menulis artikel yang tampil di halaman Artikel situs ini.", "link:Daftarkan CMS Anda:register", "---", "link:Sudah punya akun? Masuk di sini:login"]}]'
 WHERE slug = 'beranda' AND blok IS NULL;
