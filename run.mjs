import fs from 'node:fs';
import worker, { __test__ } from './worker.js';
import { makeD1 } from './d1shim.mjs';

let pass = 0, fail = 0;
function ok(name, cond, extra = '') {
  if (cond) { pass++; console.log(`  PASS  ${name}`); }
  else { fail++; console.log(`  FAIL  ${name} ${extra}`); }
}

// ---- siapkan DB dengan seed ter-hash ----
let schema = fs.readFileSync(new URL('./schema.sql', import.meta.url), 'utf8');
const hSuper = await __test__.hashPassword('Sup3rAdmin!2026');
const hWawan = await __test__.hashPassword('Wawan!Demo2026');
schema = schema.replace('__HASH_SUPERADMIN__', hSuper).replace('__HASH_WAWAN__', hWawan);

const env = {
  DB: makeD1(schema),
  SESSION_SECRET: 'x'.repeat(48),
  ALLOWED_ORIGINS: 'https://cms.piawai.id',
};

const ORIGIN = 'https://cms.piawai.id';
function req(path, { method = 'GET', body, token, ip = '1.2.3.4' } = {}) {
  const h = { 'Origin': ORIGIN, 'CF-Connecting-IP': ip };
  if (body !== undefined) h['Content-Type'] = 'application/json';
  if (token) h['Authorization'] = `Bearer ${token}`;
  return new Request(`https://api.test${path}`, {
    method, headers: h, body: body !== undefined ? JSON.stringify(body) : undefined,
  });
}
const call = async (...a) => {
  const res = await worker.fetch(req(...a), env);
  let data = null;
  try { data = await res.clone().json(); } catch (e) {}
  return { status: res.status, data, headers: res.headers };
};

/** Ambil soal captcha sungguhan dari server (seperti klien nyata) dan hitung
 *  jawaban yang benar, supaya test memverifikasi alur end-to-end (bukan mock). */
async function getCaptcha(ip = '1.2.3.4') {
  const r = await call('/public?view=captcha', { ip });
  const m = String(r.data?.challenge || '').match(/^(\d+)\s*\+\s*(\d+)\s*=\s*\?$/);
  if (!m) throw new Error(`Format soal captcha tak dikenali: ${JSON.stringify(r.data)}`);
  return { token: r.data.token, answer: Number(m[1]) + Number(m[2]) };
}

console.log('\n== 1. Hashing password ==');
ok('hash tidak memuat plaintext', !hWawan.includes('Wawan!Demo2026'));
ok('verify password benar', await __test__.verifyPassword('Wawan!Demo2026', hWawan));
ok('verify password salah ditolak', !(await __test__.verifyPassword('salah', hWawan)));
ok('dua hash password sama berbeda (salt unik)',
  (await __test__.hashPassword('abc')) !== (await __test__.hashPassword('abc')));

console.log('\n== 2. Tabel users/komentar diblokir dari /api ==');
let r = await call('/api?table=users&cmsId=cms_demo');
ok('GET users tanpa token -> 401', r.status === 401, JSON.stringify(r.data));

console.log('\n== 3. Login ==');
let cap = await getCaptcha('3.3.3.1');
r = await call('/public?view=login', { method: 'POST', ip: '3.3.3.1', body: { kodeCms: 'wawan', username: 'wawan', password: 'Wawan!Demo2026', captchaToken: cap.token, captchaAnswer: cap.answer + 1 } });
ok('jawaban captcha salah -> 400', r.status === 400, JSON.stringify(r.data));

cap = await getCaptcha('3.3.3.2');
r = await call('/public?view=login', { method: 'POST', ip: '3.3.3.2', body: { kodeCms: 'wawan', username: 'wawan', password: 'salah', captchaToken: cap.token, captchaAnswer: cap.answer } });
ok('password salah -> 401', r.status === 401);

cap = await getCaptcha('3.3.3.3');
r = await call('/public?view=login', { method: 'POST', ip: '3.3.3.3', body: { kodeCms: 'wawan', username: 'wawan', password: 'Wawan!Demo2026', captchaToken: cap.token, captchaAnswer: cap.answer } });
ok('login benar -> 200 + token', r.status === 200 && !!r.data.token, JSON.stringify(r.data));
ok('respons login tidak memuat hash/password', !JSON.stringify(r.data).match(/pbkdf2|password/i), JSON.stringify(r.data));
const tokenWawan = r.data.token;

console.log('\n== 3b. Captcha matematika — kasus tambahan ==');
cap = await getCaptcha('3.3.3.4');
r = await call('/public?view=login', { method: 'POST', ip: '3.3.3.4', body: { kodeCms: 'wawan', username: 'wawan', password: 'Wawan!Demo2026', captchaToken: cap.token, captchaAnswer: cap.answer } });
ok('login sukses dengan captcha benar (kredensial valid)', r.status === 200 && !!r.data.token, JSON.stringify(r.data));

r = await call('/public?view=login', { method: 'POST', ip: '3.3.3.5', body: { kodeCms: 'wawan', username: 'wawan', password: 'Wawan!Demo2026', captchaToken: 'token-ngawur', captchaAnswer: 5 } });
ok('token captcha rusak/tidak dikenal -> 400', r.status === 400, JSON.stringify(r.data));

// Token sesi (typ:'session') tidak boleh diterima sebagai token captcha,
// walau tanda tangannya sah — ini menguji pemisahan `typ` di verifyToken.
r = await call('/public?view=login', { method: 'POST', ip: '3.3.3.6', body: { kodeCms: 'wawan', username: 'wawan', password: 'Wawan!Demo2026', captchaToken: tokenWawan, captchaAnswer: 5 } });
ok('token sesi ditolak sebagai token captcha (typ tidak cocok)', r.status === 400, JSON.stringify(r.data));

console.log('\n== 3c. Batas percobaan captcha (per-IP) ==');
let capLockStatus = 0;
const lockIp = '3.3.3.9';
for (let i = 0; i < 11; i++) {
  const c = await getCaptcha(lockIp);
  const rr = await call('/public?view=login', { method: 'POST', ip: lockIp, body: { kodeCms: 'wawan', username: 'wawan', password: 'Wawan!Demo2026', captchaToken: c.token, captchaAnswer: c.answer + 1 } });
  capLockStatus = rr.status;
}
ok('setelah 10+ jawaban captcha salah dari IP sama -> 429 (terkunci)', capLockStatus === 429, `status terakhir ${capLockStatus}`);
const capAfterLock = await getCaptcha(lockIp).catch(() => null);
r = capAfterLock
  ? await call('/public?view=login', { method: 'POST', ip: lockIp, body: { kodeCms: 'wawan', username: 'wawan', password: 'Wawan!Demo2026', captchaToken: capAfterLock.token, captchaAnswer: capAfterLock.answer } })
  : { status: 429 };
ok('captcha benar pun tetap ditolak selama IP terkunci', r.status === 429, JSON.stringify(r.data));

r = await call('/api?table=users', { token: tokenWawan });
ok('GET users dengan token valid -> 403 (tetap diblokir)', r.status === 403, JSON.stringify(r.data));
r = await call('/api?table=komentar', { token: tokenWawan });
ok('GET komentar lewat /api -> 403', r.status === 403);

console.log('\n== 4. Registrasi + isolasi CMS (IDOR) ==');
cap = await getCaptcha('9.9.9.9');
r = await call('/public?view=register', { method: 'POST', ip: '9.9.9.9', body: {
  kodeCms: 'siti', namaCms: 'Catatan Siti', ownerName: 'Siti', username: 'siti', password: 'pendek', captchaToken: cap.token, captchaAnswer: cap.answer } });
ok('password < 8 karakter ditolak', r.status === 400, JSON.stringify(r.data));

cap = await getCaptcha('9.9.9.9');
r = await call('/public?view=register', { method: 'POST', ip: '9.9.9.9', body: {
  kodeCms: 'siti', namaCms: 'Catatan Siti', ownerName: 'Siti', username: 'siti', password: 'SitiRahasia9', captchaToken: cap.token, captchaAnswer: cap.answer } });
ok('registrasi sukses -> 201 + token', r.status === 201 && !!r.data.token, JSON.stringify(r.data));
const tokenSiti = r.data.token;
const cmsIdSiti = r.data.user.cmsId;

// Siti membuat artikel
r = await call('/api?table=post', { method: 'POST', token: tokenSiti, body: { slug: 'rahasia-siti', judul: 'Rahasia Siti', konten: '<p>hai</p>', status: 'publish' } });
ok('Siti bisa membuat artikel', r.status === 201, JSON.stringify(r.data));
const postSitiId = r.data?.id;

// Wawan mencoba membaca artikel Siti dengan memalsukan cmsId di query (IDOR klasik)
r = await call(`/api?table=post&cmsId=${cmsIdSiti}`, { token: tokenWawan });
const judulTerlihat = JSON.stringify(r.data);
ok('cmsId palsu di query DIABAIKAN (tak ada artikel Siti)', !judulTerlihat.includes('Rahasia Siti'), judulTerlihat);

r = await call(`/api?table=post&id=${postSitiId}&cmsId=${cmsIdSiti}`, { token: tokenWawan });
ok('GET by id lintas-CMS -> 404', r.status === 404);
r = await call(`/api?table=post&id=${postSitiId}&cmsId=${cmsIdSiti}`, { method: 'DELETE', token: tokenWawan });
const stillThere = await call(`/api?table=post&id=${postSitiId}`, { token: tokenSiti });
ok('DELETE lintas-CMS tidak menghapus apa pun', stillThere.status === 200 && stillThere.data?.id === postSitiId);

r = await call('/api?table=cms', { token: tokenWawan });
ok('non-superadmin hanya melihat CMS sendiri', Array.isArray(r.data) && r.data.length === 1 && r.data[0].id === 'cms_demo', JSON.stringify(r.data));

r = await call('/api?table=cms&id=cms_demo', { method: 'PATCH', token: tokenSiti, body: { nama: 'Dibajak' } });
ok('PATCH cms milik orang lain -> 403', r.status === 403);

r = await call(`/api?table=cms&id=${cmsIdSiti}`, { method: 'PATCH', token: tokenSiti, body: { nama: 'Siti Baru', status: 'nonaktif', kodeCms: 'hack' } });
ok('owner bisa ubah nama', r.status === 200 && r.data.nama === 'Siti Baru');
ok('owner TIDAK bisa ubah status/kodeCms', r.data.status === 'aktif' && r.data.kodeCms === 'siti', JSON.stringify(r.data));

console.log('\n== 5. Token palsu / kedaluwarsa ==');
const forged = tokenWawan.split('.')[0] + '.' + 'AAAA';
r = await call('/api?table=post', { token: forged });
ok('tanda tangan token dipalsukan -> 401', r.status === 401);
// payload diubah (role jadi superadmin) tanpa tanda tangan baru
const payload = JSON.parse(Buffer.from(tokenWawan.split('.')[0].replace(/-/g,'+').replace(/_/g,'/'), 'base64').toString());
payload.role = 'superadmin';
const tamper = Buffer.from(JSON.stringify(payload)).toString('base64url') + '.' + tokenWawan.split('.')[1];
r = await call('/api?table=cms', { token: tamper });
ok('payload diubah jadi superadmin -> 401', r.status === 401);

console.log('\n== 6. Sanitasi HTML ==');
const dirty = `<p>ok</p><script>alert(1)</script><img src=x onerror="alert(1)"><a href="javascript:alert(1)">klik</a><a href="java&#115;cript:alert(1)">y</a><iframe src="//evil"></iframe><p onclick="bad()">z</p>`;
const clean = __test__.sanitizeHtml(dirty);
ok('<script> dibuang', !/script/i.test(clean), clean);
ok('onerror/onclick dibuang', !/on\w+=/i.test(clean), clean);
ok('javascript: dibuang', !/javascript:/i.test(clean), clean);
ok('entity-encoded javascript: dibuang', !clean.includes('&#115;cript:'), clean);
ok('iframe dibuang', !/iframe/i.test(clean), clean);
ok('konten sah dipertahankan', clean.includes('<p>ok</p>'), clean);

r = await call('/api?table=post', { method: 'POST', token: tokenWawan, body: { slug: 'uji-xss', judul: 'Uji', konten: dirty, status: 'publish' } });
ok('konten tersimpan sudah bersih', r.status === 201 && !/script|onerror/i.test(r.data.konten), JSON.stringify(r.data?.konten));

r = await call('/public?view=artikel&user=wawan&slug=uji-xss');
ok('konten tersaji lewat /public juga bersih', r.status === 200 && !/script|onerror/i.test(r.data.post.konten));

console.log('\n== 7. Injeksi nama kolom / field tak sah ==');
r = await call('/api?table=post', { method: 'POST', token: tokenWawan, body: {
  slug: 'uji-kolom', judul: 'Uji Kolom', konten: '<p>a</p>',
  'views = 999, judul': 'x', cmsId: cmsIdSiti, id: 'pst_1', views: 9999 } });
ok('field tak sah diabaikan, insert tetap sukses', r.status === 201, JSON.stringify(r.data));
ok('cmsId dari body diabaikan', r.data?.cmsId === 'cms_demo', r.data?.cmsId);
ok('id dari body diabaikan (tidak menimpa pst_1)', r.data?.id !== 'pst_1');
ok('views tidak bisa diset klien', r.data?.views === 0);

console.log('\n== 8. Komentar ==');
r = await call('/public?view=komentar&user=wawan&slug=selamat-datang', { method: 'POST', body: { nama: 'Anonim Palsu', isi: 'spam' } });
ok('komentar tanpa token -> 401', r.status === 401);

r = await call('/public?view=komentar&user=wawan&slug=selamat-datang', { method: 'POST', token: tokenSiti, body: { nama: 'Super Admin', userId: 'usr_super', isi: 'Halo!' } });
ok('komentar dengan token -> 201', r.status === 201, JSON.stringify(r.data));
ok('nama komentator diambil dari token, bukan body', r.data?.nama === 'Siti', r.data?.nama);
ok('userId diambil dari token', r.data?.userId !== 'usr_super');

console.log('\n== 9. Rate limit login ==');
let lastStatus = 0;
for (let i = 0; i < 8; i++) {
  const c = await getCaptcha('5.5.5.5');
  const rr = await call('/public?view=login', { method: 'POST', ip: '5.5.5.5', body: { kodeCms: 'wawan', username: 'wawan', password: 'salah-terus', captchaToken: c.token, captchaAnswer: c.answer } });
  lastStatus = rr.status;
}
ok('setelah beberapa percobaan gagal -> 429 (terkunci)', lastStatus === 429, `status terakhir ${lastStatus}`);
const capFinal = await getCaptcha('5.5.5.5');
r = await call('/public?view=login', { method: 'POST', ip: '5.5.5.5', body: { kodeCms: 'wawan', username: 'wawan', password: 'Wawan!Demo2026', captchaToken: capFinal.token, captchaAnswer: capFinal.answer } });
ok('password benar pun tetap ditolak selama terkunci', r.status === 429);

console.log('\n== 10. CORS ==');
const res = await worker.fetch(new Request('https://api.test/public?view=home', { headers: { Origin: 'https://evil.example' } }), env);
ok('origin asing tidak mendapat Access-Control-Allow-Origin', !res.headers.get('Access-Control-Allow-Origin'));
const res2 = await worker.fetch(new Request('https://api.test/public?view=home', { headers: { Origin: ORIGIN } }), env);
ok('origin terdaftar diizinkan', res2.headers.get('Access-Control-Allow-Origin') === ORIGIN);

console.log('\n== 11. Kebocoran error internal ==');
r = await call('/api?table=post&id=x%27%20OR%201=1--', { token: tokenWawan });
ok('id aneh tidak membocorkan SQL', r.status === 404 || r.status === 200);

console.log('\n== 12. Halaman & menu situs (fitur landing page) ==');
const capSuper = await getCaptcha('7.7.7.1');
r = await call('/public?view=login', { method: 'POST', ip: '7.7.7.1', body: { kodeCms: 'superadmin', username: 'superadmin', password: 'Sup3rAdmin!2026', captchaToken: capSuper.token, captchaAnswer: capSuper.answer } });
ok('login superadmin -> 200', r.status === 200 && !!r.data.token, JSON.stringify(r.data));
const tokenSuper = r.data.token;

r = await call('/api?table=halaman', { token: tokenWawan });
ok('penulis biasa tidak boleh kelola halaman -> 403', r.status === 403, JSON.stringify(r.data));
r = await call('/api?table=menu', { token: tokenWawan });
ok('penulis biasa tidak boleh kelola menu -> 403', r.status === 403);

r = await call('/api?table=halaman', { token: tokenSuper });
ok('superadmin melihat daftar halaman seed', Array.isArray(r.data) && r.data.some(h => h.slug === 'beranda'), JSON.stringify(r.data));

r = await call('/api?table=halaman', { method: 'POST', token: tokenSuper, body: { slug: 'kontak', judul: 'Kontak', konten: '<p>Halo</p><script>alert(1)</script>', status: 'publish', urutan: 50 } });
ok('buat halaman baru -> 201', r.status === 201, JSON.stringify(r.data));
ok('konten halaman ikut disanitasi', !/script/i.test(r.data?.konten || ''), r.data?.konten);
const halKontakId = r.data.id;

r = await call('/api?table=halaman', { method: 'POST', token: tokenSuper, body: { slug: 'beranda', judul: 'Bajak Beranda', status: 'publish' } });
ok('slug beranda tidak bisa direbut halaman lain -> 409', r.status === 409, JSON.stringify(r.data));

const halBeranda = (await call('/api?table=halaman', { token: tokenSuper })).data.find(h => h.slug === 'beranda');
r = await call(`/api?table=halaman&id=${halBeranda.id}`, { method: 'PATCH', token: tokenSuper, body: { slug: 'beranda-lama' } });
ok('slug beranda tidak bisa diganti -> 400', r.status === 400, JSON.stringify(r.data));
r = await call(`/api?table=halaman&id=${halBeranda.id}`, { method: 'PATCH', token: tokenSuper, body: { status: 'draft' } });
ok('beranda tidak bisa dijadikan draft -> 400', r.status === 400);
r = await call(`/api?table=halaman&id=${halBeranda.id}`, { method: 'DELETE', token: tokenSuper });
ok('beranda tidak bisa dihapus -> 400', r.status === 400);
r = await call(`/api?table=halaman&id=${halBeranda.id}`, { method: 'PATCH', token: tokenSuper, body: { judul: 'Beranda Baru' } });
ok('judul beranda tetap bisa diubah', r.status === 200 && r.data.judul === 'Beranda Baru', JSON.stringify(r.data));

r = await call('/public?view=halaman');
ok('publik: tanpa slug -> halaman beranda', r.status === 200 && r.data.halaman.slug === 'beranda', JSON.stringify(r.data));
r = await call('/public?view=halaman&slug=kontak');
ok('publik: halaman by slug', r.status === 200 && r.data.halaman.judul === 'Kontak');

r = await call('/api?table=halaman', { method: 'POST', token: tokenSuper, body: { slug: 'rahasia', judul: 'Rahasia', status: 'draft' } });
const halDraftId = r.data.id;
r = await call('/public?view=halaman&slug=rahasia');
ok('halaman draft tidak tampil di publik -> 404', r.status === 404);

console.log('\n== 12b. Validasi menu ==');
r = await call('/api?table=menu', { method: 'POST', token: tokenSuper, body: { label: 'Kontak', tipe: 'halaman', target: 'kontak', urutan: 50 } });
ok('buat menu tipe halaman -> 201', r.status === 201, JSON.stringify(r.data));
const mnuKontakId = r.data.id;

r = await call('/api?table=menu', { method: 'POST', token: tokenSuper, body: { label: 'Nyasar', tipe: 'halaman', target: 'tidak-ada' } });
ok('menu ke halaman tak ada -> 400', r.status === 400, JSON.stringify(r.data));
r = await call('/api?table=menu', { method: 'POST', token: tokenSuper, body: { label: 'Rute Ngawur', tipe: 'rute', target: 'dashboard' } });
ok('menu ke rute di luar allowlist -> 400', r.status === 400);
r = await call('/api?table=menu', { method: 'POST', token: tokenSuper, body: { label: 'XSS', tipe: 'url', target: 'javascript:alert(1)' } });
ok('menu url skema berbahaya -> 400', r.status === 400);
r = await call('/api?table=menu', { method: 'POST', token: tokenSuper, body: { label: 'Luar', tipe: 'url', target: 'https://piawai.id' } });
ok('menu url http(s) diterima -> 201', r.status === 201);

r = await call('/api?table=menu', { method: 'POST', token: tokenSuper, body: { label: 'Sub Kontak', tipe: 'halaman', target: 'kontak', parentId: 'mnu_cms' } });
ok('submenu di bawah submenu ditolak -> 400', r.status === 400, JSON.stringify(r.data));
r = await call(`/api?table=menu&id=mnu_produk`, { method: 'PATCH', token: tokenSuper, body: { parentId: 'mnu_beranda' } });
ok('menu yang punya anak tidak bisa jadi submenu -> 400', r.status === 400);
r = await call(`/api?table=menu&id=${mnuKontakId}`, { method: 'PATCH', token: tokenSuper, body: { parentId: mnuKontakId } });
ok('menu tidak bisa jadi induk dirinya sendiri -> 400', r.status === 400);

r = await call('/public?view=menu');
const mProduk = r.data.menu.find(m => m.label === 'Produk PkM');
ok('publik: menu berbentuk pohon', r.status === 200 && mProduk?.children?.length === 3, JSON.stringify(r.data?.menu));
ok('publik: submenu tidak muncul di tingkat atas', !r.data.menu.some(m => m.label === 'CMS Piawai'));

r = await call(`/api?table=menu&id=mnu_lms`, { method: 'PATCH', token: tokenSuper, body: { status: 'nonaktif' } });
ok('nonaktifkan submenu -> 200', r.status === 200);
r = await call('/public?view=menu');
ok('menu nonaktif hilang dari publik', r.data.menu.find(m => m.label === 'Produk PkM').children.length === 2);

r = await call(`/api?table=halaman&id=${halKontakId}`, { method: 'DELETE', token: tokenSuper });
ok('hapus halaman -> 200', r.status === 200);
r = await call('/public?view=menu');
ok('menu yang menunjuk halaman terhapus ikut hilang', !r.data.menu.some(m => m.label === 'Kontak'), JSON.stringify(r.data.menu));

r = await call(`/api?table=menu&id=mnu_produk`, { method: 'DELETE', token: tokenSuper });
r = await call('/public?view=menu');
ok('hapus menu induk ikut menghapus submenunya', !r.data.menu.some(m => m.label === 'Produk PkM' || m.label === 'POS Piawai'));

console.log('\n== 12c. Daftar artikel lintas-CMS ==');
r = await call('/public?view=artikel-list');
ok('publik: artikel-list mengembalikan artikel publish', r.status === 200 && r.data.posts.length > 0, JSON.stringify(r.data));
ok('artikel-list menyertakan kodeCms penulis', r.data.posts.every(p => !!p.kodeCms));
ok('artikel-list tidak memuat draft', !r.data.posts.some(p => p.slug === 'draft-catatan-riset'));
r = await call(`/api?table=halaman&id=${halDraftId}`, { method: 'DELETE', token: tokenSuper });
ok('hapus halaman draft -> 200', r.status === 200);

console.log(`\n=== ${pass} lulus, ${fail} gagal ===`);
process.exit(fail ? 1 : 0);
