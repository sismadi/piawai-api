// ============================================================
// worker.js — API BACKEND CMS MULTI-USER (Cloudflare Worker + D1)
// VERSI TER-HARDENING — menutup temuan di SECURITY.md (repo cms-app).
// ============================================================
// Ringkas perubahan keamanan dibanding versi sebelumnya:
//
//  1. Password TIDAK PERNAH keluar dari server. Tabel `users` dan
//     `komentar` diblokir total dari CRUD generik /api. Satu-satunya
//     jalan autentikasi adalah POST /public?view=login|register.
//  2. Password disimpan sebagai hash PBKDF2-SHA256 (salt per-user,
//     210.000 iterasi) — kolom `users.passwordHash`, bukan `password`.
//  3. Otorisasi TIDAK lagi memercayai `cmsId`/`role` dari klien.
//     Keduanya diturunkan dari token sesi HMAC-SHA256 yang
//     diverifikasi di server (header `Authorization: Bearer <token>`).
//     Parameter `cmsId` di query string diabaikan sepenuhnya.
//  4. Captcha matematika kustom (mis. "4 + 7 = ?") diverifikasi di
//     server sebelum login/registrasi diproses — soal + jawaban
//     ditandatangani HMAC (typ:'captcha', lihat signToken/verifyToken),
//     jadi tidak perlu tabel/state baru. Menggantikan Cloudflare
//     Turnstile: tanpa dependensi pihak ketiga, tanpa script eksternal
//     yang bisa diblokir ad-blocker, tanpa secret tambahan (reuse
//     SESSION_SECRET). Percobaan jawaban salah dibatasi lewat
//     `rate_limit` yang sama seperti poin 5.
//  5. Rate limiting nyata di D1 (tabel `rate_limit`): per-IP dan
//     per-akun untuk login/registrasi, per-user untuk komentar, per-IP
//     untuk percobaan captcha.
//  6. `post.konten` di-sanitize di server (allowlist) saat disimpan
//     DAN saat disajikan lewat /public — jadi konsumen API lain
//     (mobile app, integrasi pihak ketiga) ikut terlindungi.
//  7. Nama kolom di INSERT/UPDATE di-allowlist. Versi lama merakit
//     `INSERT INTO t (${Object.keys(body)})` dari body klien —
//     itu injeksi SQL lewat nama kolom, bukan cuma masalah data.
//  8. CORS tidak lagi `*`: hanya origin yang terdaftar (ALLOWED_ORIGINS).
//
// Secret/variable yang WAJIB di-set (lihat README.md):
//   wrangler secret put SESSION_SECRET
//   (opsional) vars ALLOWED_ORIGINS = "https://cms.piawai.id"
// ============================================================

// ------------------------------------------------------------
// Konfigurasi
// ------------------------------------------------------------
const SESSION_TTL_MS = 12 * 60 * 60 * 1000;      // 12 jam
// Runtime Cloudflare Workers (WebCrypto) MEMBATASI PBKDF2 maksimal
// 100.000 iterasi (di atas itu subtle.deriveBits melempar
// NotSupportedError). 210.000 adalah rekomendasi OWASP untuk server
// Node biasa, tapi tidak didukung di Workers — pakai batas maksimal
// yang didukung Workers sebagai gantinya.
const PBKDF2_ITERATIONS = 100_000;
const SLUG_RE = /^[a-z0-9][a-z0-9-]{1,29}$/;
const USERNAME_RE = /^[A-Za-z0-9._-]{3,40}$/;
// Frontend kini dideploy sebagai situs utama `piawai.id` (landing page +
// halaman buatan admin + CMS multi-penulis). `cms.piawai.id` tetap
// didaftarkan supaya deployment lama yang masih hidup tidak langsung
// kehilangan akses API saat domainnya dipindahkan.
const DEFAULT_ORIGINS = [
  'https://piawai.id',
  'https://www.piawai.id',
  'https://cms.piawai.id',
  'http://localhost:8080',
  'http://127.0.0.1:8080',
];

// Tabel yang TIDAK BOLEH disentuh lewat CRUD generik /api sama sekali.
// `users` memuat kredensial; `komentar` hanya boleh lewat endpoint
// publik yang mengambil identitas dari token.
const BLOCKED_TABLES = new Set(['users', 'komentar']);

// Kolom yang boleh ditulis klien, per tabel. Apa pun di luar daftar ini
// dibuang diam-diam — termasuk `id`, `cmsId`, `views` yang ditentukan server.
const WRITABLE_COLUMNS = {
  post: ['slug', 'judul', 'ringkasan', 'konten', 'coverImage', 'kategori', 'tags', 'status', 'publishedAt'],
  cms: ['nama', 'bio', 'avatarUrl'],
  halaman: ['slug', 'judul', 'ringkasan', 'konten', 'coverImage', 'status', 'urutan', 'tataLetak', 'blok'],
  menu: ['parentId', 'label', 'tipe', 'target', 'urutan', 'status'],
};
// Kolom `cms` yang hanya boleh diubah superadmin.
const CMS_SUPERADMIN_COLUMNS = ['status'];

// Tabel tingkat SITUS (bukan milik satu CMS): isinya wajah publik
// piawai.id, jadi hanya superadmin yang boleh menyentuhnya lewat /api.
const SITE_TABLES = new Set(['halaman', 'menu']);

// Slug halaman yang dirender di URL "/" — dikunci: tidak bisa diganti
// namanya dan tidak bisa dihapus. Tanpa kunci ini, satu klik "Hapus" di
// panel admin membuat halaman depan situs kosong dan tidak ada cara
// mengembalikannya selain lewat SQL manual.
const HOME_SLUG = 'beranda';

const MENU_TIPE = new Set(['halaman', 'rute', 'url', 'induk']);

// Rute frontend yang boleh dituju menu bertipe `rute`. Sengaja allowlist,
// bukan teks bebas: menu yang menunjuk rute tidak dikenal akan tampil
// sebagai tautan mati yang baru ketahuan setelah pengunjung mengkliknya.
// Daftar ini harus sejalan dengan web.routes di cms-app (lihat pages/*.js).
const MENU_ROUTES = new Set(['home', 'artikel-list', 'penulis', 'login', 'register']);

// ------------------------------------------------------------
// Susunan SEKSI untuk halaman bertata-letak 'seksi' (landing page).
// ------------------------------------------------------------
// Disimpan sebagai JSON di kolom `halaman.blok`, dirender di frontend
// oleh components.hero / .features / .articleFull (cms-app/engine.js).
//
// Kenapa divalidasi seketat ini, bukan disimpan apa adanya? Karena
// komponen-komponen itu menyisipkan nilainya LANGSUNG ke template HTML
// (mis. `<h1>${d.title}</h1>`, `onclick="web.navigate('${cta.link}')"`).
// Frontend memang meng-escape isinya sebelum dirender (lihat
// resolveHalaman di pages/public.js), tapi mengandalkan satu lapis saja
// untuk data yang bentuknya bebas itu rapuh: struktur yang tidak dikenal
// lebih baik ditolak di pintu masuk daripada dibersihkan belakangan.
const SECTION_TIPE = new Set(['hero', 'features', 'articleFull']);
const MAX_SECTIONS = 12;
const MAX_FEATURE_ITEMS = 12;
const MAX_LINES = 30;
// Kelas ikon dari svg.js (mis. 'di-cart'). Nama ikon yang tidak ada
// tinggal tidak tergambar — tidak berbahaya, jadi cukup pola, bukan
// daftar nama yang harus ikut diperbarui tiap svg.js bertambah.
const ICON_RE = /^di-[a-z0-9-]{1,24}$/;

/** Target navigasi internal yang boleh dituju tombol/tautan di dalam seksi. */
function safeNavTarget(value) {
  const v = String(value || '').trim();
  if (MENU_ROUTES.has(v)) return v;
  const laman = v.match(/^laman\/([a-z0-9][a-z0-9-]{1,29})$/);
  if (laman) return v;
  return null;
}

/** Teks polos untuk seksi: tanpa tag sama sekali, panjang dibatasi. */
function plainText(value, max) {
  return String(value ?? '').replace(/<[^>]*>/g, '').trim().slice(0, max);
}

/** Validasi & bersihkan satu baris `articleFull.lines` (format lineRenderer). */
function normalizeLine(raw) {
  const line = String(raw ?? '').trim();
  if (!line) return null;
  if (line === '---') return '---';

  const heading = line.match(/^(#{2,3})\s+(.*)$/);
  if (heading) return `${heading[1]} ${plainText(heading[2], 120)}`;

  const link = line.match(/^link:([^:]{1,60}):(.+)$/);
  if (link) {
    const target = safeNavTarget(link[2]);
    if (!target) return null; // tautan ke rute tak dikenal dibuang, bukan disimpan sebagai tautan mati
    return `link:${plainText(link[1], 60)}:${target}`;
  }
  return plainText(line, 300);
}

/**
 * Validasi kolom `blok`. Menerima array (atau string JSON) lalu
 * mengembalikan STRING JSON yang siap disimpan — atau melempar HttpError
 * kalau bentuknya tidak dikenal. Field di luar daftar dibuang diam-diam,
 * pola yang sama dengan pickColumns untuk kolom tabel.
 */
function normalizeBlok(input) {
  if (input === null || input === '') return null;

  let arr = input;
  if (typeof arr === 'string') {
    try { arr = JSON.parse(arr); }
    catch (e) { throw new HttpError(400, 'Susunan seksi halaman bukan JSON yang sah.'); }
  }
  if (!Array.isArray(arr)) throw new HttpError(400, 'Susunan seksi halaman harus berupa daftar.');
  if (arr.length > MAX_SECTIONS) throw new HttpError(400, `Maksimal ${MAX_SECTIONS} seksi per halaman.`);

  const out = [];
  for (const raw of arr) {
    const section = String(raw?.section || '');
    if (!SECTION_TIPE.has(section)) {
      throw new HttpError(400, `Seksi '${section}' tidak dikenal. Pilihan: ${[...SECTION_TIPE].join(', ')}.`);
    }

    if (section === 'hero') {
      const blok = {
        section, title: plainText(raw.title, 120),
        tagline: plainText(raw.tagline, 120),
        description: plainText(raw.description, 400),
      };
      if (!blok.title) throw new HttpError(400, 'Seksi hero wajib punya judul.');
      const badges = Array.isArray(raw.badges) ? raw.badges : [];
      blok.badges = badges.slice(0, 6).map(b => plainText(b, 40)).filter(Boolean);
      const icon = String(raw.imgClass || '').trim();
      if (icon && !ICON_RE.test(icon)) throw new HttpError(400, 'Kelas ikon hero harus berbentuk "di-namaikon".');
      if (icon) blok.imgClass = icon;
      if (raw.cta && (raw.cta.text || raw.cta.link)) {
        const link = safeNavTarget(raw.cta.link);
        if (!link) throw new HttpError(400, `Tujuan tombol hero tidak dikenal. Pakai salah satu dari: ${[...MENU_ROUTES].join(', ')}, atau "laman/<slug>".`);
        blok.cta = { text: plainText(raw.cta.text, 60) || 'Selengkapnya', link };
      }
      out.push(blok);
      continue;
    }

    if (section === 'features') {
      const items = Array.isArray(raw.items) ? raw.items : [];
      if (items.length > MAX_FEATURE_ITEMS) throw new HttpError(400, `Maksimal ${MAX_FEATURE_ITEMS} item per seksi fitur.`);
      const bersih = [];
      for (const it of items) {
        const title = plainText(it?.title, 80);
        if (!title) continue; // item tanpa judul tidak menampilkan apa pun — buang
        const item = { title, content: plainText(it?.content, 300) };
        const icon = String(it?.icon || '').trim();
        if (icon && !ICON_RE.test(icon)) throw new HttpError(400, `Kelas ikon "${icon}" harus berbentuk "di-namaikon".`);
        if (icon) item.icon = icon;
        const target = it?.linkTarget ? safeNavTarget(it.linkTarget) : null;
        if (it?.linkTarget && !target) throw new HttpError(400, `Tujuan tautan fitur "${title}" tidak dikenal.`);
        if (target) { item.linkTarget = target; item.linkText = plainText(it.linkText, 40) || 'Selengkapnya'; }
        bersih.push(item);
      }
      if (!bersih.length) throw new HttpError(400, 'Seksi fitur wajib punya minimal satu item berjudul.');
      out.push({ section, items: bersih });
      continue;
    }

    // articleFull
    const lines = (Array.isArray(raw.lines) ? raw.lines : []).slice(0, MAX_LINES)
      .map(normalizeLine).filter(Boolean);
    const subtitle = plainText(raw.subtitle, 120);
    if (!subtitle && !lines.length) continue; // seksi kosong tidak perlu disimpan
    out.push({ section, subtitle, lines });
  }

  if (!out.length) return null;
  return JSON.stringify(out);
}

// ------------------------------------------------------------
// Util dasar
// ------------------------------------------------------------
function genId(table) {
  return table + '_' + Date.now().toString(36) + crypto.randomUUID().replace(/-/g, '').slice(0, 8);
}

function corsHeaders(request, env) {
  const allowed = String(env.ALLOWED_ORIGINS || DEFAULT_ORIGINS.join(','))
    .split(',').map(s => s.trim()).filter(Boolean);
  const origin = request.headers.get('Origin') || '';
  const h = {
    'Vary': 'Origin',
    'Access-Control-Allow-Methods': 'GET,POST,PATCH,DELETE,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
  };
  if (origin && allowed.includes(origin)) h['Access-Control-Allow-Origin'] = origin;
  return h;
}

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
      ...extraHeaders,
    },
  });
}

/** Error terkontrol — pesan ini AMAN ditampilkan ke pengguna. */
class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

function clientIp(request) {
  return request.headers.get('CF-Connecting-IP')
    || request.headers.get('X-Forwarded-For')?.split(',')[0].trim()
    || 'unknown';
}

const enc = new TextEncoder();

function b64urlEncode(bytes) {
  let s = '';
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  for (const b of arr) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64urlDecode(str) {
  const pad = str.length % 4 ? '='.repeat(4 - (str.length % 4)) : '';
  const bin = atob(str.replace(/-/g, '+').replace(/_/g, '/') + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** Perbandingan waktu-konstan untuk hash/signature. */
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// ------------------------------------------------------------
// [KRITIS #1] Hashing password — PBKDF2-SHA256 lewat Web Crypto.
// Format tersimpan: pbkdf2$sha256$<iterasi>$<saltB64url>$<hashB64url>
// Argon2id lebih ideal, tapi tidak tersedia native di Workers runtime;
// PBKDF2 210k iterasi adalah rekomendasi OWASP untuk SHA-256.
// ------------------------------------------------------------
async function pbkdf2(password, salt, iterations) {
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, key, 256);
  return new Uint8Array(bits);
}

async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await pbkdf2(password, salt, PBKDF2_ITERATIONS);
  return `pbkdf2$sha256$${PBKDF2_ITERATIONS}$${b64urlEncode(salt)}$${b64urlEncode(hash)}`;
}

async function verifyPassword(password, stored) {
  const parts = String(stored || '').split('$');
  if (parts.length !== 5 || parts[0] !== 'pbkdf2') return false;
  const iterations = parseInt(parts[2], 10);
  // 100_000 = batas maksimal PBKDF2 yang didukung WebCrypto di Cloudflare
  // Workers (lihat catatan di PBKDF2_ITERATIONS). Hash dengan iterasi di
  // atas itu (mis. sisa dari konfigurasi lama) tidak valid untuk
  // diverifikasi di runtime ini — gagal dengan aman, bukan crash 500.
  if (!Number.isFinite(iterations) || iterations < 1000 || iterations > 100_000) return false;
  const salt = b64urlDecode(parts[3]);
  const expected = b64urlDecode(parts[4]);
  const actual = await pbkdf2(password, salt, iterations);
  return timingSafeEqual(actual, expected);
}

// ------------------------------------------------------------
// [KRITIS #2] Token bertanda tangan server — HMAC-SHA256, generik.
// `typ` membedakan jenis token (mis. 'session' vs 'captcha') supaya
// satu jenis token TIDAK BISA dipakai ulang sebagai jenis lain walau
// tanda tangannya sah (mis. token captcha kedaluwarsa-pendek yang
// disodorkan sebagai token sesi) — signature valid tidak cukup, `typ`
// harus cocok dengan yang diminta pemanggil.
//
// Token sesi: payload { typ:'session', uid, cid, kode, cmsNama,
// username, name, role, iat, exp }. cmsId & role SELALU dibaca dari
// sini, tidak pernah dari klien.
// Token captcha: payload { typ:'captcha', a, b, iat, exp }.
// ------------------------------------------------------------
async function hmacKey(env) {
  const secret = env.SESSION_SECRET;
  if (!secret || String(secret).length < 32) {
    throw new HttpError(500, 'Server belum dikonfigurasi (SESSION_SECRET kosong atau terlalu pendek).');
  }
  return crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
}

async function signToken(env, typ, payload, ttlMs) {
  const body = { ...payload, typ, iat: Date.now(), exp: Date.now() + ttlMs };
  const data = b64urlEncode(enc.encode(JSON.stringify(body)));
  const sig = await crypto.subtle.sign('HMAC', await hmacKey(env), enc.encode(data));
  return { token: `${data}.${b64urlEncode(sig)}`, payload: body };
}

async function verifyToken(env, typ, token) {
  if (!token || typeof token !== 'string' || !token.includes('.')) return null;
  const [data, sig] = token.split('.');
  let expected;
  try {
    expected = new Uint8Array(await crypto.subtle.sign('HMAC', await hmacKey(env), enc.encode(data)));
  } catch (e) { throw e; }
  let given;
  try { given = b64urlDecode(sig || ''); } catch (e) { return null; }
  if (!timingSafeEqual(expected, given)) return null;
  let payload;
  try { payload = JSON.parse(new TextDecoder().decode(b64urlDecode(data))); } catch (e) { return null; }
  if (!payload?.exp || Date.now() > payload.exp) return null;
  if (payload.typ !== typ) return null; // token jenis lain (mis. captcha) tidak sah sebagai sesi, atau sebaliknya
  return payload;
}

async function signSession(env, payload) {
  return signToken(env, 'session', payload, SESSION_TTL_MS);
}

async function verifySession(env, token) {
  return verifyToken(env, 'session', token);
}

/** Ambil sesi dari header Authorization; lempar 401 kalau tidak sah. */
async function requireSession(request, env) {
  const raw = request.headers.get('Authorization') || '';
  const token = raw.startsWith('Bearer ') ? raw.slice(7).trim() : '';
  const session = await verifySession(env, token);
  if (!session) throw new HttpError(401, 'Sesi tidak valid atau sudah berakhir. Silakan masuk kembali.');
  return session;
}

// ------------------------------------------------------------
// [TINGGI #3] Captcha matematika kustom, diverifikasi di server.
// Menggantikan Cloudflare Turnstile: tidak ada dependensi pihak
// ketiga, tidak ada script eksternal yang bisa ter-block ad-blocker,
// tidak ada secret tambahan yang perlu di-set.
//
// Soalnya ("a + b = ?") DAN jawabannya (a, b) ditandatangani HMAC di
// `token` (typ:'captcha', lihat signToken/verifyToken) lalu dikirim
// ke klien — klien tidak pernah tahu jawabannya dari token itu sendiri
// (token cuma bisa diverifikasi ulang, bukan dibaca isinya tanpa
// tanda tangan yang valid diverifikasi server), jadi harus benar-benar
// menjumlahkan untuk lolos. Token kedaluwarsa pendek (lihat
// CAPTCHA_TTL_MS) supaya soal tidak bisa "disimpan" lalu dipakai
// berkali-kali dalam jangka panjang.
//
// Ini BUKAN pertahanan anti-bot yang kuat (bot sederhana pun bisa
// mem-parsing "a + b = ?" dan menjumlahkannya) — tujuannya sama seperti
// captcha matematika pada umumnya: menyaring form-spam otomatis yang
// generik, bukan menghentikan penyerang yang menargetkan aplikasi ini
// secara spesifik. Fail-closed tetap dipertahankan lewat
// `hmacKey()`/`SESSION_SECRET` (kalau kosong, seluruh alur token —
// termasuk captcha — otomatis gagal).
// ------------------------------------------------------------
const CAPTCHA_TTL_MS = 5 * 60 * 1000; // 5 menit — cukup untuk mengisi form, tidak untuk disimpan lama

async function generateMathCaptcha(env) {
  const a = 1 + Math.floor(Math.random() * 9); // 1..9
  const b = 1 + Math.floor(Math.random() * 9); // 1..9
  const { token } = await signToken(env, 'captcha', { a, b }, CAPTCHA_TTL_MS);
  return { challenge: `${a} + ${b} = ?`, token };
}

/**
 * Verifikasi jawaban captcha. Percobaan (benar maupun salah, sama
 * seperti login) dibatasi per-IP lewat `rate_limit` yang sama dipakai
 * untuk login/registrasi — jadi tidak perlu tabel/infra baru.
 */
async function verifyMathCaptcha(env, db, token, answer, ip) {
  const key = `captcha:ip:${ip}`;
  await rateLimitCheck(db, key, { max: 10, windowMs: 15 * 60_000, blockMs: 15 * 60_000 });

  const payload = await verifyToken(env, 'captcha', token);
  const given = Number(answer);
  const correct = payload && Number.isFinite(given) && (payload.a + payload.b) === given;

  if (!correct) {
    await rateLimitHit(db, key);
    throw new HttpError(400, 'Jawaban captcha salah atau soal sudah kedaluwarsa. Muat ulang soal dan coba lagi.');
  }
}

// ------------------------------------------------------------
// [TINGGI #4] Rate limiting nyata di D1 (tabel `rate_limit`).
// Dipakai per-IP dan per-akun; lockout ditegakkan SEBELUM password
// dicocokkan, jadi bot yang memanggil API langsung tetap kena.
// ------------------------------------------------------------
async function rateLimitCheck(db, key, { max, windowMs, blockMs }) {
  const now = Date.now();
  const row = await db.prepare(`SELECT * FROM rate_limit WHERE key = ?`).bind(key).first();
  if (row && row.blockedUntil > now) {
    throw new HttpError(429, `Terlalu banyak percobaan. Coba lagi dalam ${Math.ceil((row.blockedUntil - now) / 1000)} detik.`);
  }
  if (!row || (now - row.windowStart) > windowMs) {
    await db.prepare(
      `INSERT INTO rate_limit (key, count, windowStart, blockedUntil) VALUES (?, 0, ?, 0)
       ON CONFLICT(key) DO UPDATE SET count = 0, windowStart = ?, blockedUntil = 0`
    ).bind(key, now, now).run();
    return;
  }
  if (row.count >= max) {
    const until = now + blockMs;
    await db.prepare(`UPDATE rate_limit SET blockedUntil = ?, count = 0, windowStart = ? WHERE key = ?`)
      .bind(until, now, key).run();
    throw new HttpError(429, `Terlalu banyak percobaan. Coba lagi dalam ${Math.ceil(blockMs / 1000)} detik.`);
  }
}

async function rateLimitHit(db, key) {
  const now = Date.now();
  await db.prepare(
    `INSERT INTO rate_limit (key, count, windowStart, blockedUntil) VALUES (?, 1, ?, 0)
     ON CONFLICT(key) DO UPDATE SET count = count + 1`
  ).bind(key, now).run();
}

async function rateLimitReset(db, key) {
  await db.prepare(`DELETE FROM rate_limit WHERE key = ?`).bind(key).run().catch(() => {});
}

// ------------------------------------------------------------
// [SEDANG #5] Sanitasi HTML sisi server untuk `post.konten`.
// Allowlist tag + atribut (bukan blocklist). Dipakai saat menyimpan
// DAN saat menyajikan, jadi baris lama yang sudah terlanjur kotor
// tetap bersih ketika dibaca.
// ------------------------------------------------------------
const ALLOWED_TAGS = {
  p: [], br: [], hr: [], strong: [], b: [], em: [], i: [], u: [], s: [],
  h1: [], h2: [], h3: [], h4: [], h5: [], h6: [],
  ul: [], ol: [], li: [], blockquote: [], pre: [], code: [], span: [],
  figure: [], figcaption: [], table: [], thead: [], tbody: [], tr: [],
  th: ['colspan', 'rowspan'], td: ['colspan', 'rowspan'],
  a: ['href', 'title'], img: ['src', 'alt', 'title', 'width', 'height'],
};
const VOID_TAGS = new Set(['br', 'hr', 'img']);

/** Normalkan entity & whitespace supaya `java&#115;cript:` tidak lolos. */
function decodeEntities(str) {
  return String(str)
    .replace(/&#x([0-9a-f]+);?/gi, (_, h) => String.fromCharCode(parseInt(h, 16)))
    .replace(/&#(\d+);?/g, (_, d) => String.fromCharCode(parseInt(d, 10)))
    .replace(/&amp;/gi, '&');
}

function safeUrl(value, { allowMailto = false } = {}) {
  const v = decodeEntities(value).replace(/[\u0000-\u0020]/g, '').toLowerCase();
  if (/^(javascript|data|vbscript|file|blob):/i.test(v)) return null;
  if (/^[a-z][a-z0-9+.-]*:/i.test(v)) {
    if (v.startsWith('http://') || v.startsWith('https://')) return value;
    if (allowMailto && v.startsWith('mailto:')) return value;
    return null;
  }
  return value; // relatif / anchor / protocol-relative dibiarkan apa adanya
}

function escapeAttr(v) {
  return String(v).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function sanitizeHtml(input) {
  let html = String(input || '');
  // Buang komentar dan elemen yang isinya pun berbahaya (beserta kontennya).
  html = html.replace(/<!--[\s\S]*?-->/g, '');
  html = html.replace(/<\s*(script|style|iframe|object|embed|noscript|template|svg|math)\b[\s\S]*?<\s*\/\s*\1\s*>/gi, '');
  html = html.replace(/<\s*\/?\s*(script|style|iframe|object|embed|noscript|template|svg|math)\b[^>]*>/gi, '');

  return html.replace(/<\/?([a-zA-Z][a-zA-Z0-9]*)((?:[^>"']|"[^"]*"|'[^']*')*)>/g, (full, rawName, rawAttrs) => {
    const name = rawName.toLowerCase();
    if (!(name in ALLOWED_TAGS)) return '';
    if (full.startsWith('</')) return VOID_TAGS.has(name) ? '' : `</${name}>`;

    const allowedAttrs = ALLOWED_TAGS[name];
    let out = `<${name}`;
    const attrRe = /([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*("([^"]*)"|'([^']*)'|([^\s"'=<>`]+))/g;
    let m;
    while ((m = attrRe.exec(rawAttrs)) !== null) {
      const attr = m[1].toLowerCase();
      const value = m[3] ?? m[4] ?? m[5] ?? '';
      if (attr.startsWith('on')) continue;             // semua event handler
      if (!allowedAttrs.includes(attr)) continue;      // allowlist per tag
      if (attr === 'href' || attr === 'src') {
        const safe = safeUrl(value, { allowMailto: attr === 'href' });
        if (safe === null) continue;
        out += ` ${attr}="${escapeAttr(safe)}"`;
        continue;
      }
      out += ` ${attr}="${escapeAttr(value)}"`;
    }
    if (name === 'a') out += ' rel="noopener noreferrer nofollow"';
    return VOID_TAGS.has(name) ? out + '>' : out + '>';
  });
}

// ------------------------------------------------------------
// Helper penulisan DB dengan kolom ter-allowlist (anti injeksi nama kolom)
// ------------------------------------------------------------
function pickColumns(body, allowed) {
  const out = {};
  for (const col of allowed) {
    if (body[col] !== undefined) out[col] = body[col];
  }
  return out;
}

async function insertRow(db, table, record) {
  const cols = Object.keys(record);
  await db.prepare(
    `INSERT INTO ${table} (${cols.join(', ')}) VALUES (${cols.map(() => '?').join(', ')})`
  ).bind(...cols.map(c => record[c])).run();
  return record;
}

async function updateRow(db, table, id, patch) {
  const cols = Object.keys(patch);
  if (!cols.length) return;
  await db.prepare(
    `UPDATE ${table} SET ${cols.map(c => `${c} = ?`).join(', ')} WHERE id = ?`
  ).bind(...cols.map(c => patch[c]), id).run();
}

// ------------------------------------------------------------
// Tabel situs (`halaman` & `menu`) — validasi + CRUD.
// Dipisah dari handleApi supaya aturan khususnya (kunci slug beranda,
// batas satu tingkat submenu, allowlist tipe/target menu) terbaca utuh
// di satu tempat, bukan terselip di antara cabang `post`/`cms`.
// ------------------------------------------------------------

/** Susun patch kolom `halaman` dari body klien. `existing` = null saat create. */
function normalizeHalaman(body, existing) {
  const data = pickColumns(body, WRITABLE_COLUMNS.halaman);
  const patch = {};

  if (data.slug !== undefined) {
    const slug = String(data.slug).trim().toLowerCase();
    if (!SLUG_RE.test(slug)) throw new HttpError(400, 'Slug halaman harus 2-30 karakter: huruf kecil, angka, atau tanda strip.');
    // Slug beranda dikunci dua arah: yang asli tidak boleh pindah nama,
    // dan halaman lain tidak boleh mengambil alih namanya.
    if (existing?.slug === HOME_SLUG && slug !== HOME_SLUG) {
      throw new HttpError(400, `Slug halaman depan ("${HOME_SLUG}") tidak dapat diubah. Ubah judul & isinya saja.`);
    }
    if (existing?.slug !== HOME_SLUG && slug === HOME_SLUG) {
      throw new HttpError(409, `Slug "${HOME_SLUG}" sudah dipakai halaman depan situs.`);
    }
    patch.slug = slug;
  }
  if (data.judul !== undefined) {
    const judul = String(data.judul).trim().slice(0, 200);
    if (!judul) throw new HttpError(400, 'Judul halaman wajib diisi.');
    patch.judul = judul;
  }
  if (data.ringkasan !== undefined) patch.ringkasan = String(data.ringkasan).slice(0, 500);
  if (data.konten !== undefined) patch.konten = sanitizeHtml(data.konten);
  if (data.coverImage !== undefined) patch.coverImage = safeUrl(String(data.coverImage || '')) || null;
  if (data.status !== undefined) patch.status = data.status === 'publish' ? 'publish' : 'draft';
  if (data.urutan !== undefined) {
    const n = Number(data.urutan);
    patch.urutan = Number.isFinite(n) ? Math.trunc(n) : 0;
  }
  if (data.tataLetak !== undefined) patch.tataLetak = data.tataLetak === 'seksi' ? 'seksi' : 'konten';
  if (data.blok !== undefined) patch.blok = normalizeBlok(data.blok);

  // Halaman bertata-letak 'seksi' tanpa satu pun seksi akan tampil sebagai
  // halaman kosong — tolak di sini, selagi admin masih di formnya.
  const tataLetak = patch.tataLetak ?? existing?.tataLetak ?? 'konten';
  const blok = patch.blok !== undefined ? patch.blok : existing?.blok;
  if (tataLetak === 'seksi' && !blok) {
    throw new HttpError(400, 'Tata letak "seksi" membutuhkan minimal satu seksi (hero, features, atau articleFull).');
  }
  // Halaman depan HARUS selalu tayang — kalau boleh di-draft, URL "/"
  // ikut kosong padahal halamannya masih ada (bingung mencarinya).
  if (existing?.slug === HOME_SLUG && patch.status === 'draft') {
    throw new HttpError(400, 'Halaman depan tidak dapat dijadikan draft. Ubah isinya, atau tunjuk menu ke halaman lain.');
  }
  return patch;
}

/** Susun patch kolom `menu`, termasuk cek induk/anak. `id` = null saat create. */
async function normalizeMenu(db, body, existing, id) {
  const data = pickColumns(body, WRITABLE_COLUMNS.menu);
  const patch = {};

  if (data.label !== undefined) {
    const label = String(data.label).trim().slice(0, 60);
    if (!label) throw new HttpError(400, 'Label menu wajib diisi.');
    patch.label = label;
  }
  if (data.tipe !== undefined) {
    const tipe = String(data.tipe).trim().toLowerCase();
    if (!MENU_TIPE.has(tipe)) throw new HttpError(400, `Tipe menu harus salah satu dari: ${[...MENU_TIPE].join(', ')}.`);
    patch.tipe = tipe;
  }
  if (data.urutan !== undefined) {
    const n = Number(data.urutan);
    patch.urutan = Number.isFinite(n) ? Math.trunc(n) : 0;
  }
  if (data.status !== undefined) patch.status = data.status === 'nonaktif' ? 'nonaktif' : 'aktif';

  // --- parentId: submenu dibatasi SATU tingkat ---
  if (data.parentId !== undefined) {
    const parentId = String(data.parentId || '').trim();
    if (!parentId) {
      patch.parentId = null;
    } else {
      if (parentId === id) throw new HttpError(400, 'Menu tidak dapat dijadikan induk bagi dirinya sendiri.');
      const parent = await db.prepare(`SELECT id, parentId FROM menu WHERE id = ?`).bind(parentId).first();
      if (!parent) throw new HttpError(400, 'Menu induk yang dipilih tidak ditemukan.');
      if (parent.parentId) throw new HttpError(400, 'Submenu hanya didukung satu tingkat — menu induk yang dipilih sudah menjadi submenu.');
      if (id) {
        const anak = await db.prepare(`SELECT id FROM menu WHERE parentId = ? LIMIT 1`).bind(id).first();
        if (anak) throw new HttpError(400, 'Menu ini sudah punya submenu, jadi tidak bisa dipindah menjadi submenu menu lain.');
      }
      patch.parentId = parentId;
    }
  }

  // --- target: artinya tergantung tipe, jadi divalidasi setelah tipe diketahui ---
  const tipe = patch.tipe ?? existing?.tipe ?? 'halaman';
  if (data.target !== undefined || patch.tipe !== undefined) {
    const raw = String(data.target ?? existing?.target ?? '').trim();

    if (tipe === 'induk') {
      patch.target = null; // wadah submenu, tidak menuju ke mana pun
    } else if (tipe === 'halaman') {
      const slug = raw.toLowerCase();
      if (!SLUG_RE.test(slug)) throw new HttpError(400, 'Untuk tipe "halaman", target harus berupa slug halaman.');
      const hal = await db.prepare(`SELECT id FROM halaman WHERE slug = ?`).bind(slug).first();
      if (!hal) throw new HttpError(400, `Halaman dengan slug "${slug}" belum ada. Buat halamannya lebih dulu.`);
      patch.target = slug;
    } else if (tipe === 'rute') {
      if (!MENU_ROUTES.has(raw)) throw new HttpError(400, `Untuk tipe "rute", target harus salah satu dari: ${[...MENU_ROUTES].join(', ')}.`);
      patch.target = raw;
    } else { // url
      const safe = safeUrl(raw);
      if (!safe || !/^https?:\/\//i.test(safe)) throw new HttpError(400, 'Untuk tipe "url", target harus URL absolut yang diawali http:// atau https://.');
      patch.target = safe.slice(0, 300);
    }
  }
  return patch;
}

async function handleSiteTable(request, env, table, id, session) {
  if (session.role !== 'superadmin') {
    throw new HttpError(403, 'Hanya superadmin yang dapat mengelola halaman dan menu situs.');
  }
  const db = env.DB;
  const now = new Date().toISOString();

  if (request.method === 'GET') {
    if (id) {
      const row = await db.prepare(`SELECT * FROM ${table} WHERE id = ?`).bind(id).first();
      return json(row || null, row ? 200 : 404);
    }
    const order = table === 'halaman' ? 'urutan ASC, judul ASC' : 'urutan ASC, label ASC';
    const { results } = await db.prepare(`SELECT * FROM ${table} ORDER BY ${order}`).all();
    return json(results);
  }

  const body = request.method === 'POST' || request.method === 'PATCH'
    ? await request.json().catch(() => ({})) : {};

  if (request.method === 'POST' && !id) {
    const patch = table === 'halaman'
      ? normalizeHalaman(body, null)
      : await normalizeMenu(db, body, null, null);

    if (table === 'halaman' && (!patch.slug || !patch.judul)) {
      throw new HttpError(400, 'Slug dan judul halaman wajib diisi.');
    }
    if (table === 'menu' && !patch.label) throw new HttpError(400, 'Label menu wajib diisi.');

    const record = table === 'halaman'
      ? {
        id: genId('hal'), slug: patch.slug, judul: patch.judul,
        ringkasan: patch.ringkasan ?? '', konten: patch.konten ?? '',
        coverImage: patch.coverImage ?? null,
        tataLetak: patch.tataLetak ?? 'konten', blok: patch.blok ?? null,
        status: patch.status ?? 'draft', urutan: patch.urutan ?? 0,
        createdAt: now, updatedAt: now,
      }
      : {
        id: genId('mnu'), parentId: patch.parentId ?? null, label: patch.label,
        tipe: patch.tipe ?? 'halaman', target: patch.target ?? null,
        urutan: patch.urutan ?? 0, status: patch.status ?? 'aktif',
        createdAt: now, updatedAt: now,
      };
    try { await insertRow(db, table, record); }
    catch (e) {
      if (String(e.message).includes('UNIQUE')) throw new HttpError(409, 'Slug halaman sudah dipakai.');
      throw e;
    }
    return json(record, 201);
  }

  if (request.method === 'PATCH' && id) {
    const existing = await db.prepare(`SELECT * FROM ${table} WHERE id = ?`).bind(id).first();
    if (!existing) throw new HttpError(404, `Data ${table} tidak ditemukan.`);

    const patch = table === 'halaman'
      ? normalizeHalaman(body, existing)
      : await normalizeMenu(db, body, existing, id);
    if (!Object.keys(patch).length) throw new HttpError(400, 'Tidak ada field yang bisa diperbarui.');
    patch.updatedAt = now;

    try { await updateRow(db, table, id, patch); }
    catch (e) {
      if (String(e.message).includes('UNIQUE')) throw new HttpError(409, 'Slug halaman sudah dipakai.');
      throw e;
    }
    return json({ ...existing, ...patch });
  }

  if (request.method === 'DELETE' && id) {
    const existing = await db.prepare(`SELECT * FROM ${table} WHERE id = ?`).bind(id).first();
    if (!existing) return json({ ok: true }); // idempotent

    if (table === 'halaman') {
      if (existing.slug === HOME_SLUG) throw new HttpError(400, 'Halaman depan situs tidak dapat dihapus.');
      // Menu yang menunjuk halaman ini ikut dibersihkan — kalau dibiarkan,
      // pengunjung mendapat menu yang mengarah ke halaman tidak ada.
      await db.batch([
        db.prepare(`DELETE FROM menu WHERE tipe = 'halaman' AND target = ?`).bind(existing.slug),
        db.prepare(`DELETE FROM halaman WHERE id = ?`).bind(id),
      ]);
    } else {
      // Menghapus menu induk ikut menghapus submenunya — submenu tanpa
      // induk tidak akan pernah tampil di navigasi, jadi menyisakannya
      // hanya membuat data yang tak terlihat dan membingungkan.
      await db.batch([
        db.prepare(`DELETE FROM menu WHERE parentId = ?`).bind(id),
        db.prepare(`DELETE FROM menu WHERE id = ?`).bind(id),
      ]);
    }
    return json({ ok: true });
  }

  throw new HttpError(405, 'Method not allowed');
}

// ------------------------------------------------------------
// /api — CRUD generik, SEKARANG WAJIB TOKEN.
//   GET    /api?table=post            -> list (otomatis di-scope ke cms token)
//   GET    /api?table=post&id=I       -> detail
//   POST   /api?table=post            -> create
//   PATCH  /api?table=post&id=I       -> update
//   DELETE /api?table=post&id=I       -> delete
// Parameter `cmsId` dari klien DIABAIKAN — nilainya diambil dari token.
// ------------------------------------------------------------
async function handleApi(request, env) {
  const session = await requireSession(request, env);
  const url = new URL(request.url);
  const table = url.searchParams.get('table');
  const id = url.searchParams.get('id');
  const db = env.DB;

  if (!table) throw new HttpError(400, "Query 'table' wajib diisi");
  if (BLOCKED_TABLES.has(table)) {
    throw new HttpError(403, `Tabel '${table}' tidak dapat diakses lewat /api. Gunakan endpoint khusus.`);
  }
  if (SITE_TABLES.has(table)) return handleSiteTable(request, env, table, id, session);
  if (table !== 'post' && table !== 'cms') throw new HttpError(400, `Tabel '${table}' tidak dikenal`);

  const isSuper = session.role === 'superadmin';

  // ---------- tabel `post` (selalu ter-scope ke cms milik token) ----------
  if (table === 'post') {
    const cmsId = session.cid;

    if (request.method === 'GET') {
      if (id) {
        const row = await db.prepare(`SELECT * FROM post WHERE id = ? AND cmsId = ?`).bind(id, cmsId).first();
        return json(row || null, row ? 200 : 404);
      }
      const { results } = await db.prepare(`SELECT * FROM post WHERE cmsId = ? ORDER BY createdAt DESC`).bind(cmsId).all();
      return json(results);
    }

    const body = request.method === 'POST' || request.method === 'PATCH'
      ? await request.json().catch(() => ({})) : {};

    if (request.method === 'POST' && !id) {
      const data = pickColumns(body, WRITABLE_COLUMNS.post);
      const slug = String(data.slug || '').trim().toLowerCase();
      if (!SLUG_RE.test(slug)) throw new HttpError(400, 'Slug artikel harus 2-30 karakter: huruf kecil, angka, atau tanda strip.');
      const judul = String(data.judul || '').trim().slice(0, 200);
      if (!judul) throw new HttpError(400, 'Judul artikel wajib diisi.');
      const status = data.status === 'publish' ? 'publish' : 'draft';
      const now = new Date().toISOString();

      const record = {
        id: genId('post'), cmsId, slug, judul,
        ringkasan: String(data.ringkasan || '').slice(0, 500),
        konten: sanitizeHtml(data.konten || ''),
        coverImage: safeUrl(String(data.coverImage || '')) || null,
        kategori: String(data.kategori || '').slice(0, 80),
        tags: String(data.tags || '').slice(0, 200),
        status, views: 0,
        publishedAt: status === 'publish' ? now : null,
        createdAt: now, updatedAt: now,
      };
      try {
        await insertRow(db, 'post', record);
      } catch (e) {
        if (String(e.message).includes('UNIQUE')) throw new HttpError(409, 'Slug artikel sudah dipakai di CMS ini.');
        throw e;
      }
      return json(record, 201);
    }

    if (request.method === 'PATCH' && id) {
      const existing = await db.prepare(`SELECT * FROM post WHERE id = ? AND cmsId = ?`).bind(id, cmsId).first();
      if (!existing) throw new HttpError(404, 'Artikel tidak ditemukan.');

      const data = pickColumns(body, WRITABLE_COLUMNS.post);
      const patch = {};
      if (data.slug !== undefined) {
        const slug = String(data.slug).trim().toLowerCase();
        if (!SLUG_RE.test(slug)) throw new HttpError(400, 'Slug artikel harus 2-30 karakter: huruf kecil, angka, atau tanda strip.');
        patch.slug = slug;
      }
      if (data.judul !== undefined) patch.judul = String(data.judul).trim().slice(0, 200);
      if (data.ringkasan !== undefined) patch.ringkasan = String(data.ringkasan).slice(0, 500);
      if (data.konten !== undefined) patch.konten = sanitizeHtml(data.konten);
      if (data.coverImage !== undefined) patch.coverImage = safeUrl(String(data.coverImage || '')) || null;
      if (data.kategori !== undefined) patch.kategori = String(data.kategori).slice(0, 80);
      if (data.tags !== undefined) patch.tags = String(data.tags).slice(0, 200);
      if (data.status !== undefined) {
        patch.status = data.status === 'publish' ? 'publish' : 'draft';
        if (patch.status === 'publish' && !existing.publishedAt) patch.publishedAt = new Date().toISOString();
      }
      patch.updatedAt = new Date().toISOString();

      try {
        await updateRow(db, 'post', id, patch);
      } catch (e) {
        if (String(e.message).includes('UNIQUE')) throw new HttpError(409, 'Slug artikel sudah dipakai di CMS ini.');
        throw e;
      }
      return json({ ...existing, ...patch });
    }

    if (request.method === 'DELETE' && id) {
      const existing = await db.prepare(`SELECT id FROM post WHERE id = ? AND cmsId = ?`).bind(id, cmsId).first();
      if (!existing) return json({ ok: true }); // idempotent, tanpa membocorkan keberadaan id
      await db.batch([
        db.prepare(`DELETE FROM komentar WHERE postId = ?`).bind(id),
        db.prepare(`DELETE FROM post WHERE id = ?`).bind(id),
      ]);
      return json({ ok: true });
    }

    throw new HttpError(405, 'Method not allowed');
  }

  // ---------- tabel `cms` ----------
  // Superadmin melihat semua; pengguna biasa HANYA barisnya sendiri.
  if (request.method === 'GET') {
    if (id) {
      if (!isSuper && id !== session.cid) throw new HttpError(404, 'Tidak ditemukan.');
      const row = await db.prepare(`SELECT * FROM cms WHERE id = ?`).bind(id).first();
      return json(row || null, row ? 200 : 404);
    }
    const stmt = isSuper
      ? db.prepare(`SELECT * FROM cms ORDER BY nama ASC`)
      : db.prepare(`SELECT * FROM cms WHERE id = ?`).bind(session.cid);
    const { results } = await stmt.all();
    return json(results);
  }

  if (request.method === 'PATCH' && id) {
    if (!isSuper && id !== session.cid) throw new HttpError(403, 'Anda tidak berhak mengubah CMS ini.');
    const existing = await db.prepare(`SELECT * FROM cms WHERE id = ?`).bind(id).first();
    if (!existing) throw new HttpError(404, 'CMS tidak ditemukan.');

    const body = await request.json().catch(() => ({}));
    const allowed = isSuper
      ? [...WRITABLE_COLUMNS.cms, ...CMS_SUPERADMIN_COLUMNS]
      : WRITABLE_COLUMNS.cms; // kodeCms & status TIDAK bisa diubah pemilik
    const data = pickColumns(body, allowed);
    const patch = {};
    if (data.nama !== undefined) patch.nama = String(data.nama).trim().slice(0, 80);
    if (data.bio !== undefined) patch.bio = String(data.bio).slice(0, 300);
    if (data.avatarUrl !== undefined) patch.avatarUrl = safeUrl(String(data.avatarUrl || '')) || null;
    if (data.status !== undefined) patch.status = data.status === 'nonaktif' ? 'nonaktif' : 'aktif';
    if (!Object.keys(patch).length) throw new HttpError(400, 'Tidak ada field yang bisa diperbarui.');

    await updateRow(db, 'cms', id, patch);
    return json({ ...existing, ...patch });
  }

  // Pembuatan CMS baru HANYA lewat /public?view=register (agar sekalian
  // membuat akun owner + hash password + captcha), atau oleh superadmin.
  if (request.method === 'POST' && !id) {
    if (!isSuper) throw new HttpError(403, 'Pembuatan CMS dilakukan lewat halaman registrasi.');
    const body = await request.json().catch(() => ({}));
    const kode = String(body.kodeCms || '').trim().toLowerCase();
    if (!SLUG_RE.test(kode)) throw new HttpError(400, 'Kode CMS harus 2-30 karakter: huruf kecil, angka, atau tanda strip.');
    const record = {
      id: genId('cms'), kodeCms: kode,
      nama: String(body.nama || kode).trim().slice(0, 80),
      bio: String(body.bio || '').slice(0, 300),
      avatarUrl: safeUrl(String(body.avatarUrl || '')) || null,
      status: 'aktif', createdAt: new Date().toISOString(),
    };
    try { await insertRow(db, 'cms', record); }
    catch (e) {
      if (String(e.message).includes('UNIQUE')) throw new HttpError(409, 'Kode CMS sudah dipakai.');
      throw e;
    }
    return json(record, 201);
  }

  if (request.method === 'DELETE' && id) {
    if (!isSuper) throw new HttpError(403, 'Hanya superadmin yang dapat menghapus CMS.');
    await db.batch([
      db.prepare(`DELETE FROM komentar WHERE cmsId = ?`).bind(id),
      db.prepare(`DELETE FROM post WHERE cmsId = ?`).bind(id),
      db.prepare(`DELETE FROM users WHERE cmsId = ?`).bind(id),
      db.prepare(`DELETE FROM cms WHERE id = ?`).bind(id),
    ]);
    return json({ ok: true });
  }

  throw new HttpError(405, 'Method not allowed');
}

// ------------------------------------------------------------
// /public — data publik + endpoint auth.
//   GET  /public?view=home
//   GET  /public?view=profile&user=<kodeCms>
//   GET  /public?view=artikel&user=<kodeCms>&slug=<slug>
//   GET  /public?view=captcha    -> {challenge, token} — panggil sebelum login/registrasi
//   POST /public?view=login      body:{kodeCms,username,password,captchaToken,captchaAnswer}
//   POST /public?view=register   body:{kodeCms,namaCms,bio,ownerName,username,password,captchaToken,captchaAnswer}
//   POST /public?view=komentar&user=<kodeCms>&slug=<slug>  body:{isi}  + Bearer token
// ------------------------------------------------------------
async function handlePublic(request, env) {
  const url = new URL(request.url);
  const view = url.searchParams.get('view');
  const userSlug = (url.searchParams.get('user') || '').toLowerCase();
  const postSlug = url.searchParams.get('slug') || '';
  const db = env.DB;

  if (view === 'captcha') {
    return json(await generateMathCaptcha(env));
  }

  if (view === 'home') {
    const { results } = await db.prepare(
      `SELECT kodeCms, nama, bio, avatarUrl FROM cms WHERE status = 'aktif' AND id != 'system' ORDER BY nama ASC`
    ).all();
    return json({ cms: results });
  }

  // ---------- HALAMAN STATIS SITUS ----------
  // Dipakai untuk landing page (`slug=beranda`, dirender di URL "/")
  // maupun halaman lain buatan admin (?laman/<slug> di frontend).
  if (view === 'halaman') {
    const slug = (url.searchParams.get('slug') || HOME_SLUG).toLowerCase();
    const halaman = await db.prepare(
      `SELECT slug, judul, ringkasan, konten, coverImage, tataLetak, blok, updatedAt FROM halaman
       WHERE slug = ? AND status = 'publish'`
    ).bind(slug).first();
    if (!halaman) throw new HttpError(404, `Halaman "${slug}" tidak ditemukan atau belum dipublikasikan.`);
    // Sanitasi ulang saat disajikan — sama seperti `post.konten`, supaya
    // baris yang terlanjur tersimpan lewat jalur lain tetap aman dibaca.
    halaman.konten = sanitizeHtml(halaman.konten);
    // `blok` disimpan sebagai string JSON; kirim sudah ter-parse supaya tiap
    // klien tidak perlu mengulang parsing (dan menangani JSON rusak) sendiri.
    // Divalidasi ulang saat disajikan, sama alasannya dengan sanitasi konten:
    // baris lama yang terlanjur tersimpan lewat jalur lain ikut tersaring.
    halaman.blok = halaman.blok ? JSON.parse(normalizeBlok(halaman.blok) || 'null') : null;
    return json({ halaman });
  }

  // ---------- POHON MENU PUBLIK ----------
  // Dikirim sudah berbentuk pohon (induk + `children`), bukan daftar
  // datar: perakitannya butuh aturan yang sama persis dengan validasi di
  // atas (satu tingkat, menu nonaktif disembunyikan), jadi lebih aman
  // dikerjakan sekali di sini daripada diulang di tiap klien API.
  if (view === 'menu') {
    const { results } = await db.prepare(
      `SELECT id, parentId, label, tipe, target FROM menu
       WHERE status = 'aktif' ORDER BY urutan ASC, label ASC`
    ).all();
    const anak = new Map();
    for (const m of results) {
      if (!m.parentId) continue;
      if (!anak.has(m.parentId)) anak.set(m.parentId, []);
      anak.get(m.parentId).push(m);
    }
    const menu = results
      .filter(m => !m.parentId)
      .map(m => ({ ...m, children: anak.get(m.id) || [] }))
      // Menu induk tanpa submenu aktif tidak berguna (tidak bisa diklik,
      // tidak punya isi) — jangan tampilkan.
      .filter(m => m.tipe !== 'induk' || m.children.length);
    return json({ menu });
  }

  // ---------- DAFTAR ARTIKEL LINTAS-CMS ----------
  // Halaman "Artikel" situs: tulisan terbaru dari SEMUA penulis, supaya
  // pengunjung punya satu pintu masuk tanpa harus tahu kode CMS siapa pun.
  if (view === 'artikel-list') {
    const { results } = await db.prepare(
      `SELECT p.slug, p.judul, p.ringkasan, p.kategori, p.publishedAt,
              c.kodeCms, c.nama AS penulis
       FROM post p JOIN cms c ON c.id = p.cmsId
       WHERE p.status = 'publish' AND c.status = 'aktif' AND c.id != 'system'
       ORDER BY p.publishedAt DESC LIMIT 50`
    ).all();
    return json({ posts: results });
  }

  if (view === 'profile') {
    const cms = await db.prepare(
      `SELECT id, kodeCms, nama, bio, avatarUrl, status FROM cms WHERE kodeCms = ? AND status = 'aktif'`
    ).bind(userSlug).first();
    if (!cms) throw new HttpError(404, `CMS "${userSlug}" tidak ditemukan.`);
    const { results: posts } = await db.prepare(
      `SELECT slug, judul, ringkasan, kategori, publishedAt FROM post
       WHERE cmsId = ? AND status = 'publish' ORDER BY publishedAt DESC LIMIT 30`
    ).bind(cms.id).all();
    return json({ cms, posts });
  }

  if (view === 'artikel') {
    const cms = await db.prepare(
      `SELECT id, kodeCms, nama, bio, avatarUrl FROM cms WHERE kodeCms = ? AND status = 'aktif'`
    ).bind(userSlug).first();
    if (!cms) throw new HttpError(404, `CMS "${userSlug}" tidak ditemukan.`);
    const post = await db.prepare(
      `SELECT * FROM post WHERE cmsId = ? AND slug = ? AND status = 'publish'`
    ).bind(cms.id, postSlug).first();
    if (!post) throw new HttpError(404, `Artikel "${postSlug}" tidak ditemukan atau belum dipublikasikan.`);

    db.prepare(`UPDATE post SET views = views + 1 WHERE id = ?`).bind(post.id).run().catch(() => {});

    // Sanitasi ulang saat disajikan: melindungi juga baris lama yang
    // tersimpan sebelum sanitasi sisi-server ini ada.
    post.konten = sanitizeHtml(post.konten);

    const { results: komentar } = await db.prepare(
      `SELECT id, postId, nama, isi, createdAt FROM komentar
       WHERE postId = ? AND status = 'approved' ORDER BY createdAt ASC LIMIT 200`
    ).bind(post.id).all();

    return json({ cms, post, komentar });
  }

  // ---------- LOGIN ----------
  if (view === 'login' && request.method === 'POST') {
    const body = await request.json().catch(() => ({}));
    const kode = String(body.kodeCms || '').trim().toLowerCase();
    const username = String(body.username || '').trim();
    const password = String(body.password || '');
    const ip = clientIp(request);

    await rateLimitCheck(db, `login:ip:${ip}`, { max: 20, windowMs: 15 * 60_000, blockMs: 15 * 60_000 });
    await rateLimitCheck(db, `login:acc:${kode}:${username}`, { max: 5, windowMs: 15 * 60_000, blockMs: 15 * 60_000 });
    await verifyMathCaptcha(env, db, body.captchaToken, body.captchaAnswer, ip);

    if (!kode || !username || !password) throw new HttpError(400, 'Kode CMS, username, dan password wajib diisi.');

    const cms = await db.prepare(`SELECT * FROM cms WHERE kodeCms = ?`).bind(kode).first();
    const user = cms
      ? await db.prepare(`SELECT * FROM users WHERE cmsId = ? AND username = ?`).bind(cms.id, username).first()
      : null;

    // Selalu jalankan verifikasi (dengan hash dummy kalau user tidak ada)
    // supaya waktu respons tidak membocorkan username mana yang valid.
    const ok = await verifyPassword(password, user?.passwordHash || `pbkdf2$sha256$${PBKDF2_ITERATIONS}$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`);

    if (!cms || !user || !ok) {
      await rateLimitHit(db, `login:ip:${ip}`);
      await rateLimitHit(db, `login:acc:${kode}:${username}`);
      throw new HttpError(401, 'Kode CMS, username, atau password salah.');
    }
    if (cms.status === 'nonaktif') throw new HttpError(403, 'CMS ini sedang dinonaktifkan. Hubungi superadmin.');

    await rateLimitReset(db, `login:acc:${kode}:${username}`);
    const { token, payload } = await signSession(env, {
      uid: user.id, cid: cms.id, kode: cms.kodeCms, cmsNama: cms.nama,
      username: user.username, name: user.name, role: user.role,
    });
    return json({ token, expiresAt: payload.exp, user: sessionUserView(payload) });
  }

  // ---------- REGISTER ----------
  if (view === 'register' && request.method === 'POST') {
    const body = await request.json().catch(() => ({}));
    const ip = clientIp(request);
    await rateLimitCheck(db, `register:ip:${ip}`, { max: 5, windowMs: 60 * 60_000, blockMs: 60 * 60_000 });
    await verifyMathCaptcha(env, db, body.captchaToken, body.captchaAnswer, ip);
    await rateLimitHit(db, `register:ip:${ip}`);

    const kode = String(body.kodeCms || '').trim().toLowerCase();
    const namaCms = String(body.namaCms || '').trim().slice(0, 80);
    const ownerName = String(body.ownerName || '').trim().slice(0, 80);
    const username = String(body.username || '').trim();
    const password = String(body.password || '');

    if (!kode || !namaCms || !ownerName || !username || !password) throw new HttpError(400, 'Semua field bertanda * wajib diisi.');
    if (!SLUG_RE.test(kode)) throw new HttpError(400, 'Kode CMS harus 2-30 karakter: huruf kecil, angka, atau tanda strip.');
    if (!USERNAME_RE.test(username)) throw new HttpError(400, 'Username 3-40 karakter: huruf, angka, titik, garis bawah, atau strip.');
    if (password.length < 8) throw new HttpError(400, 'Password minimal 8 karakter.');

    const existing = await db.prepare(`SELECT id FROM cms WHERE kodeCms = ?`).bind(kode).first();
    if (existing) throw new HttpError(409, 'Kode CMS sudah dipakai, gunakan kode lain.');

    const now = new Date().toISOString();
    const cmsRecord = {
      id: genId('cms'), kodeCms: kode, nama: namaCms,
      bio: String(body.bio || '').slice(0, 300), avatarUrl: null,
      status: 'aktif', createdAt: now,
    };
    const userRecord = {
      id: genId('usr'), cmsId: cmsRecord.id, username,
      passwordHash: await hashPassword(password),
      name: ownerName, role: 'owner', createdAt: now,
    };
    try {
      await insertRow(db, 'cms', cmsRecord);
      await insertRow(db, 'users', userRecord);
    } catch (e) {
      if (String(e.message).includes('UNIQUE')) throw new HttpError(409, 'Kode CMS atau username sudah dipakai.');
      throw e;
    }

    const { token, payload } = await signSession(env, {
      uid: userRecord.id, cid: cmsRecord.id, kode: cmsRecord.kodeCms, cmsNama: cmsRecord.nama,
      username: userRecord.username, name: userRecord.name, role: 'owner',
    });
    return json({ token, expiresAt: payload.exp, user: sessionUserView(payload) }, 201);
  }

  // ---------- KOMENTAR (wajib login) ----------
  if (view === 'komentar' && request.method === 'POST') {
    const session = await requireSession(request, env);
    await rateLimitCheck(db, `komentar:${session.uid}`, { max: 10, windowMs: 60 * 60_000, blockMs: 15 * 60_000 });

    const cms = await db.prepare(`SELECT id FROM cms WHERE kodeCms = ? AND status = 'aktif'`).bind(userSlug).first();
    if (!cms) throw new HttpError(404, `CMS "${userSlug}" tidak ditemukan.`);
    const post = await db.prepare(`SELECT id FROM post WHERE cmsId = ? AND slug = ? AND status = 'publish'`)
      .bind(cms.id, postSlug).first();
    if (!post) throw new HttpError(404, `Artikel "${postSlug}" tidak ditemukan.`);

    const body = await request.json().catch(() => ({}));
    const isi = String(body.isi || '').trim().slice(0, 2000);
    if (!isi) throw new HttpError(400, 'Isi komentar wajib diisi.');

    // Identitas komentator diambil dari TOKEN, bukan dari body request —
    // `nama`/`userId` yang dikirim klien diabaikan sepenuhnya.
    const author = await db.prepare(`SELECT name FROM users WHERE id = ?`).bind(session.uid).first();

    const komentar = {
      id: genId('komentar'), cmsId: cms.id, postId: post.id,
      userId: session.uid, nama: author?.name || session.name || 'Pengguna',
      isi, status: 'approved', createdAt: new Date().toISOString(),
    };
    await insertRow(db, 'komentar', komentar);
    await rateLimitHit(db, `komentar:${session.uid}`);
    return json(komentar, 201);
  }

  throw new HttpError(400, `View '${view}' tidak dikenal`);
}

/** Bentuk objek sesi yang dikirim ke frontend — tanpa hash/kredensial apa pun. */
function sessionUserView(p) {
  return {
    cmsId: p.cid, cmsNama: p.cmsNama, cmsKode: p.kode,
    userId: p.uid, username: p.username, name: p.name, role: p.role,
  };
}

// ============================================================
// Entry point
// ============================================================
export default {
  async fetch(request, env) {
    const cors = corsHeaders(request, env);
    const url = new URL(request.url);

    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });

    try {
      if (url.pathname === '/api') {
        const res = await handleApi(request, env);
        return withHeaders(res, cors);
      }
      if (url.pathname === '/public') {
        const res = await handlePublic(request, env);
        return withHeaders(res, cors);
      }
    } catch (err) {
      if (err instanceof HttpError) return withHeaders(json({ error: err.message }, err.status), cors);
      // Pesan error internal TIDAK dibocorkan ke klien (bisa memuat SQL/struktur DB).
      console.error('cms-api error:', err?.stack || err);
      return withHeaders(json({ error: 'Terjadi kesalahan di server.' }, 500), cors);
    }

    return withHeaders(json({ error: 'Not found. Gunakan /api?table=... atau /public?view=...' }, 404), cors);
  },
};

function withHeaders(res, headers) {
  const out = new Response(res.body, res);
  for (const [k, v] of Object.entries(headers)) out.headers.set(k, v);
  return out;
}

// Diekspor untuk keperluan pengujian (tidak memengaruhi runtime Worker).
export const __test__ = {
  hashPassword, verifyPassword, signSession, verifySession,
  signToken, verifyToken, generateMathCaptcha, verifyMathCaptcha,
  sanitizeHtml, safeUrl, rateLimitCheck, rateLimitHit, pickColumns,
};
