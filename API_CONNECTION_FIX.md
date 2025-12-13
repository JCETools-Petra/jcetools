# 🔧 JCE Tools - Perbaikan Masalah Koneksi API

## 📋 Ringkasan Masalah

C++ Launcher tidak bisa connect ke API di shared hosting meskipun folder `vendor` dan file `.env` sudah berada di lokasi yang benar (`public_html/jcetools.my.id/`).

## 🔍 Analisis Masalah

### Masalah Ditemukan

1. **File `.htaccess` salah konfigurasi** ⚠️
   - Semua request ke `/api/*` di-redirect ke `jcetools-check.php`
   - Menyebabkan endpoint baru (`/api/test/1.php` dan `/api/auth/get-session-key.php`) tidak bisa diakses
   - Request menggunakan autentikasi JWT Token tapi diarahkan ke file lama yang pakai API Key

2. **Error yang terlihat di log:**
   ```
   [11-Sep-2025 21:16:36] Invalid API Key
   ```
   Artinya: Request **BERHASIL sampai ke server**, tapi diarahkan ke file yang salah!

### Struktur Folder (Sudah Benar) ✅

```
public_html/jcetools.my.id/
├── vendor/              ✅ Sudah ada (Composer dependencies)
│   ├── autoload.php
│   ├── vlucas/phpdotenv/
│   └── firebase/php-jwt/
├── .env                 ✅ Sudah ada (Konfigurasi database)
└── api/
    ├── .htaccess        ⚠️ INI YANG BERMASALAH!
    ├── jcetools-check.php (file lama, pakai API Key)
    ├── test/
    │   └── 1.php       ← Endpoint baru (pakai JWT Token)
    └── auth/
        └── get-session-key.php  ← Endpoint session key
```

### Alur Koneksi Yang Seharusnya

```
C++ Launcher
    ↓
1. Request session key
   POST https://jcetools.my.id/api/auth/get-session-key.php
    ↓
2. Dapat JWT Token
   {"status":"success", "session_token":"eyJ0eXAi..."}
    ↓
3. Request HWID validation dengan JWT Token
   POST https://jcetools.my.id/api/test/1.php
   Header: Authorization: Bearer eyJ0eXAi...
   Body: {"hwid":"encrypted_hwid_here"}
    ↓
4. Dapat response
   {"status":"success", "message":"Access granted"}
```

### Alur Yang Terjadi Sebelumnya (SALAH) ❌

```
C++ Launcher
    ↓
Request https://jcetools.my.id/api/test/1.php
    ↓
.htaccess redirect → jcetools-check.php (file lama!)
    ↓
Error: Invalid API Key (karena file lama pakai API Key, bukan JWT)
```

## ✅ Solusi Yang Diterapkan

### 1. Perbaikan File `.htaccess`

**Lokasi**: `public_html/jcetools.my.id/api/.htaccess`

**Perubahan yang dilakukan:**

Menambahkan exception untuk endpoint API baru:

```apache
<IfModule mod_rewrite.c>
    RewriteEngine On

    # [PERBAIKAN] Exclude API endpoints dari rewrite
    # Izinkan akses langsung ke folder /test/ dan /auth/
    RewriteCond %{REQUEST_URI} !^/api/test/
    RewriteCond %{REQUEST_URI} !^/api/auth/
    RewriteCond %{REQUEST_URI} !^/api/utils/

    # Izinkan akses langsung jika file atau direktori benar-benar ada
    RewriteCond %{REQUEST_FILENAME} !-f
    RewriteCond %{REQUEST_FILENAME} !-d

    # Arahkan semua request lain ke skrip utama PHP
    RewriteRule ^(.*)$ jcetools-check.php [L,QSA]
</IfModule>
```

**Penjelasan:**
- `RewriteCond %{REQUEST_URI} !^/api/test/` → JANGAN redirect request ke `/api/test/*`
- `RewriteCond %{REQUEST_URI} !^/api/auth/` → JANGAN redirect request ke `/api/auth/*`
- Request ke endpoint lain tetap di-redirect ke `jcetools-check.php` (untuk backward compatibility)

## 🚀 Langkah Deploy ke Shared Hosting

### Langkah 1: Upload File yang Diperbaiki

Upload file `.htaccess` yang sudah diperbaiki ke:
```
public_html/jcetools.my.id/api/.htaccess
```

### Langkah 2: Pastikan Struktur Folder Benar

Cek struktur folder di hosting:

```bash
cd public_html/jcetools.my.id
ls -la
```

Harus ada:
- ✅ Folder `vendor/`
- ✅ File `.env`
- ✅ Folder `api/`

### Langkah 3: Cek File .env

File `.env` harus berisi konfigurasi yang benar:

```env
DB_HOST=localhost
DB_USER=your_db_username
DB_PASS=your_db_password
DB_NAME=your_db_name

API_KEY=your_api_key_here
JWT_SECRET=your_jwt_secret_key_minimum_64_characters
```

### Langkah 4: Cek Permission File

```bash
# Permission folder
chmod 755 api/
chmod 755 api/test/
chmod 755 api/auth/

# Permission file .htaccess
chmod 644 api/.htaccess

# Permission file .env (harus protected)
chmod 600 .env
```

### Langkah 5: Test API Endpoint

**Test 1: Request Session Key**

```bash
curl -X POST https://jcetools.my.id/api/auth/get-session-key.php
```

**Response yang diharapkan:**
```json
{
    "status": "success",
    "session_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "expires_in": 300,
    "message": "Session key generated successfully"
}
```

**Test 2: Request HWID Validation**

Gunakan token dari Test 1:

```bash
curl -X POST https://jcetools.my.id/api/test/1.php \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_SESSION_TOKEN_HERE" \
  -d '{"hwid":"test_hwid_encrypted"}'
```

**Response yang diharapkan:**
```json
{
    "status": "error",
    "message": "Access denied.",
    "code": "NOT_FOUND"
}
```
(Error NOT_FOUND normal jika HWID belum terdaftar di database)

## 🔍 Troubleshooting

### Problem: Masih dapat error "Invalid API Key"

**Penyebab:**
- File `.htaccess` belum ter-update di server
- Cache browser/server masih menyimpan konfigurasi lama

**Solusi:**
1. Pastikan file `.htaccess` sudah ter-upload
2. Clear cache server (jika ada cPanel: Tools → Cache Manager)
3. Test dengan curl (bukan browser) untuk bypass cache
4. Restart Apache (jika punya akses)

### Problem: Error "Server configuration error"

**Penyebab:**
- File `.env` tidak ditemukan atau tidak bisa dibaca

**Solusi:**
1. Pastikan `.env` ada di `public_html/jcetools.my.id/.env`
2. Cek permission: `chmod 644 .env`
3. Cek isi file `.env` (harus ada DB_HOST, DB_USER, dll)

### Problem: Error "Database connection error"

**Penyebab:**
- Kredensial database di `.env` salah
- Database belum dibuat

**Solusi:**
1. Buat database di cPanel → MySQL Databases
2. Update `.env` dengan kredensial yang benar
3. Import struktur tabel (lihat DEPLOYMENT_GUIDE.md)

### Problem: Error 500 Internal Server Error

**Penyebab:**
- Syntax error di `.htaccess`
- PHP extension tidak aktif
- Folder `vendor` tidak ada

**Solusi:**
1. Cek error log di cPanel
2. Cek PHP extensions: `mysqli`, `json`, `openssl`, `mbstring`
3. Pastikan folder `vendor` sudah ter-upload lengkap
4. Test dengan rename `.htaccess` jadi `.htaccess.bak` untuk isolasi masalah

## 📊 Cara Verifikasi Perbaikan Berhasil

### 1. Cek Error Log

```bash
tail -f api/error.log
```

**Sebelum perbaikan:**
```
[11-Sep-2025 21:16:36] Invalid API Key
[11-Sep-2025 21:16:37] Invalid API Key
```

**Setelah perbaikan:**
```
[Success] Valid access - User: JohnDoe - Expires: 2025-12-31
```

### 2. Test dengan cURL

Request harus mendapat response JSON yang valid (bukan redirect HTML).

### 3. Test dari C++ Launcher

Jalankan launcher, seharusnya tidak ada error lagi dan bisa login.

## 📝 Catatan Penting

1. **Backward Compatibility**: File `jcetools-check.php` (API lama) masih bisa diakses untuk compatibility
2. **Security**: Pastikan JWT_SECRET di `.env` adalah string random minimal 64 karakter
3. **SSL**: Pastikan website menggunakan HTTPS (sudah ada di .htaccess)
4. **Rate Limiting**: Sudah aktif di endpoint baru (max 10 request/menit per IP)

## 🎯 Kesimpulan

**Masalah:** File `.htaccess` mengarahkan semua request ke file lama yang pakai API Key

**Solusi:** Menambahkan exception di `.htaccess` agar endpoint baru bisa diakses langsung

**Hasil:** C++ Launcher sekarang bisa connect ke API dan melakukan autentikasi dengan JWT Token

---

**Dibuat:** 13 Desember 2025
**Update Terakhir:** 13 Desember 2025
**Versi:** 1.0
