# JCE Tools API - Panduan Deployment ke Shared Hosting

## 📋 Masalah yang Ditemukan

Program tidak bisa connect ke API karena:

1. **Folder `vendor` tidak ada** - Dependencies PHP (Composer packages) belum diinstall
2. **File `.env` tidak ada** - Konfigurasi database dan security keys belum dibuat
3. **Struktur folder salah** - Vendor dan .env harus berada di level yang sama dengan folder `api`

## 🔧 Solusi: Struktur Folder yang Benar

Struktur folder yang harus ada di shared hosting:

```
public_html/jcetools.my.id/
├── vendor/                    ← Folder dependencies (hasil composer install)
│   ├── autoload.php
│   ├── vlucas/
│   ├── firebase/
│   └── ...
├── .env                       ← File konfigurasi (copy dari .env.example)
├── composer.json              ← File konfigurasi Composer
├── .htaccess                  ← (opsional) untuk keamanan tambahan
└── api/                       ← Folder API Anda
    ├── test/
    │   ├── 1.php
    │   ├── auth/
    │   └── utils/
    ├── auth/
    │   └── get-session-key.php
    ├── utils/
    │   ├── TokenManager.php
    │   └── RateLimiter.php
    └── ...
```

## 📦 Langkah-langkah Deployment

### Langkah 1: Upload Semua File

Upload ke shared hosting Anda di folder `public_html/jcetools.my.id/`:

- ✅ Folder `api/` (semua isi nya)
- ✅ File `composer.json`
- ✅ File `.env.example`

### Langkah 2: Install Composer Dependencies

**PENTING:** Anda harus install dependencies PHP menggunakan Composer.

#### Opsi A: Menggunakan SSH (Jika Tersedia)

Jika hosting Anda support SSH:

```bash
# Login ke SSH
ssh username@your-hosting.com

# Masuk ke folder website
cd public_html/jcetools.my.id

# Install dependencies
composer install --no-dev --optimize-autoloader
```

#### Opsi B: Menggunakan cPanel (PHP Composer Manager)

Banyak shared hosting menyediakan "Composer Manager" di cPanel:

1. Login ke cPanel
2. Cari "Select PHP Version" atau "MultiPHP Manager"
3. Pilih PHP 7.4 atau lebih tinggi
4. Cari "Composer" atau "PHP Composer"
5. Arahkan ke folder `public_html/jcetools.my.id`
6. Klik "Install Dependencies"

#### Opsi C: Upload Folder `vendor` Secara Manual

Jika hosting tidak support Composer, Anda bisa install di komputer lokal lalu upload:

```bash
# Di komputer lokal (Windows/Linux/Mac)
cd /path/to/jcetools
composer install --no-dev --optimize-autoloader

# Kemudian upload folder 'vendor' yang sudah jadi ke hosting
# Gunakan FTP/SFTP untuk upload folder 'vendor' ke:
# public_html/jcetools.my.id/vendor/
```

### Langkah 3: Setup File .env

1. Copy file `.env.example` menjadi `.env`:
   ```bash
   cp .env.example .env
   ```

2. Edit file `.env` dengan editor (vim, nano, atau File Manager di cPanel):
   ```bash
   nano .env
   ```

3. Isi dengan konfigurasi database Anda:
   ```env
   DB_HOST=localhost
   DB_USER=apsx2353_jceuser
   DB_PASS=password_database_anda
   DB_NAME=apsx2353_jcetools

   API_KEY=buatlah_kunci_rahasia_minimal_32_karakter_disini
   JWT_SECRET=buatlah_jwt_secret_minimal_64_karakter_sangat_panjang_dan_aman
   ```

### Langkah 4: Buat Database dan Tabel

Buat database MySQL dan tabel yang dibutuhkan:

```sql
-- Tabel user_jce (untuk menyimpan data lisensi user)
CREATE TABLE IF NOT EXISTS user_jce (
    id INT AUTO_INCREMENT PRIMARY KEY,
    Nama VARCHAR(255) NOT NULL,
    hwid_encrypted VARCHAR(512) NOT NULL UNIQUE,
    expiry_date DATE NOT NULL,
    counter INT DEFAULT 0,
    last_login TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_hwid (hwid_encrypted),
    INDEX idx_expiry (expiry_date)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Tabel session_keys (untuk session token management)
CREATE TABLE IF NOT EXISTS session_keys (
    id INT AUTO_INCREMENT PRIMARY KEY,
    session_id VARCHAR(64) UNIQUE NOT NULL,
    session_key VARCHAR(128) NOT NULL,
    session_iv VARCHAR(64) NOT NULL,
    client_ip VARCHAR(45) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    INDEX idx_session_id (session_id),
    INDEX idx_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Tabel rate_limits (untuk rate limiting)
CREATE TABLE IF NOT EXISTS rate_limits (
    id INT AUTO_INCREMENT PRIMARY KEY,
    identifier VARCHAR(255) NOT NULL,
    request_count INT DEFAULT 1,
    window_start TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_request TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY unique_identifier (identifier),
    INDEX idx_identifier (identifier),
    INDEX idx_window (window_start)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

### Langkah 5: Set Permissions (Izin Folder)

Pastikan permissions sudah benar:

```bash
# Folder api dan subfolder
chmod 755 api/
chmod 755 api/test/
chmod 755 api/auth/

# File PHP
find api/ -type f -name "*.php" -exec chmod 644 {} \;

# File .env harus dilindungi
chmod 600 .env

# Vendor folder
chmod -R 755 vendor/
```

### Langkah 6: Keamanan Tambahan (Opsional tapi Direkomendasikan)

Buat file `.htaccess` di root folder `public_html/jcetools.my.id/`:

```apache
# Lindungi file .env agar tidak bisa diakses dari browser
<Files .env>
    Order allow,deny
    Deny from all
</Files>

# Lindungi file composer
<FilesMatch "^(composer\.json|composer\.lock)$">
    Order allow,deny
    Deny from all
</FilesMatch>

# Aktifkan HTTPS (jika sudah ada SSL)
<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteCond %{HTTPS} off
    RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]
</IfModule>
```

### Langkah 7: Testing

Test API endpoint Anda:

**1. Test Session Key Generator:**
```bash
curl -X POST https://jcetools.my.id/api/auth/get-session-key.php
```

Response yang diharapkan:
```json
{
    "status": "success",
    "session_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
    "expires_in": 300,
    "message": "Session key generated successfully"
}
```

**2. Test HWID Validation:**
```bash
curl -X POST https://jcetools.my.id/api/test/1.php \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_SESSION_TOKEN" \
  -d '{"hwid":"test_encrypted_hwid"}'
```

## 🚨 Troubleshooting

### Error: "Server configuration error"

**Penyebab:** File `.env` tidak ditemukan atau tidak bisa dibaca

**Solusi:**
1. Pastikan file `.env` ada di folder yang benar
2. Cek permissions: `chmod 644 .env`
3. Pastikan path di PHP benar

### Error: "Class 'Dotenv\Dotenv' not found"

**Penyebab:** Folder `vendor` tidak ada atau autoload tidak ter-generate

**Solusi:**
1. Jalankan `composer install`
2. Atau upload folder `vendor` secara manual

### Error: "Database connection error"

**Penyebab:** Konfigurasi database di `.env` salah

**Solusi:**
1. Cek kredensial database di `.env`
2. Pastikan database sudah dibuat
3. Test koneksi database dari cPanel

### Error: "Failed to open stream: No such file or directory"

**Penyebab:** Struktur folder tidak sesuai

**Solusi:**
Pastikan struktur folder seperti ini:
```
public_html/jcetools.my.id/
├── vendor/      ← Harus ada!
├── .env         ← Harus ada!
└── api/
```

## 📞 Dukungan

Jika masih ada masalah, periksa:
1. Error log di `api/error.log`
2. PHP error log di cPanel
3. Versi PHP (minimal 7.4)
4. Extensions PHP yang aktif: `mysqli`, `json`, `openssl`, `mbstring`

## ✅ Checklist Deployment

- [ ] Upload folder `api/` ke hosting
- [ ] Upload file `composer.json` ke hosting
- [ ] Install Composer dependencies (buat folder `vendor/`)
- [ ] Copy `.env.example` menjadi `.env`
- [ ] Edit `.env` dengan konfigurasi database
- [ ] Buat database MySQL
- [ ] Import tabel SQL (user_jce, session_keys, rate_limits)
- [ ] Set permissions folder dan file
- [ ] Buat `.htaccess` untuk keamanan
- [ ] Test API endpoint
- [ ] Test dari C++ launcher

Setelah semua langkah selesai, launcher C++ Anda seharusnya bisa connect ke API!
