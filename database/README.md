# 🗄️ JCE Tools - Setup Database

## 📋 Error Yang Terjadi

```
PHP Fatal error: Table 'apsx2353_jce-data.session_keys' doesn't exist
```

**Artinya:** Tabel `session_keys` belum dibuat di database.

## ✅ Solusi: Buat Tabel Database

Anda perlu membuat 3 tabel di database:

1. ✅ `user_jce` - Menyimpan data user dan lisensi
2. ❌ `session_keys` - Menyimpan session key untuk JWT (BELUM ADA - ini yang error!)
3. ❌ `rate_limits` - Menyimpan data rate limiting

## 🚀 Langkah-langkah Setup Database

### Metode 1: Via phpMyAdmin (Paling Mudah) 👍

**Step 1: Login ke cPanel**

1. Buka browser, akses cPanel Anda
2. Login dengan username dan password cPanel

**Step 2: Buka phpMyAdmin**

1. Di cPanel, cari "phpMyAdmin"
2. Klik untuk membuka phpMyAdmin

**Step 3: Pilih Database**

1. Di sidebar kiri, klik database Anda (misal: `apsx2353_jce-data`)
2. Pastikan database sudah dipilih (akan terlihat di menu atas)

**Step 4: Import SQL Script**

1. Klik tab **"SQL"** di menu atas
2. Buka file `database/schema.sql` di text editor
3. **Copy semua isi file** (Ctrl+A → Ctrl+C)
4. **Paste** ke kotak SQL di phpMyAdmin
5. Klik tombol **"Go"** di kanan bawah

**Step 5: Verifikasi Berhasil**

Setelah klik "Go", Anda akan melihat:

✅ Message: "3 queries executed successfully"

Di sidebar kiri, Anda akan melihat tabel baru:
- ✅ user_jce
- ✅ session_keys (baru dibuat!)
- ✅ rate_limits (baru dibuat!)

### Metode 2: Via MySQL Command Line (Untuk Advanced User)

Jika punya akses SSH:

```bash
# Login ke MySQL
mysql -u your_username -p your_database_name

# Jalankan SQL script
source /path/to/jcetools/database/schema.sql

# Atau copy-paste manual
mysql -u your_username -p your_database_name < database/schema.sql
```

## 📊 Struktur Tabel Yang Dibuat

### Tabel 1: `user_jce`

Menyimpan data user dan lisensi mereka.

| Kolom | Tipe | Keterangan |
|-------|------|------------|
| id | INT | Primary key, auto increment |
| Nama | VARCHAR(255) | Nama user/pelanggan |
| hwid_encrypted | VARCHAR(512) | Hardware ID terenkripsi (UNIQUE) |
| expiry_date | DATE | Tanggal kedaluwarsa lisensi |
| counter | INT | Jumlah login/akses |
| last_login | TIMESTAMP | Waktu login terakhir |
| created_at | TIMESTAMP | Waktu data dibuat |

**Contoh data:**

```sql
INSERT INTO user_jce (Nama, hwid_encrypted, expiry_date) VALUES
('John Doe', 'abc123def456...', '2025-12-31');
```

### Tabel 2: `session_keys` ⭐ (YANG ERROR)

Menyimpan session key untuk enkripsi dinamis JWT authentication.

| Kolom | Tipe | Keterangan |
|-------|------|------------|
| id | INT | Primary key, auto increment |
| session_id | VARCHAR(64) | ID session unik |
| session_key | VARCHAR(128) | Encryption key (AES-256) |
| session_iv | VARCHAR(64) | Initialization Vector |
| client_ip | VARCHAR(45) | IP address client |
| created_at | TIMESTAMP | Waktu session dibuat |
| expires_at | TIMESTAMP | Waktu session kadaluarsa (5 menit) |

**Cara kerja:**
1. Client request session key → server generate random key + IV
2. Server simpan di tabel ini dengan expiry 5 menit
3. Client pakai key ini untuk encrypt HWID
4. Server validasi dengan key yang sama dari tabel ini

### Tabel 3: `rate_limits`

Menyimpan data rate limiting untuk mencegah spam/abuse.

| Kolom | Tipe | Keterangan |
|-------|------|------------|
| id | INT | Primary key, auto increment |
| identifier | VARCHAR(255) | IP address atau identifier |
| request_count | INT | Jumlah request dalam window |
| window_start | TIMESTAMP | Waktu mulai counting |
| last_request | TIMESTAMP | Waktu request terakhir |

**Cara kerja:**
- Max 10 request per menit per IP untuk endpoint `/api/test/1.php`
- Max 20 request per menit per IP untuk endpoint `/api/auth/get-session-key.php`
- Auto cleanup setiap 7 hari

## 🧪 Testing Setelah Setup

### Test 1: Cek Tabel Sudah Ada

Di phpMyAdmin, klik database Anda, harus terlihat:

```
✅ rate_limits
✅ session_keys
✅ user_jce
```

### Test 2: Test API Endpoint Session Key

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

### Test 3: Cek Data di Tabel session_keys

Di phpMyAdmin:

1. Klik tabel `session_keys`
2. Klik tab "Browse"
3. Harus ada 1 row data baru dengan:
   - session_id = (random string)
   - expires_at = (5 menit dari sekarang)

### Test 4: Test HWID Validation (Akan Error Karena HWID Belum Terdaftar)

```bash
# Ambil session token dari Test 2
SESSION_TOKEN="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."

# Test validation
curl -X POST https://jcetools.my.id/api/test/1.php \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $SESSION_TOKEN" \
  -d '{"hwid":"test_hwid_12345"}'
```

**Response yang diharapkan:**
```json
{
  "status": "error",
  "message": "Access denied.",
  "code": "NOT_FOUND"
}
```

**Ini NORMAL!** Error "NOT_FOUND" berarti:
- ✅ API endpoint berfungsi
- ✅ Session token valid
- ✅ Database connection OK
- ❌ HWID belum terdaftar di database (ini normal karena belum ada user)

## 📝 Menambahkan User Baru

Untuk menambahkan user dengan HWID yang valid:

### Step 1: Dapatkan HWID Terenkripsi

Jalankan C++ launcher, cek file log untuk melihat HWID terenkripsi yang dikirim.

Atau gunakan script PHP berikut untuk encrypt HWID:

```php
<?php
// File: api/generate-hwid.php
require_once __DIR__ . '/../vendor/autoload.php';

$dotenv = Dotenv\Dotenv::createImmutable(__DIR__ . '/..');
$dotenv->load();

// HWID dari volume serial number (contoh: 1234567890)
$hwid_raw = "1234567890"; // Ganti dengan HWID asli

// Encrypt menggunakan key dari session
// (Untuk testing, gunakan dummy key)
$key = bin2hex(random_bytes(32));
$iv = bin2hex(random_bytes(16));

function encrypt_hwid($plaintext, $key, $iv) {
    $key_bin = hex2bin($key);
    $iv_bin = hex2bin($iv);
    $encrypted = openssl_encrypt($plaintext, 'AES-256-CBC', $key_bin, OPENSSL_RAW_DATA, $iv_bin);
    return bin2hex($encrypted);
}

$hwid_encrypted = encrypt_hwid($hwid_raw, $key, $iv);

echo "HWID Raw: $hwid_raw\n";
echo "HWID Encrypted: $hwid_encrypted\n";
echo "\nInsert SQL:\n";
echo "INSERT INTO user_jce (Nama, hwid_encrypted, expiry_date) VALUES\n";
echo "('Your Name', '$hwid_encrypted', '2025-12-31');\n";
?>
```

### Step 2: Insert User ke Database

Di phpMyAdmin:

1. Klik tabel `user_jce`
2. Klik tab "Insert"
3. Isi data:
   - Nama: `Test User`
   - hwid_encrypted: `(hasil dari script di atas)`
   - expiry_date: `2025-12-31`
4. Klik "Go"

**Atau pakai SQL:**

```sql
INSERT INTO user_jce (Nama, hwid_encrypted, expiry_date) VALUES
('Test User', 'hwid_encrypted_dari_script_di_atas', '2025-12-31');
```

## 🔧 Troubleshooting

### Error: "Table already exists"

**Penyebab:** Tabel sudah ada di database

**Solusi:**
- Jika tabel kosong/corrupt, drop dulu: `DROP TABLE session_keys;`
- Lalu jalankan lagi SQL script

### Error: "Access denied for user"

**Penyebab:** User MySQL tidak punya permission

**Solusi:**
1. Cek di cPanel → MySQL Databases
2. Pastikan user sudah di-assign ke database
3. Pastikan user punya privilege: SELECT, INSERT, UPDATE, DELETE, CREATE

### Error: "Unknown database"

**Penyebab:** Database belum dibuat

**Solusi:**
1. Di cPanel → MySQL Databases
2. Buat database baru (misal: `apsx2353_jce-data`)
3. Update file `.env` dengan nama database yang benar

### Auto-cleanup Event Tidak Jalan

**Penyebab:** MySQL Event Scheduler tidak aktif

**Solusi (opsional):**

```sql
-- Cek status event scheduler
SHOW VARIABLES LIKE 'event_scheduler';

-- Aktifkan (butuh SUPER privilege, mungkin tidak tersedia di shared hosting)
SET GLOBAL event_scheduler = ON;
```

Jika tidak bisa aktifkan, tidak masalah. Anda bisa manual cleanup dengan:

```sql
-- Cleanup manual expired sessions
DELETE FROM session_keys WHERE expires_at < NOW();

-- Cleanup manual old rate limits
DELETE FROM rate_limits WHERE last_request < DATE_SUB(NOW(), INTERVAL 7 DAY);
```

## 📚 File Terkait

- `database/schema.sql` - SQL script untuk membuat tabel
- `api/auth/get-session-key.php` - Endpoint untuk request session key
- `api/test/1.php` - Endpoint untuk HWID validation
- `.env` - Konfigurasi database connection

## ✅ Checklist Setup

- [ ] Login ke cPanel
- [ ] Buka phpMyAdmin
- [ ] Pilih database (misal: `apsx2353_jce-data`)
- [ ] Klik tab "SQL"
- [ ] Copy-paste isi file `database/schema.sql`
- [ ] Klik "Go"
- [ ] Verifikasi 3 tabel sudah dibuat (user_jce, session_keys, rate_limits)
- [ ] Test endpoint: `curl -X POST https://jcetools.my.id/api/auth/get-session-key.php`
- [ ] Response harus return JWT token (tidak error lagi!)
- [ ] Test dari C++ Launcher

Setelah semua checklist selesai, program Anda seharusnya sudah bisa connect! 🎉
