# Fix untuk Error "Code: 202" - Tabel session_keys Tidak Ada

## Masalah

Error yang muncul:
```
2025-12-13 16:51:49 | Session key obtained successfully
2025-12-13 16:51:49 | JWT token parsed successfully
2025-12-13 16:51:49 | Using dynamic encryption keys from session
2025-12-13 16:51:49 | ERROR: Gagal memahami respons dari server. (Code: 202)
```

**Penyebab:** Tabel `session_keys` belum ada di database `apsx2353_jce-data`

## Solusi (Pilih Salah Satu)

### Opsi 1: Manual via phpMyAdmin (DIREKOMENDASIKAN)

1. **Login ke phpMyAdmin** di hosting Anda
2. **Pilih database** `apsx2353_jce-data`
3. **Klik tab "SQL"**
4. **Copy paste SQL berikut:**

```sql
CREATE TABLE IF NOT EXISTS `session_keys` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `session_id` varchar(64) NOT NULL,
  `session_key` varchar(128) NOT NULL,
  `session_iv` varchar(64) NOT NULL,
  `client_ip` varchar(45) NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `expires_at` timestamp NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `session_id` (`session_id`),
  KEY `idx_session_id` (`session_id`),
  KEY `idx_expires` (`expires_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
```

5. **Klik "Go"** untuk menjalankan
6. **Refresh aplikasi** dan coba lagi

### Opsi 2: Otomatis (Alternatif)

Tabel akan dibuat otomatis saat Anda memanggil endpoint:
```
https://jcetools.my.id/api/auth/get-session-key.php
```

Namun, ini mungkin tidak bekerja jika ada permission issue.

## Verifikasi

Setelah membuat tabel, cek di phpMyAdmin:
1. Buka database `apsx2353_jce-data`
2. Lihat daftar tabel
3. Pastikan tabel `session_keys` ada dengan 7 kolom:
   - id
   - session_id
   - session_key
   - session_iv
   - client_ip
   - created_at
   - expires_at

## Struktur Tabel yang Benar

```
+-------------+--------------+------+-----+-------------------+
| Field       | Type         | Null | Key | Default           |
+-------------+--------------+------+-----+-------------------+
| id          | int(11)      | NO   | PRI | NULL              |
| session_id  | varchar(64)  | NO   | UNI | NULL              |
| session_key | varchar(128) | NO   |     | NULL              |
| session_iv  | varchar(64)  | NO   |     | NULL              |
| client_ip   | varchar(45)  | NO   |     | NULL              |
| created_at  | timestamp    | NO   |     | CURRENT_TIMESTAMP |
| expires_at  | timestamp    | NO   |     | NULL              |
+-------------+--------------+------+-----+-------------------+
```

## Penjelasan

Tabel `session_keys` digunakan untuk:
- Menyimpan session token sementara untuk enkripsi HWID
- Validasi session antara client dan server
- Meningkatkan keamanan dengan dynamic encryption keys
- Session expired otomatis setelah 5 menit

## Maintenance

Untuk membersihkan session yang sudah expired secara otomatis, jalankan SQL ini (opsional):

```sql
CREATE EVENT IF NOT EXISTS `cleanup_expired_sessions`
ON SCHEDULE EVERY 1 HOUR
DO
  DELETE FROM session_keys WHERE expires_at < NOW();
```

Atau bisa dibersihkan manual dengan query:
```sql
DELETE FROM session_keys WHERE expires_at < NOW();
```

## Masih Ada Masalah?

Jika setelah membuat tabel masih error, cek:
1. ✅ File `.env` sudah diconfig dengan benar
2. ✅ Database credentials benar
3. ✅ User database punya permission untuk CREATE TABLE
4. ✅ Cek error log di hosting: `/home/apsx2353/public_html/jcetools.my.id/api/auth/error_log`
