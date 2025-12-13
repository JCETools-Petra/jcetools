-- ============================================================================
-- JCE Tools Database Schema
-- ============================================================================
-- Database untuk JCE Tools License Management System
-- Termasuk: user management, session keys, dan rate limiting
--
-- Cara menggunakan:
-- 1. Buka phpMyAdmin di cPanel
-- 2. Pilih database Anda (misal: apsx2353_jce-data)
-- 3. Klik tab "SQL"
-- 4. Copy-paste script ini dan klik "Go"
-- ============================================================================

-- ============================================================================
-- Tabel 1: user_jce
-- Menyimpan data user dan lisensi mereka
-- ============================================================================

CREATE TABLE IF NOT EXISTS `user_jce` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `Nama` VARCHAR(255) NOT NULL COMMENT 'Nama user/pelanggan',
  `hwid_encrypted` VARCHAR(512) NOT NULL COMMENT 'Hardware ID yang sudah dienkripsi',
  `expiry_date` DATE NOT NULL COMMENT 'Tanggal kedaluwarsa lisensi',
  `counter` INT(11) DEFAULT 0 COMMENT 'Jumlah login/akses',
  `last_login` TIMESTAMP NULL DEFAULT NULL COMMENT 'Waktu login terakhir',
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT 'Waktu data dibuat',
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_hwid` (`hwid_encrypted`),
  INDEX `idx_hwid` (`hwid_encrypted`),
  INDEX `idx_expiry` (`expiry_date`),
  INDEX `idx_nama` (`Nama`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Tabel user dan lisensi JCE Tools';

-- ============================================================================
-- Tabel 2: session_keys
-- Menyimpan session key untuk enkripsi dinamis (JWT authentication)
-- ============================================================================

CREATE TABLE IF NOT EXISTS `session_keys` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `session_id` VARCHAR(64) NOT NULL COMMENT 'ID session unik',
  `session_key` VARCHAR(128) NOT NULL COMMENT 'Encryption key untuk session ini',
  `session_iv` VARCHAR(64) NOT NULL COMMENT 'Initialization Vector untuk AES encryption',
  `client_ip` VARCHAR(45) NOT NULL COMMENT 'IP address client',
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT 'Waktu session dibuat',
  `expires_at` TIMESTAMP NOT NULL COMMENT 'Waktu session kadaluarsa',
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_session_id` (`session_id`),
  INDEX `idx_session_id` (`session_id`),
  INDEX `idx_expires` (`expires_at`),
  INDEX `idx_client_ip` (`client_ip`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Tabel session keys untuk JWT authentication';

-- ============================================================================
-- Tabel 3: rate_limits
-- Menyimpan data rate limiting untuk mencegah abuse/spam
-- ============================================================================

CREATE TABLE IF NOT EXISTS `rate_limits` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `identifier` VARCHAR(255) NOT NULL COMMENT 'IP address atau user identifier',
  `request_count` INT(11) DEFAULT 1 COMMENT 'Jumlah request dalam time window',
  `window_start` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT 'Waktu mulai counting window',
  `last_request` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT 'Waktu request terakhir',
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_identifier` (`identifier`),
  INDEX `idx_identifier` (`identifier`),
  INDEX `idx_window` (`window_start`),
  INDEX `idx_last_request` (`last_request`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Tabel rate limiting untuk API';

-- ============================================================================
-- Event untuk auto-cleanup (opsional, butuh EVENT scheduler aktif)
-- ============================================================================

-- Cleanup expired sessions (jalan otomatis setiap 1 jam)
DELIMITER $$
CREATE EVENT IF NOT EXISTS `cleanup_expired_sessions`
ON SCHEDULE EVERY 1 HOUR
DO BEGIN
  DELETE FROM `session_keys` WHERE `expires_at` < NOW();
END$$
DELIMITER ;

-- Cleanup old rate limit data (jalan otomatis setiap 1 hari)
DELIMITER $$
CREATE EVENT IF NOT EXISTS `cleanup_old_rate_limits`
ON SCHEDULE EVERY 1 DAY
DO BEGIN
  DELETE FROM `rate_limits` WHERE `last_request` < DATE_SUB(NOW(), INTERVAL 7 DAY);
END$$
DELIMITER ;

-- ============================================================================
-- Verifikasi tabel berhasil dibuat
-- ============================================================================

-- Tampilkan semua tabel yang baru dibuat
SHOW TABLES LIKE '%user_jce%';
SHOW TABLES LIKE '%session_keys%';
SHOW TABLES LIKE '%rate_limits%';

-- Tampilkan struktur tabel
DESCRIBE user_jce;
DESCRIBE session_keys;
DESCRIBE rate_limits;

-- ============================================================================
-- Sample data untuk testing (opsional)
-- ============================================================================

-- Uncomment baris di bawah ini jika ingin insert data testing
/*
INSERT INTO `user_jce` (`Nama`, `hwid_encrypted`, `expiry_date`) VALUES
('Test User 1', 'test_hwid_encrypted_12345', '2025-12-31'),
('Test User 2', 'test_hwid_encrypted_67890', '2025-12-31');
*/

-- ============================================================================
-- Selesai!
-- ============================================================================
-- Semua tabel sudah dibuat. Silakan test API endpoint:
-- 1. GET https://jcetools.my.id/api/auth/get-session-key.php
-- 2. POST https://jcetools.my.id/api/test/1.php
-- ============================================================================
