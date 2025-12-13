-- Migration: Add session_keys table for JWT session management
-- Date: 2025-12-13
-- Description: Creates session_keys table to store temporary session tokens for HWID encryption

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

-- Add cleanup event to automatically delete expired sessions
CREATE EVENT IF NOT EXISTS `cleanup_expired_sessions`
ON SCHEDULE EVERY 1 HOUR
DO
  DELETE FROM session_keys WHERE expires_at < NOW();
