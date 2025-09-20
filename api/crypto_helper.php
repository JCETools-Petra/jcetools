<?php
// Helper untuk enkripsi dan dekripsi payload antara server dan klien.

define('ENCRYPTION_METHOD', 'aes-256-cbc');

/**
 * Enkripsi data JSON menjadi format base64.
 *
 * @param string $json_data Data dalam format JSON.
 * @param string $secret_key Kunci rahasia 32-byte.
 * @return string|false String terenkripsi dalam base64, atau false jika gagal.
 */
function encrypt_payload(string $json_data, string $secret_key) {
    if (mb_strlen($secret_key, '8bit') !== 32) {
        // Kunci harus tepat 32 byte (256 bit)
        return false;
    }
    // IV (Initialization Vector) harus 16 byte untuk AES-256-CBC
    $iv = openssl_random_pseudo_bytes(16);
    $ciphertext = openssl_encrypt($json_data, ENCRYPTION_METHOD, $secret_key, OPENSSL_RAW_DATA, $iv);
    
    if ($ciphertext === false) {
        return false;
    }
    
    // Gabungkan IV dengan ciphertext, lalu encode ke base64
    // IV ditaruh di depan agar bisa diekstrak saat dekripsi
    return base64_encode($iv . $ciphertext);
}

/**
 * Dekripsi data base64 menjadi JSON.
 *
 * @param string $base64_encrypted Data terenkripsi dalam format base64.
 * @param string $secret_key Kunci rahasia 32-byte.
 * @return string|false String JSON yang sudah didekripsi, atau false jika gagal.
 */
function decrypt_payload(string $base64_encrypted, string $secret_key) {
    if (mb_strlen($secret_key, '8bit') !== 32) {
        return false;
    }
    
    $decoded_data = base64_decode($base64_encrypted, true);
    if ($decoded_data === false) {
        return false;
    }
    
    // Ekstrak IV dari awal data
    $iv_length = 16;
    $iv = substr($decoded_data, 0, $iv_length);
    $ciphertext = substr($decoded_data, $iv_length);
    
    if (strlen($iv) !== $iv_length) {
        return false;
    }

    $decrypted = openssl_decrypt($ciphertext, ENCRYPTION_METHOD, $secret_key, OPENSSL_RAW_DATA, $iv);
    
    return $decrypted;
}