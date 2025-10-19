<?php
/**
 * Mendekripsi HWID dari format heksadesimal kembali ke teks biasa.
 *
 * @param string $ciphertext_hex HWID terenkripsi dalam format hex.
 * @return string|false HWID yang sudah didekripsi, atau false jika gagal.
 */
function decrypt_hwid(string $ciphertext_hex)
{
    // Kunci dan IV harus sama persis dengan yang digunakan saat enkripsi
    $key_string = "JCETOOLS-1830";
    $key = str_pad($key_string, 32, "\0", STR_PAD_RIGHT);

    $iv_hex = "1234567890abcdef1234567800000000";
    $iv = hex2bin($iv_hex);

    // Periksa apakah input adalah string heksadesimal yang valid
    if (!ctype_xdigit($ciphertext_hex)) {
        return false;
    }

    // Ubah heksadesimal kembali ke data biner mentah
    $ciphertext_raw = hex2bin($ciphertext_hex);

    // Lakukan dekripsi
    $decrypted_text = openssl_decrypt(
        $ciphertext_raw,
        'aes-256-cbc',
        $key,
        OPENSSL_RAW_DATA,
        $iv
    );

    return $decrypted_text;
}
?>