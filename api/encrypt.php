<?php

function encrypt_hwid(string $plaintext): string
{
    // Kunci dan IV harus dalam format biner
    $key_string = "JCETOOLS-1830";
    $key = str_pad($key_string, 32, "\0", STR_PAD_RIGHT);

    // IV diubah menjadi 16 byte (32 karakter hex)
    $iv_hex = "1234567890abcdef1234567800000000";
    $iv = hex2bin($iv_hex);

    // Enkripsi data
    $ciphertext_raw = openssl_encrypt(
        $plaintext,
        'aes-256-cbc',
        $key,
        OPENSSL_RAW_DATA,
        $iv
    );

    // Konversi hasil enkripsi (binary) ke format heksadesimal
    return bin2hex($ciphertext_raw);
}

?>