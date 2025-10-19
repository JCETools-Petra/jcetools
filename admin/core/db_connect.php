<?php
// File: admin/core/db_connect.php

// 1. Path yang Diperbaiki untuk Memuat Autoloader Composer
// __DIR__ adalah /admin/core, jadi kita naik dua level ke root (../../)
require_once __DIR__ . '/../../vendor/autoload.php';

try {
    // 2. Path yang Diperbaiki untuk Memuat file .env dari Root
    $dotenv = Dotenv\Dotenv::createImmutable(__DIR__ . '/../../');
    $dotenv->load();
} catch (\Dotenv\Exception\InvalidPathException $e) {
    // 3. Pesan Error yang Jelas Jika Gagal
    // Pesan ini akan ditampilkan jika file .env atau folder vendor tidak ada di root
    die("Error: Tidak dapat memuat file .env. Pastikan file tersebut ada di direktori root dan Anda telah menjalankan 'composer install'.");
}

// ===== KODE BARU (BENAR) =====

// Ambil kredensial database dari environment variables
$db_host = $_ENV['DB_HOST'];
$db_user = $_ENV['DB_USER'];
$db_pass = $_ENV['DB_PASS'];
$db_name = $_ENV['DB_NAME'];

// Buat koneksi ke database
$conn = new mysqli($db_host, $db_user, $db_pass, $db_name);

// Cek koneksi
if ($conn->connect_error) {
    die("Koneksi database gagal: " . $conn->connect_error);
}

// Set charset untuk koneksi agar mendukung berbagai karakter
$conn->set_charset("utf8mb4");
?>