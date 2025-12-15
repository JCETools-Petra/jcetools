<?php
// Tampilkan semua error
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// Load dotenv jika ada (sesuaikan path)
require_once __DIR__ . '/../vendor/autoload.php';
try {
    $dotenv = Dotenv\Dotenv::createImmutable(__DIR__ . '/..');
    $dotenv->load();
    echo "✅ .env berhasil dimuat.<br>";
    if(isset($_ENV['LOG_DIR'])) {
        echo "ℹ️ LOG_DIR dari .env: " . $_ENV['LOG_DIR'] . "<br>";
    } else {
        echo "ℹ️ LOG_DIR tidak diset di .env (Menggunakan default).<br>";
    }
} catch (Exception $e) {
    echo "⚠️ Tidak ada file .env atau error memuatnya.<br>";
}

// Set Timezone
date_default_timezone_set('Asia/Jakarta');

// Tentukan path log (sesuai logika 1.php)
$logDir = $_ENV['LOG_DIR'] ?? __DIR__ . '/../logs';
$logFile = $logDir . '/test_write.log';

echo "<h2>Diagnosa Log</h2>";
echo "Target Folder: " . realpath($logDir) . " (Raw: $logDir)<br>";
echo "Target File: $logFile<br><hr>";

// 1. Cek apakah folder ada
if (!is_dir($logDir)) {
    echo "❌ Folder tidak ditemukan. Mencoba membuat...<br>";
    if (mkdir($logDir, 0777, true)) {
        echo "✅ Folder berhasil dibuat.<br>";
    } else {
        echo "⛔ GAGAL membuat folder. Cek permission folder induk (public_html/jcetools.my.id).<br>";
        exit;
    }
} else {
    echo "✅ Folder logs ditemukan.<br>";
}

// 2. Cek apakah folder writable
if (is_writable($logDir)) {
    echo "✅ Folder memiliki izin tulis (Writable).<br>";
} else {
    echo "⛔ Folder TIDAK Writable. chmod folder 'logs' ke 777 via File Manager.<br>";
}

// 3. Coba tulis file
$testMessage = date('[Y-m-d H:i:s]') . " | Tes Log Berhasil Masuk!\n";
if (file_put_contents($logFile, $testMessage, FILE_APPEND)) {
    echo "✅ <b>SUKSES!</b> Berhasil menulis ke file log.<br>";
    echo "Silakan cek file: <code>$logFile</code>";
} else {
    echo "⛔ <b>GAGAL MENULIS FILE.</b> Ada masalah permission tingkat file atau disk penuh.";
    $error = error_get_last();
    if ($error) {
        echo "<br>Error System: " . $error['message'];
    }
}
?>