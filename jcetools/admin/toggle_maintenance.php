<?php
session_start();
require_once 'core/db_connect.php';

// Keamanan: Cek CSRF token dan pastikan hanya user 'joshhh'
if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token'] || !isset($_SESSION['username']) || $_SESSION['username'] !== 'joshhh') {
    die('Akses ditolak.');
}

// Ambil status saat ini
$result = $conn->query("SELECT setting_value FROM settings WHERE setting_key = 'maintenance_mode'");
if (!$result || $result->num_rows === 0) {
    die('Error: Kunci pengaturan maintenance_mode tidak ditemukan di database.');
}
$current_status = $result->fetch_assoc()['setting_value'];

// Tentukan status baru
$new_status = ($current_status === 'on') ? 'off' : 'on';

// Update status di database
$stmt = $conn->prepare("UPDATE settings SET setting_value = ? WHERE setting_key = 'maintenance_mode'");
$stmt->bind_param("s", $new_status);
$stmt->execute();
$stmt->close();

// Set pesan sukses dan kembali ke dashboard
$_SESSION['success_message'] = "Mode maintenance berhasil diubah menjadi " . strtoupper($new_status);
header("Location: dashboard.php");
exit();