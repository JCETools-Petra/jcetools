<?php
session_start();
if (!isset($_SESSION['admin_logged_in']) || $_SESSION['admin_logged_in'] !== true) {
    header('Location: login.php');
    exit;
}

// Panggil koneksi database terpusat
require_once __DIR__ . '/core/db_connect.php';

$user_id = $_GET['id'] ?? null;
if ($user_id) {
    $stmt = $conn->prepare("DELETE FROM user_jce WHERE id = ?");
    $stmt->bind_param('i', $user_id);
    if ($stmt->execute()) {
        header('Location: dashboard.php?status=hapus_sukses');
    } else {
        header('Location: dashboard.php?status=hapus_gagal');
    }
    $stmt->close();
} else {
    header('Location: dashboard.php');
}
$conn->close();
exit;
?>