<?php
session_start();
if (!isset($_SESSION['admin_logged_in'])) {
    header('Location: login.php');
    exit;
}
require_once 'core/db_connect.php';

$id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);

if ($id) {
    // Sebaiknya cek dulu apakah produk ini terkait dengan transaksi
    // Untuk saat ini, kita langsung hapus saja
    $stmt = $conn->prepare("DELETE FROM produk WHERE id = ?");
    $stmt->bind_param("i", $id);
    $stmt->execute();
}

header('Location: dashboard.php?status=produk_dihapus');
exit;