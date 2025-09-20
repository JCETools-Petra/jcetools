<?php
session_start();
// Pastikan hanya admin yang bisa akses
if (!isset($_SESSION['admin_logged_in'])) {
    header('Location: login.php');
    exit;
}

// Sertakan koneksi database yang sudah ada
require_once 'core/db_connect.php';

// Ambil semua produk dari database
$result = $conn->query("SELECT * FROM produk ORDER BY id DESC");
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Kelola Produk</title>
    <link rel="stylesheet" href="style.css"> 
</head>
<body>
    <div class="container">
        <h1>Kelola Produk</h1>
        <a href="tambah_produk.php" class="btn btn-primary">Tambah Produk Baru</a>
        <br><br>
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Nama Produk</th>
                    <th>Harga</th>
                    <th>Durasi (Hari)</th>
                    <th>Status</th>
                    <th>Aksi</th>
                </tr>
            </thead>
            <tbody>
                <?php while($row = $result->fetch_assoc()): ?>
                <tr>
                    <td><?php echo $row['id']; ?></td>
                    <td><?php echo htmlspecialchars($row['nama_produk']); ?></td>
                    <td>Rp <?php echo number_format($row['harga']); ?></td>
                    <td><?php echo $row['durasi_hari']; ?></td>
                    <td><?php echo $row['is_active'] ? 'Aktif' : 'Tidak Aktif'; ?></td>
                    <td>
                        <a href="edit_produk.php?id=<?php echo $row['id']; ?>">Edit</a>
                        </td>
                </tr>
                <?php endwhile; ?>
            </tbody>
        </table>
    </div>
</body>
</html>