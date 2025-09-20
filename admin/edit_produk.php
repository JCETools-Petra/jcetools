<?php
session_start();
if (!isset($_SESSION['admin_logged_in'])) {
    header('Location: login.php');
    exit;
}
require_once 'core/db_connect.php';

$id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);
if (!$id) {
    header('Location: dashboard.php');
    exit;
}

$error = '';

// Proses update
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $nama_produk = $_POST['nama_produk'] ?? '';
    $deskripsi = $_POST['deskripsi'] ?? '';
    $harga = filter_input(INPUT_POST, 'harga', FILTER_VALIDATE_INT);
    $durasi_hari = filter_input(INPUT_POST, 'durasi_hari', FILTER_VALIDATE_INT);
    $download_link = filter_input(INPUT_POST, 'download_link', FILTER_VALIDATE_URL);
    $is_active = isset($_POST['is_active']) ? 1 : 0;

    if (!empty($nama_produk) && $harga > 0 && $durasi_hari > 0) {
        $stmt = $conn->prepare("UPDATE produk SET nama_produk=?, deskripsi=?, harga=?, durasi_hari=?, download_link=?, is_active=? WHERE id=?");
        $stmt->bind_param("ssiissi", $nama_produk, $deskripsi, $harga, $durasi_hari, $download_link, $is_active, $id);
        
        if ($stmt->execute()) {
            header('Location: dashboard.php?status=produk_update_sukses');
            exit;
        } else {
            $error = "Gagal mengupdate produk.";
        }
    } else {
        $error = "Semua field wajib diisi dengan format yang benar.";
    }
}

// Ambil data produk yang akan diedit
$stmt = $conn->prepare("SELECT * FROM produk WHERE id = ?");
$stmt->bind_param("i", $id);
$stmt->execute();
$result = $stmt->get_result();
$produk = $result->fetch_assoc();

if (!$produk) {
    header('Location: dashboard.php');
    exit;
}
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <title>Edit Produk</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css">
    <style>
        :root {
            --bg-dark: #121212;
            --bg-light: #1e1e1e;
            --gold: #FFD700;
            --text-light: #e0e0e0;
            --border-color: #444;
        }
        body {
            background-color: var(--bg-dark);
            color: var(--text-light);
        }
        .form-container {
            background-color: var(--bg-light);
            padding: 40px;
            border-radius: 15px;
            margin-top: 50px;
            max-width: 700px;
            border-top: 4px solid var(--gold);
        }
        h2 {
            color: var(--gold);
            font-weight: 700;
        }
        .form-control, .form-select {
            background-color: #2a2a2a;
            color: var(--text-light);
            border-color: var(--border-color);
        }
        .form-control:focus, .form-select:focus {
            background-color: #333;
            border-color: var(--gold);
            box-shadow: 0 0 0 0.2rem rgba(255, 215, 0, 0.25);
            color: var(--text-light);
        }
        .btn-gold {
            background-color: var(--gold);
            border-color: var(--gold);
            color: #121212;
            font-weight: bold;
        }
    </style>
</head>
<body>
<div class="container form-container">
    <div class="d-flex justify-content-between align-items-center mb-4">
        <h2><i class="bi bi-pencil-square"></i> Edit Produk</h2>
        <a href="dashboard.php" class="btn btn-secondary">Kembali ke Dashboard</a>
    </div>
    
    <?php if ($error): ?>
        <div class="alert alert-danger"><?php echo $error; ?></div>
    <?php endif; ?>

    <form method="POST">
        <div class="mb-3">
            <label for="nama_produk" class="form-label">Nama Produk</label>
            <input type="text" class="form-control" id="nama_produk" name="nama_produk" value="<?php echo htmlspecialchars($produk['nama_produk']); ?>" required>
        </div>
        <div class="mb-3">
            <label for="deskripsi" class="form-label">Deskripsi (Opsional)</label>
            <textarea class="form-control" id="deskripsi" name="deskripsi" rows="3"><?php echo htmlspecialchars($produk['deskripsi']); ?></textarea>
        </div>
        <div class="row">
            <div class="col-md-6 mb-3">
                <label for="harga" class="form-label">Harga (IDR)</label>
                <input type="number" class="form-control" id="harga" name="harga" value="<?php echo $produk['harga']; ?>" required>
            </div>
            <div class="col-md-6 mb-3">
                <label for="durasi_hari" class="form-label">Durasi Aktif (Hari)</label>
                <input type="number" class="form-control" id="durasi_hari" name="durasi_hari" value="<?php echo $produk['durasi_hari']; ?>" required>
            </div>
        </div>
        <div class="mb-3">
            <label for="download_link" class="form-label">URL Download</label>
            <input type="url" class="form-control" id="download_link" name="download_link" value="<?php echo htmlspecialchars($produk['download_link'] ?? ''); ?>">
        </div>
        <div class="form-check form-switch mb-4">
            <input class="form-check-input" type="checkbox" role="switch" id="is_active" name="is_active" <?php if ($produk['is_active']) echo 'checked'; ?>>
            <label class="form-check-label" for="is_active">Jadikan Produk Aktif</label>
        </div>
        <button type="submit" class="btn btn-gold w-100">Update Produk</button>
    </form>
</div>
</body>
</html>