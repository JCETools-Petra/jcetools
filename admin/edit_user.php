<?php
session_start();
if (!isset($_SESSION['admin_logged_in']) || $_SESSION['admin_logged_in'] !== true) {
    header('Location: login.php');
    exit;
}

require_once __DIR__ . '/core/db_connect.php';
require_once __DIR__ . '/core/whatsapp_helper.php';

$user_id = $_GET['id'] ?? null;
if (!$user_id) {
    header('Location: dashboard.php');
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $nama = $_POST['nama'];
    $hwid = $_POST['hwid'];
    $expiry_date = $_POST['expiry_date'];
    $phone_number = $_POST['phone_number'];

    $stmt = $conn->prepare("UPDATE user_jce SET Nama = ?, hwid_encrypted = ?, expiry_date = ?, phone_number = ? WHERE id = ?");
    $stmt->bind_param('ssssi', $nama, $hwid, $expiry_date, $phone_number, $user_id);

    if ($stmt->execute()) {
        // Tentukan apakah tanggal kedaluwarsa adalah "Permanent"
        $expiry_year = (int)date('Y', strtotime($expiry_date));
        $formatted_expiry_date = ($expiry_year > 2030) ? 'Permanent' : date('d F Y H:i', strtotime($expiry_date));
        
        // Perbaiki: Kirim notifikasi setelah update berhasil
        $pesan_notifikasi = "Halo {$nama},\n\nData lisensi JCE Tools Anda telah berhasil diperbarui oleh admin.\n\nTanggal Kedaluwarsa Baru: " . $formatted_expiry_date . "\n\nTerima kasih.";
        
        if (!empty($phone_number)) {
            kirimWhatsApp($phone_number, $pesan_notifikasi);
        }

        header('Location: dashboard.php?status=edit_sukses');
        exit;
    } else {
        $error = "Gagal mengupdate user: " . $stmt->error;
    }
    $stmt->close();
}

$stmt = $conn->prepare("SELECT Nama, hwid_encrypted, expiry_date, phone_number FROM user_jce WHERE id = ?");
$stmt->bind_param('i', $user_id);
$stmt->execute();
$result = $stmt->get_result();
$user = $result->fetch_assoc();
if (!$user) {
    header('Location: dashboard.php?status=user_tidak_ditemukan');
    exit;
}
$stmt->close();
$conn->close();
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <title>Edit User</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        :root {
            --bg-dark: #121212;
            --gold: #FFD700;
            --red: #DC3545;
            --text-color: #f1f1f1;
        }
        body {
            background-color: var(--bg-dark);
            color: var(--text-color);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
        }
        .container {
            background-color: #222;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 0 20px rgba(0,0,0,0.5);
        }
        h2 {
            color: var(--gold);
        }
        hr {
            border-color: #444;
        }
        .form-label {
            color: var(--text-color);
        }
        .form-control {
            background-color: #2a2a2a;
            border-color: #444;
            color: var(--text-color);
        }
        .form-control:focus {
            background-color: #2a2a2a;
            border-color: var(--gold);
            box-shadow: 0 0 0 0.25rem rgba(255, 215, 0, 0.25);
            color: var(--text-color);
        }
        .btn-primary {
            background-color: var(--gold);
            border-color: var(--gold);
            color: var(--bg-dark);
            font-weight: bold;
        }
        .btn-primary:hover {
            background-color: #ffd700;
            border-color: #ffd700;
            filter: brightness(1.1);
        }
        .btn-secondary {
            background-color: #6c757d;
            border-color: #6c757d;
        }
        .btn-secondary:hover {
            background-color: #5a6268;
            border-color: #5a6268;
        }
        .alert-danger {
            background-color: var(--red);
            border-color: var(--red);
            color: white;
        }
    </style>
</head>
<body>
<div class="container mt-5">
    <h2>Edit User: <?php echo htmlspecialchars($user['Nama']); ?></h2><hr>
    <?php if (isset($error)): ?><div class="alert alert-danger"><?php echo htmlspecialchars($error); ?></div><?php endif; ?>

    <form action="edit_user.php?id=<?php echo htmlspecialchars($user_id); ?>" method="POST">
        <div class="mb-3">
            <label for="nama" class="form-label">Nama</label>
            <input type="text" class="form-control" id="nama" name="nama" value="<?php echo htmlspecialchars($user['Nama']); ?>" required>
        </div>
        <div class="mb-3">
            <label for="hwid" class="form-label">HWID Terenkripsi</label>
            <input type="text" class="form-control" id="hwid" name="hwid" value="<?php echo htmlspecialchars($user['hwid_encrypted']); ?>" required>
        </div>
         <div class="mb-3">
            <label for="expiry_date" class="form-label">Tanggal Kedaluwarsa</label>
            <input type="datetime-local" class="form-control" id="expiry_date" name="expiry_date" value="<?php echo htmlspecialchars(date('Y-m-d\TH:i', strtotime($user['expiry_date']))); ?>" required>
        </div>
        
        <div class="mb-3">
            <label for="phone_number" class="form-label">Nomor WhatsApp</label>
            <input type="text" class="form-control" id="phone_number" name="phone_number" value="<?php echo htmlspecialchars($user['phone_number'] ?? ''); ?>" placeholder="Contoh: 6281234567890">
        </div>

        <button type="submit" class="btn btn-primary">Update</button>
        <a href="dashboard.php" class="btn btn-secondary">Batal</a>
    </form>
</div>
</body>
</html>