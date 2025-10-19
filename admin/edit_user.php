<?php
session_start();
if (!isset($_SESSION['admin_logged_in']) || $_SESSION['admin_logged_in'] !== true) {
    header('Location: login.php');
    exit;
}

require_once __DIR__ . '/core/db_connect.php';
require_once __DIR__ . '/core/email_helper.php'; 
require_once __DIR__ . '/core/crypto_helper.php'; // Panggil helper dekripsi

$user_id = $_GET['id'] ?? null;
if (!$user_id) {
    header('Location: dashboard.php');
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $nama = $_POST['nama'];
    $hwid_encrypted = $_POST['hwid']; // Ini masih dalam bentuk terenkripsi
    $expiry_date = $_POST['expiry_date'];
    $email = $_POST['email'];

    // Update data di database
    $stmt = $conn->prepare("UPDATE user_jce SET Nama = ?, hwid_encrypted = ?, expiry_date = ?, email = ? WHERE id = ?");
    $stmt->bind_param('ssssi', $nama, $hwid_encrypted, $expiry_date, $email, $user_id);

    if ($stmt->execute()) {
        
        // ==================================================================
        // PENAMBAHAN BARU: Kirim email detail setelah update berhasil
        // ==================================================================
        
        // Kirim notifikasi email jika alamat email valid
        if (!empty($email) && filter_var($email, FILTER_VALIDATE_EMAIL)) {
            
            // 1. Dekripsi HWID untuk ditampilkan di email
            $hwid_decrypted = decrypt_hwid($hwid_encrypted);
            if ($hwid_decrypted === false) {
                $hwid_decrypted = '[Data HWID tidak valid]';
            }

            // 2. Format tanggal kedaluwarsa
            $expiry_year = (int)date('Y', strtotime($expiry_date));
            $formatted_expiry_date = ($expiry_year > 2030) ? 'Permanent' : date('d F Y H:i', strtotime($expiry_date));

            // 3. Siapkan subjek dan isi pesan email yang detail
            $subjek_email = "Informasi Lisensi JCE Tools Anda Telah Diperbarui";
            
            $pesan_notifikasi = "Data lisensi JCE Tools Anda telah berhasil diperbarui oleh admin. Di bawah ini adalah rincian informasi lisensi Anda yang terbaru:" .
                                "<br><br><b>Nama Pengguna:</b> " . htmlspecialchars($nama) .
                                "<br><b>Alamat Email:</b> " . htmlspecialchars($email) .
                                "<br><b>HWID Anda:</b> " . htmlspecialchars($hwid_decrypted) .
                                "<br><b>Berlaku Hingga:</b> " . $formatted_expiry_date .
                                "<br><br>Mohon simpan informasi ini dengan baik. Jika Anda tidak merasa melakukan perubahan atau memiliki pertanyaan, silakan hubungi tim support kami.";
            
            // 4. Kirim email menggunakan helper
            kirimEmail($email, $nama, $subjek_email, $pesan_notifikasi);
        }
        // ==================================================================
        // AKHIR DARI PENAMBAHAN
        // ==================================================================

        header('Location: dashboard.php?status=edit_sukses');
        exit;
    } else {
        $error = "Gagal mengupdate user: " . $stmt->error;
    }
    $stmt->close();
}

// Bagian untuk menampilkan data di form (tidak ada perubahan di sini)
$stmt = $conn->prepare("SELECT Nama, hwid_encrypted, expiry_date, email FROM user_jce WHERE id = ?");
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
            <label for="email" class="form-label">Alamat Email</label>
            <input type="email" class="form-control" id="email" name="email" value="<?php echo htmlspecialchars($user['email'] ?? ''); ?>" placeholder="Contoh: user@example.com">
        </div>

        <button type="submit" class="btn btn-primary">Update</button>
        <a href="dashboard.php" class="btn btn-secondary">Batal</a>
    </form>
</div>
</body>
</html>