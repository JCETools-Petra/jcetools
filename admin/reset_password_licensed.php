<?php
session_start();
// Pastikan hanya admin yang sudah login yang bisa mengakses halaman ini
if (!isset($_SESSION['admin_logged_in']) || $_SESSION['admin_logged_in'] !== true) {
    header('Location: login.php');
    exit;
}

require_once __DIR__ . '/core/db_connect.php';

$message = '';
$error = '';

// Proses form hanya jika methodnya POST
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'];
    $new_password = $_POST['new_password'];

    // Validasi sederhana agar tidak ada field yang kosong
    if (empty($username) || empty($new_password)) {
        $error = "Username dan Password Baru wajib diisi.";
    } else {
        // Enkripsi (hash) password baru sebelum disimpan ke database
        // Ini PENTING agar sesuai dengan metode verifikasi saat login
        $password_hash = password_hash($new_password, PASSWORD_DEFAULT);

        // Menggunakan prepared statement untuk keamanan dari SQL Injection
        $stmt = $conn->prepare("UPDATE licensed_users SET password = ? WHERE username = ?");
        $stmt->bind_param('ss', $password_hash, $username);

        if ($stmt->execute()) {
            // Cek apakah ada baris yang terpengaruh (updated)
            if ($stmt->affected_rows > 0) {
                $message = "Password untuk user '" . htmlspecialchars($username) . "' berhasil direset.";
            } else {
                $error = "Gagal mereset password. User '" . htmlspecialchars($username) . "' tidak ditemukan.";
            }
        } else {
            $error = "Gagal menjalankan query: " . $stmt->error;
        }
        $stmt->close();
    }
    $conn->close();
}
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <title>Reset Password Licensed User</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        :root {
            --bg-dark: #121212;
            --gold: #FFD700;
            --red: #DC3545;
            --green: #198754;
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
            margin-top: 50px;
            max-width: 600px;
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
        .btn-secondary {
            background-color: #6c757d;
            border-color: #6c757d;
        }
        .alert-danger {
            background-color: var(--red);
            color: white;
        }
        .alert-success {
            background-color: var(--green);
            color: white;
        }
    </style>
</head>
<body>
<div class="container">
    <h2>Reset Password Licensed User</h2>
    <hr>
    <?php if (!empty($message)): ?>
        <div class="alert alert-success"><?php echo $message; ?></div>
    <?php endif; ?>
    <?php if (!empty($error)): ?>
        <div class="alert alert-danger"><?php echo $error; ?></div>
    <?php endif; ?>

    <form action="reset_password_licensed.php" method="POST">
        <div class="mb-3">
            <label for="username" class="form-label">Username</label>
            <input type="text" class="form-control" id="username" name="username" placeholder="Masukkan username yang akan direset" required>
        </div>
        <div class="mb-3">
            <label for="new_password" class="form-label">Password Baru</label>
            <input type="password" class="form-control" id="new_password" name="new_password" placeholder="Masukkan password baru" required>
        </div>
        
        <button type="submit" class="btn btn-primary">Reset Password</button>
        <a href="dashboard.php" class="btn btn-secondary">Kembali ke Dashboard</a>
    </form>
</div>
</body>
</html>