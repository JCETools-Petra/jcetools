<?php
session_start();
if (isset($_SESSION['admin_logged_in']) && $_SESSION['admin_logged_in'] === true) {
    header('Location: dashboard.php');
    exit;
}

$error_message = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Memuat koneksi database dan helper WhatsApp
    require_once __DIR__ . '/core/db_connect.php';
    require_once __DIR__ . '/core/whatsapp_helper.php';

    // Fungsi untuk mendapatkan alamat IP pengguna
    function getUserIP() {
        return $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN';
    }

    $username = $_POST['username'];
    $password = $_POST['password'];

    $stmt = $conn->prepare("SELECT password_hash FROM admins WHERE username = ?");
    $stmt->bind_param('s', $username);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows === 1) {
        $admin = $result->fetch_assoc();
        if (password_verify($password, $admin['password_hash'])) {
            
            // --- AWAL BAGIAN NOTIFIKASI ---
            try {
                $ip_address = getUserIP();
                $target_nomor = '6285157781148'; // Nomor tujuan notifikasi
                $pesan_notifikasi = "🔔 *Notifikasi Login Admin JCE Tools* 🔔\n\n" .
                                   "Seseorang telah berhasil login ke panel admin.\n\n" .
                                   "👤 Username: *{$username}*\n" .
                                   "🌐 Alamat IP: *{$ip_address}*\n" .
                                   "⏰ Waktu: " . date('Y-m-d H:i:s');

                // Mengirim notifikasi WhatsApp
                kirimWhatsApp($target_nomor, $pesan_notifikasi);
            } catch (Exception $e) {
                // Jika pengiriman notifikasi gagal, proses login tetap berjalan.
                // Error dicatat di log server.
                error_log('Gagal mengirim notifikasi WA: ' . $e->getMessage());
            }
            // --- AKHIR BAGIAN NOTIFIKASI ---

            // Menetapkan sesi dan mengarahkan ke dashboard
            $_SESSION['admin_logged_in'] = true;
            $_SESSION['username'] = $username;
            header('Location: dashboard.php');
            exit;
        }
    }
    $error_message = 'Username atau password salah.';
    $stmt->close();
    $conn->close();
}
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Login - JCE Tools</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Montserrat:wght@400;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-dark: #0A0A0A;
            --form-bg: #1A1A1A;
            --gold: #FFD700;
            --red: #DC3545;
            --text-light: #E0E0E0;
        }
        body {
            background-color: var(--bg-dark);
            color: var(--text-light);
            font-family: 'Montserrat', sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }
        .login-card {
            background-color: var(--form-bg);
            border: 2px solid var(--gold);
            border-radius: 12px;
            box-shadow: 0 8px 30px rgba(0,0,0,0.7);
            padding: 2.5rem;
            width: 100%;
            max-width: 400px;
        }
        .login-logo {
            display: block;
            margin: 0 auto 1.5rem auto;
            max-height: 150px;
            width: auto;
        }
        .form-control {
            background-color: #2A2A2A;
            border: 1px solid #444;
            color: var(--text-light);
        }
        .form-control:focus {
            background-color: #333;
            border-color: var(--gold);
            box-shadow: 0 0 0 0.2rem rgba(255, 215, 0, 0.3);
            color: var(--text-light);
        }
        .btn-submit {
            background-color: var(--gold);
            border-color: var(--gold);
            color: var(--bg-dark);
            font-weight: 700;
        }
    </style>
</head>
<body>
    <div class="login-card">
        <img src="logo.png" alt="Logo JCE Tools" class="login-logo">
        
        <?php if(!empty($error_message)): ?>
            <div class="alert alert-danger text-center"><?php echo htmlspecialchars($error_message, ENT_QUOTES, 'UTF-8'); ?></div>
        <?php endif; ?>
        
        <form action="login.php" method="POST">
            <div class="mb-3">
                <label for="username" class="form-label">Username</label>
                <input type="text" class="form-control" id="username" name="username" required autocomplete="username">
            </div>
            <div class="mb-3">
                <label for="password" class="form-label">Password</label>
                <input type="password" class="form-control" id="password" name="password" required autocomplete="current-password">
            </div>
            <div class="d-grid mt-4">
                <button type="submit" class="btn btn-submit">Login</button>
            </div>
        </form>
    </div>
</body>
</html>