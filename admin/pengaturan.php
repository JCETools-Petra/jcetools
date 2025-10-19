<?php
session_start();
// Pastikan admin sudah login
if (!isset($_SESSION['admin_logged_in']) || $_SESSION['admin_logged_in'] !== true) {
    header('Location: login.php');
    exit;
}

require_once __DIR__ . '/core/db_connect.php';

// Menyiapkan token CSRF untuk keamanan form
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$pesan = '';

// Proses form jika ada data yang dikirim (metode POST)
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Validasi token CSRF
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $pesan = '<div class="alert alert-danger">Sesi tidak valid. Silakan coba lagi.</div>';
    } else {
        // Proses update harga
        if (isset($_POST['harga_perpanjangan_hwid'])) {
            $harga_baru = filter_input(INPUT_POST, 'harga_perpanjangan_hwid', FILTER_SANITIZE_NUMBER_INT);

            // Gunakan query UPSERT (INSERT ... ON DUPLICATE KEY UPDATE)
            $stmt = $conn->prepare("INSERT INTO settings (setting_key, setting_value) VALUES ('harga_perpanjangan_hwid', ?) ON DUPLICATE KEY UPDATE setting_value = ?");
            $stmt->bind_param('ss', $harga_baru, $harga_baru);
            
            if ($stmt->execute()) {
                $pesan = '<div class="alert alert-success">Pengaturan berhasil disimpan!</div>';
            } else {
                $pesan = '<div class="alert alert-danger">Gagal menyimpan pengaturan.</div>';
            }
            $stmt->close();
        }
    }
}

// Ambil nilai harga saat ini dari database untuk ditampilkan di form
$stmt = $conn->prepare("SELECT setting_value FROM settings WHERE setting_key = 'harga_perpanjangan_hwid'");
$stmt->execute();
$result = $stmt->get_result();
$pengaturan = $result->fetch_assoc();
$stmt->close();
$conn->close();

$harga_perpanjangan_hwid = $pengaturan['setting_value'] ?? '0';

?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Pengaturan - JCE Tools Admin</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css">
    <style>
        /* Menggunakan tone warna yang sama dengan dashboard.php */
        :root {
            --bg-dark: #121212;
            --bg-light: #1e1e1e;
            --gold: #FFD700;
            --gold-dark: #cca300;
            --text-light: #e0e0e0;
            --border-color: #444;
        }
        body {
            background-color: var(--bg-dark);
            color: var(--text-light);
        }
        .navbar {
            background-color: var(--bg-light) !important;
            border-bottom: 2px solid var(--gold);
        }
        .navbar-brand, .nav-link {
            color: var(--gold) !important;
            font-weight: 600;
        }
        .content-section {
            background-color: var(--bg-light);
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 0 20px rgba(0,0,0,0.5);
            margin-top: 2rem;
        }
        h2 {
            color: var(--gold);
            border-bottom: 2px solid var(--border-color);
            padding-bottom: 10px;
            margin-bottom: 20px;
            font-weight: 700;
        }
        .form-label {
            font-weight: 600;
        }
        .form-control, .input-group-text {
            background-color: #2a2a2a;
            color: var(--text-light);
            border-color: var(--border-color);
        }
        .form-control:focus {
            background-color: #3a3a3a;
            color: var(--text-light);
            border-color: var(--gold);
            box-shadow: 0 0 0 0.2rem rgba(255, 215, 0, 0.25);
        }
        .btn-gold {
            background-color: var(--gold);
            border-color: var(--gold);
            color: #121212;
            font-weight: bold;
        }
        .btn-gold:hover {
            background-color: var(--gold-dark);
            border-color: var(--gold-dark);
        }
        .form-text {
            color: #888 !important;
        }
    </style>
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-dark">
    <div class="container-fluid">
        <a class="navbar-brand" href="dashboard.php">JCE Tools Admin</a>
        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
            <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="navbarNav">
            <ul class="navbar-nav ms-auto">
                <li class="nav-item">
                    <a class="nav-link" href="dashboard.php"><i class="bi bi-speedometer2"></i> Dashboard</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="logout.php">Logout <i class="bi bi-box-arrow-right"></i></a>
                </li>
            </ul>
        </div>
    </div>
</nav>

<div class="container my-4">
    <div class="content-section">
        <h2><i class="bi bi-gear-fill"></i> Pengaturan Aplikasi</h2>
        
        <?php echo $pesan; // Tampilkan pesan sukses atau error di sini ?>

        <form method="POST" action="pengaturan.php">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">

            <div class="mb-4">
                <label for="harga_perpanjangan_hwid" class="form-label">
                    Harga Perpanjangan HWID (Per Bulan)
                </label>
                <div class="input-group">
                    <span class="input-group-text">Rp</span>
                    <input type="number" class="form-control" id="harga_perpanjangan_hwid" name="harga_perpanjangan_hwid" value="<?php echo htmlspecialchars($harga_perpanjangan_hwid); ?>" required>
                </div>
                <small class="form-text">
                    Harga ini akan digunakan sebagai biaya perpanjangan lisensi berbasis HWID per bulan.
                </small>
            </div>
            
            <button type="submit" class="btn btn-gold"><i class="bi bi-save"></i> Simpan Pengaturan</button>
        </form>
    </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>