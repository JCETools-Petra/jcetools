<?php
session_start();
if (!isset($_SESSION['admin_logged_in']) || $_SESSION['admin_logged_in'] !== true) {
    header('Location: login.php');
    exit;
}

require_once __DIR__ . '/core/db_connect.php';

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$username = $_SESSION['username'];

// Proses update link download
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['update_download_link'])) {
    if (isset($_SESSION['username']) && $_SESSION['username'] === 'joshhh') {
        $new_link = trim($_POST['download_link']);
        if (filter_var($new_link, FILTER_VALIDATE_URL)) {
            $stmt = $conn->prepare("UPDATE settings SET setting_value = ? WHERE setting_key = 'download_link'");
            $stmt->bind_param('s', $new_link);
            $stmt->execute();
            $stmt->close();
            header('Location: dashboard.php?status=link_updated');
            exit;
        }
    }
}

// Proses update template pesan
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['update_template'])) {
    $new_template = $_POST['message_template'];
    $stmt = $conn->prepare("UPDATE admins SET message_template = ? WHERE username = ?");
    $stmt->bind_param('ss', $new_template, $username);
    $stmt->execute();
    $stmt->close();
    header('Location: dashboard.php?status=template_sukses');
    exit;
}

// Ambil data untuk dashboard
$template_result = $conn->query("SELECT message_template FROM admins WHERE username = '{$username}'");
$current_template = $template_result->fetch_assoc()['message_template'] ?? '';

// Logika untuk Pencarian dan Pengurutan User
$sort_column_user = $_GET['sort_user'] ?? 'id';
$valid_user_columns = ['id', 'Nama', 'expiry_date', 'last_login', 'phone_number'];
if (!in_array($sort_column_user, $valid_user_columns)) {
    $sort_column_user = 'id';
}

$search_term = $_GET['search_nama'] ?? '';
$sql_params = [];
$sql_types = '';

$sql_users = "SELECT id, Nama, hwid_encrypted, expiry_date, last_login, phone_number FROM user_jce";

if (!empty($search_term)) {
    $sql_users .= " WHERE Nama LIKE ?";
    $sql_params[] = "%" . $search_term . "%";
    $sql_types .= 's';
}

$sql_users .= " ORDER BY {$sort_column_user} ASC";

$stmt_users = $conn->prepare($sql_users);
if (!empty($sql_params)) {
    $stmt_users->bind_param($sql_types, ...$sql_params);
}
$stmt_users->execute();
$users = $stmt_users->get_result();

// Ambil data produk
$sort_column_product = $_GET['sort_product'] ?? 'id';
$valid_product_columns = ['id', 'nama_produk', 'harga', 'durasi_hari', 'is_active'];
if (!in_array($sort_column_product, $valid_product_columns)) $sort_column_product = 'id';
$products = $conn->query("SELECT * FROM produk ORDER BY {$sort_column_product} ASC");

// Ambil pengaturan dari database
$settings_result = $conn->query("SELECT setting_key, setting_value FROM settings WHERE setting_key IN ('maintenance_mode', 'download_link')");
$settings = [];
while ($row = $settings_result->fetch_assoc()) {
    $settings[$row['setting_key']] = $row['setting_value'];
}

$current_maintenance_status = $settings['maintenance_mode'] ?? 'off';
$current_download_link = $settings['download_link'] ?? '';
$is_maintenance_on = ($current_maintenance_status === 'on');

?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Dashboard - JCE Tools</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css">
    <style>
        :root {
            --bg-dark: #121212;
            --bg-light: #1e1e1e;
            --gold: #FFD700;
            --gold-dark: #cca300;
            --red: #DC3545;
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
        .container-fluid {
            padding-left: 2rem;
            padding-right: 2rem;
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
        .table {
            color: var(--text-light);
        }
        .table thead th {
            color: var(--gold);
            background-color: #2a2a2a;
            border-color: var(--border-color);
        }
        .table tbody tr {
            transition: all 0.2s ease-in-out;
        }
        .table-hover tbody tr:hover {
            background-color: #2c2c2c;
            transform: scale(1.01);
        }
        .table td, .table th {
            border-color: var(--border-color);
            vertical-align: middle;
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
        .btn-outline-gold {
            color: var(--gold);
            border-color: var(--gold);
        }
        .btn-outline-gold:hover {
            color: #121212;
            background-color: var(--gold);
            border-color: var(--gold);
        }
    </style>
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-dark">
    <div class="container-fluid">
        <a class="navbar-brand" href="#">JCE Tools Admin</a>
        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
            <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="navbarNav">
            <ul class="navbar-nav ms-auto">
                <li class="nav-item">
                    <a class="nav-link" href="logout.php">Logout <i class="bi bi-box-arrow-right"></i></a>
                </li>
            </ul>
        </div>
    </div>
</nav>

<div class="container-fluid mt-4">

    <?php if (isset($_SESSION['username']) && $_SESSION['username'] === 'joshhh'): ?>
    <div class="content-section">
        <h2 class="h5"><i class="bi bi-gear-fill"></i> Panel Super Admin</h2>
        
        <h5 class="mt-4">Mode Pemeliharaan (Maintenance)</h5>
        <form action="toggle_maintenance.php" method="POST" class="mt-3">
            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
            <div class="d-flex align-items-center">
                <strong>Status Saat Ini:</strong> 
                <?php if ($is_maintenance_on): ?>
                    <span class="badge bg-danger ms-2">AKTIF</span>
                <?php else: ?>
                    <span class="badge bg-success ms-2">NONAKTIF</span>
                <?php endif; ?>
            </div>
            <div class="mt-3">
                <button type="submit" class="btn <?php echo $is_maintenance_on ? 'btn-success' : 'btn-danger'; ?>">
                    <i class="bi bi-power"></i> <?php echo $is_maintenance_on ? 'Matikan' : 'Aktifkan'; ?> Maintenance
                </button>
            </div>
        </form>

        <hr class="my-4" style="border-color: var(--border-color);">

        <h5 class="mt-4">Pengaturan Link Download</h5>
        <p class="mb-2">URL ini akan dikirimkan ke pelanggan via WhatsApp setelah pembayaran berhasil.</p>
        <form action="dashboard.php" method="POST" class="mt-3">
            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
            <div class="mb-3">
                <label for="download_link" class="form-label">URL Download Launcher</label>
                <input type="url" class="form-control bg-dark text-white border-secondary" id="download_link" name="download_link" value="<?php echo htmlspecialchars($current_download_link); ?>" required>
            </div>
            <button type="submit" name="update_download_link" class="btn btn-gold"><i class="bi bi-save"></i> Simpan Link</button>
        </form>
    </div>
    <?php endif; ?>

    <div class="content-section">
        <h2><i class="bi bi-whatsapp"></i> Template Pesan Massal</h2>
        <p>Edit template pesan yang akan digunakan untuk fitur "Kirim Pesan Massal". Gunakan placeholder <code>{nama}</code> dan <code>{expiry_date}</code> yang akan diganti secara otomatis.</p>
        <form action="dashboard.php" method="POST">
             <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
            <div class="mb-3">
                <textarea name="message_template" class="form-control bg-dark text-white border-secondary" rows="5"><?php echo htmlspecialchars($current_template); ?></textarea>
            </div>
            <button type="submit" name="update_template" class="btn btn-gold"><i class="bi bi-save"></i> Simpan Template</button>
        </form>
    </div>
    <div class="content-section">
        <div class="d-flex justify-content-between align-items-center mb-3">
            <h2><i class="bi bi-box-seam"></i> Manajemen Produk</h2>
            <a href="tambah_produk.php" class="btn btn-gold"><i class="bi bi-plus-circle"></i> Tambah Produk Baru</a>
        </div>
        <div class="table-responsive">
            <table class="table table-dark table-striped table-hover">
                <thead>
                    <tr>
                        <th><a href="?sort_product=id" class="text-white">ID</a></th>
                        <th><a href="?sort_product=nama_produk" class="text-white">Nama Produk</a></th>
                        <th><a href="?sort_product=harga" class="text-white">Harga</a></th>
                        <th><a href="?sort_product=durasi_hari" class="text-white">Durasi (Hari)</a></th>
                        <th><a href="?sort_product=is_active" class="text-white">Status</a></th>
                        <th>Aksi</th>
                    </tr>
                </thead>
                <tbody>
                    <?php while($p = $products->fetch_assoc()): ?>
                    <tr>
                        <td><?php echo $p['id']; ?></td>
                        <td><?php echo htmlspecialchars($p['nama_produk']); ?></td>
                        <td>Rp <?php echo number_format($p['harga']); ?></td>
                        <td><?php echo $p['durasi_hari']; ?></td>
                        <td>
                            <?php if ($p['is_active']): ?>
                                <span class="badge bg-success">Aktif</span>
                            <?php else: ?>
                                <span class="badge bg-secondary">Tidak Aktif</span>
                            <?php endif; ?>
                        </td>
                        <td>
                            <a href="edit_produk.php?id=<?php echo $p['id']; ?>" class="btn btn-outline-gold btn-sm"><i class="bi bi-pencil-square"></i> Edit</a>
                            <a href="hapus_produk.php?id=<?php echo $p['id']; ?>" class="btn btn-danger btn-sm" onclick="return confirm('Yakin hapus produk ini?');"><i class="bi bi-trash"></i> Hapus</a>
                        </td>
                    </tr>
                    <?php endwhile; ?>
                </tbody>
            </table>
        </div>
    </div>
    
    <div class="content-section">
        <div class="d-flex justify-content-between align-items-center mb-3">
            <h2><i class="bi bi-people"></i> Manajemen User (Sistem HWID Lama)</h2>
            <div>
                <a href="kirim_massal.php" class="btn btn-outline-danger">Kirim Pesan Massal</a>
                <a href="tambah_user.php" class="btn btn-gold">Tambah User Baru</a>
            </div>
        </div>

        <form action="dashboard.php" method="GET" class="mb-4">
            <div class="input-group">
                <input type="text" name="search_nama" class="form-control bg-dark text-white border-secondary" placeholder="Cari pengguna berdasarkan nama..." value="<?php echo htmlspecialchars($search_term); ?>">
                <button class="btn btn-gold" type="submit"><i class="bi bi-search"></i> Cari</button>
                <a href="dashboard.php" class="btn btn-outline-light">Reset</a>
            </div>
        </form>

        <div class="table-responsive">
            <table class="table table-dark table-striped table-hover">
                <thead>
                    <tr>
                        <th><a href="?sort_user=id" class="text-white">ID</a></th>
                        <th><a href="?sort_user=Nama" class="text-white">Nama</a></th>
                        <th>HWID</th>
                        <th><a href="?sort_user=phone_number" class="text-white">Nomor Telepon</a></th>
                        <th><a href="?sort_user=expiry_date" class="text-white">Expiry Date</a></th>
                        <th><a href="?sort_user=last_login" class="text-white">Last Login</a></th>
                        <th>Aksi</th>
                    </tr>
                </thead>
                <tbody>
                    <?php while($row = $users->fetch_assoc()): ?>
                    <tr>
                        <td><?php echo $row['id']; ?></td>
                        <td><?php echo htmlspecialchars($row['Nama']); ?></td>
                        <td><?php echo htmlspecialchars($row['hwid_encrypted']); ?></td>
                        <td><?php echo htmlspecialchars($row['phone_number']); ?></td>
                        <td><?php echo htmlspecialchars($row['expiry_date']); ?></td>
                        <td><?php echo htmlspecialchars($row['last_login']); ?></td>
                        <td>
                            <a href="edit_user.php?id=<?php echo $row['id']; ?>" class="btn btn-outline-gold btn-sm">Edit</a>
                            <a href="hapus_user.php?id=<?php echo $row['id']; ?>" class="btn btn-danger btn-sm" onclick="return confirm('Yakin hapus user ini?');">Hapus</a>
                        </td>
                    </tr>
                    <?php endwhile; ?>
                </tbody>
            </table>
        </div>
    </div>

</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
<?php $conn->close(); ?>