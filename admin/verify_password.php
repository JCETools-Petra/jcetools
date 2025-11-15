<?php
session_start();
// Pastikan hanya admin yang sudah login yang bisa mengakses halaman ini
if (!isset($_SESSION['admin_logged_in']) || $_SESSION['admin_logged_in'] !== true) {
    header('Location: login.php');
    exit;
}

require_once __DIR__ . '/core/db_connect.php';

$verification_result = '';
$error = '';
$success = '';
$users_list = [];

// Ambil daftar semua user untuk dropdown
$stmt_users = $conn->prepare("SELECT username, phone_number, expiry_date FROM licensed_users ORDER BY username ASC");
$stmt_users->execute();
$result = $stmt_users->get_result();
while ($row = $result->fetch_assoc()) {
    $users_list[] = $row;
}
$stmt_users->close();

// Proses verifikasi password
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $verification_type = $_POST['verification_type'] ?? '';

    if ($verification_type === 'manual') {
        // Verifikasi manual: input password dan hash secara langsung
        $password_plain = $_POST['password_plain'] ?? '';
        $password_hash = $_POST['password_hash'] ?? '';

        if (empty($password_plain) || empty($password_hash)) {
            $error = "Password dan Hash wajib diisi.";
        } else {
            // Verifikasi menggunakan password_verify
            if (password_verify($password_plain, $password_hash)) {
                $success = "✅ Password COCOK dengan hash!";
                $verification_result = "<div class='alert alert-success'><strong>COCOK!</strong> Password yang Anda masukkan sesuai dengan hash.</div>";
            } else {
                $error = "❌ Password TIDAK COCOK dengan hash!";
                $verification_result = "<div class='alert alert-danger'><strong>TIDAK COCOK!</strong> Password yang Anda masukkan tidak sesuai dengan hash.</div>";
            }
        }
    } elseif ($verification_type === 'user') {
        // Verifikasi berdasarkan username dari database
        $username = $_POST['username'] ?? '';
        $password_plain = $_POST['password_user'] ?? '';

        if (empty($username) || empty($password_plain)) {
            $error = "Username dan Password wajib diisi.";
        } else {
            // Ambil password hash dari database
            $stmt = $conn->prepare("SELECT password FROM licensed_users WHERE username = ?");
            $stmt->bind_param('s', $username);
            $stmt->execute();
            $user_result = $stmt->get_result();

            if ($user_result->num_rows === 0) {
                $error = "Username tidak ditemukan.";
            } else {
                $user_data = $user_result->fetch_assoc();
                $stored_hash = $user_data['password'];

                // Verifikasi password
                if (password_verify($password_plain, $stored_hash)) {
                    $success = "✅ Password COCOK untuk user: " . htmlspecialchars($username);
                    $verification_result = "<div class='alert alert-success'><strong>COCOK!</strong> Password yang Anda masukkan sesuai untuk user <strong>" . htmlspecialchars($username) . "</strong>.</div>";
                } else {
                    $error = "❌ Password TIDAK COCOK untuk user: " . htmlspecialchars($username);
                    $verification_result = "<div class='alert alert-danger'><strong>TIDAK COCOK!</strong> Password yang Anda masukkan tidak sesuai untuk user <strong>" . htmlspecialchars($username) . "</strong>.</div>";
                }
            }
            $stmt->close();
        }
    } elseif ($verification_type === 'generate') {
        // Generate hash dari password baru
        $new_password = $_POST['new_password'] ?? '';

        if (empty($new_password)) {
            $error = "Password wajib diisi.";
        } else {
            $generated_hash = password_hash($new_password, PASSWORD_BCRYPT);
            $verification_result = "<div class='alert alert-info'>
                <h5>Hash yang Dihasilkan:</h5>
                <code style='color: #fff; background: #333; padding: 10px; display: block; border-radius: 5px; word-wrap: break-word;'>" . htmlspecialchars($generated_hash) . "</code>
                <small class='mt-2 d-block'>Hash ini dapat digunakan untuk disimpan ke database.</small>
            </div>";
        }
    }
}

$conn->close();
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <title>Verifikasi Password Licensed User</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        :root {
            --bg-dark: #121212;
            --gold: #FFD700;
            --red: #DC3545;
            --green: #198754;
            --blue: #0dcaf0;
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
            margin-top: 30px;
            margin-bottom: 30px;
            box-shadow: 0 0 20px rgba(0,0,0,0.5);
        }
        h2, h4 {
            color: var(--gold);
        }
        .form-control, .form-select {
            background-color: #2a2a2a;
            border-color: #444;
            color: var(--text-color);
        }
        .form-control:focus, .form-select:focus {
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
        .btn-info {
            background-color: var(--blue);
            border-color: var(--blue);
            color: var(--bg-dark);
            font-weight: bold;
        }
        .alert-danger {
            background-color: var(--red);
            color: white;
        }
        .alert-success {
            background-color: var(--green);
            color: white;
        }
        .nav-tabs .nav-link {
            color: var(--text-color);
            background-color: #2a2a2a;
            border-color: #444;
        }
        .nav-tabs .nav-link.active {
            background-color: var(--gold);
            color: var(--bg-dark);
            border-color: var(--gold);
            font-weight: bold;
        }
        .nav-tabs .nav-link:hover {
            border-color: var(--gold);
        }
        .card {
            background-color: #2a2a2a;
            border-color: #444;
        }
        .table {
            color: var(--text-color);
        }
        .table-striped tbody tr:nth-of-type(odd) {
            background-color: rgba(255, 215, 0, 0.05);
        }
        label {
            font-weight: 500;
        }
        hr {
            border-color: #444;
        }
        code {
            background-color: #333;
            color: var(--gold);
            padding: 2px 6px;
            border-radius: 3px;
        }
    </style>
</head>
<body>
<div class="container">
    <h2>🔐 Verifikasi Password Licensed User</h2>
    <p class="text-muted">Tool untuk memeriksa dan memverifikasi password yang di-hash dengan bcrypt</p>
    <hr>

    <?php if (!empty($verification_result)): ?>
        <?php echo $verification_result; ?>
    <?php endif; ?>

    <?php if (!empty($error) && empty($verification_result)): ?>
        <div class="alert alert-danger"><?php echo $error; ?></div>
    <?php endif; ?>

    <?php if (!empty($success) && empty($verification_result)): ?>
        <div class="alert alert-success"><?php echo $success; ?></div>
    <?php endif; ?>

    <ul class="nav nav-tabs mb-4" id="verificationTabs" role="tablist">
        <li class="nav-item" role="presentation">
            <button class="nav-link active" id="user-tab" data-bs-toggle="tab" data-bs-target="#user" type="button" role="tab">
                Verifikasi by Username
            </button>
        </li>
        <li class="nav-item" role="presentation">
            <button class="nav-link" id="manual-tab" data-bs-toggle="tab" data-bs-target="#manual" type="button" role="tab">
                Verifikasi Manual
            </button>
        </li>
        <li class="nav-item" role="presentation">
            <button class="nav-link" id="generate-tab" data-bs-toggle="tab" data-bs-target="#generate" type="button" role="tab">
                Generate Hash
            </button>
        </li>
        <li class="nav-item" role="presentation">
            <button class="nav-link" id="info-tab" data-bs-toggle="tab" data-bs-target="#info" type="button" role="tab">
                Info & Panduan
            </button>
        </li>
    </ul>

    <div class="tab-content" id="verificationTabsContent">
        <!-- Tab Verifikasi by Username -->
        <div class="tab-pane fade show active" id="user" role="tabpanel">
            <h4>Verifikasi Password by Username</h4>
            <p class="text-muted">Pilih username dari database dan test password-nya</p>
            <form action="verify_password.php" method="POST">
                <input type="hidden" name="verification_type" value="user">
                <div class="mb-3">
                    <label for="username" class="form-label">Username</label>
                    <select class="form-select" id="username" name="username" required>
                        <option value="">-- Pilih Username --</option>
                        <?php foreach ($users_list as $user): ?>
                            <option value="<?php echo htmlspecialchars($user['username']); ?>">
                                <?php echo htmlspecialchars($user['username']); ?>
                                (<?php echo htmlspecialchars($user['phone_number']); ?> -
                                Exp: <?php echo htmlspecialchars($user['expiry_date']); ?>)
                            </option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="mb-3">
                    <label for="password_user" class="form-label">Password yang ingin ditest</label>
                    <input type="text" class="form-control" id="password_user" name="password_user"
                           placeholder="Masukkan password (plain text)" required>
                    <small class="text-muted">Masukkan password yang ingin Anda verifikasi</small>
                </div>
                <button type="submit" class="btn btn-primary">🔍 Verifikasi Password</button>
            </form>
        </div>

        <!-- Tab Verifikasi Manual -->
        <div class="tab-pane fade" id="manual" role="tabpanel">
            <h4>Verifikasi Manual (Password vs Hash)</h4>
            <p class="text-muted">Masukkan password dan hash secara manual untuk memverifikasi kecocokan</p>
            <form action="verify_password.php" method="POST">
                <input type="hidden" name="verification_type" value="manual">
                <div class="mb-3">
                    <label for="password_plain" class="form-label">Password (Plain Text)</label>
                    <input type="text" class="form-control" id="password_plain" name="password_plain"
                           placeholder="Contoh: mypassword123" required>
                </div>
                <div class="mb-3">
                    <label for="password_hash" class="form-label">Hash (Bcrypt)</label>
                    <input type="text" class="form-control" id="password_hash" name="password_hash"
                           placeholder="Contoh: $2y$10$DWniQEQgAaXV501SyxBsFeC36g4R4JomlYyngftwdysOxD.fhvqn2" required>
                    <small class="text-muted">Hash bcrypt dimulai dengan <code>$2y$10$</code> atau <code>$2a$10$</code></small>
                </div>
                <button type="submit" class="btn btn-primary">🔍 Verifikasi</button>
            </form>
        </div>

        <!-- Tab Generate Hash -->
        <div class="tab-pane fade" id="generate" role="tabpanel">
            <h4>Generate Hash Baru</h4>
            <p class="text-muted">Buat hash bcrypt dari password baru</p>
            <form action="verify_password.php" method="POST">
                <input type="hidden" name="verification_type" value="generate">
                <div class="mb-3">
                    <label for="new_password" class="form-label">Password Baru</label>
                    <input type="text" class="form-control" id="new_password" name="new_password"
                           placeholder="Masukkan password yang ingin di-hash" required>
                </div>
                <button type="submit" class="btn btn-info">🔐 Generate Hash</button>
            </form>
        </div>

        <!-- Tab Info -->
        <div class="tab-pane fade" id="info" role="tabpanel">
            <h4>ℹ️ Informasi & Panduan</h4>
            <div class="card p-3 mb-3">
                <h5>Tentang Bcrypt Hash</h5>
                <p>Bcrypt adalah algoritma hashing password yang aman. Hash yang dihasilkan memiliki format:</p>
                <code>$2y$10$[22 karakter salt][31 karakter hash]</code>
                <p class="mt-2 mb-0">Contoh hash bcrypt:</p>
                <code>$2y$10$DWniQEQgAaXV501SyxBsFeC36g4R4JomlYyngftwdysOxD.fhvqn2</code>
            </div>

            <div class="card p-3 mb-3">
                <h5>Cara Penggunaan</h5>
                <ol>
                    <li><strong>Verifikasi by Username:</strong> Pilih user dari database dan test apakah password cocok</li>
                    <li><strong>Verifikasi Manual:</strong> Jika Anda punya hash dan ingin test password tertentu</li>
                    <li><strong>Generate Hash:</strong> Buat hash baru dari password untuk testing atau keperluan lain</li>
                </ol>
            </div>

            <div class="card p-3 mb-3">
                <h5>Catatan Keamanan</h5>
                <ul class="mb-0">
                    <li>Password <strong>TIDAK PERNAH</strong> disimpan dalam bentuk plain text</li>
                    <li>Yang disimpan adalah <strong>hash</strong> dari password</li>
                    <li>Bcrypt adalah one-way hash, artinya tidak bisa di-decrypt kembali ke password asli</li>
                    <li>Untuk verifikasi, gunakan fungsi <code>password_verify()</code></li>
                </ul>
            </div>

            <div class="card p-3">
                <h5>Daftar Licensed Users (<?php echo count($users_list); ?> users)</h5>
                <?php if (empty($users_list)): ?>
                    <p class="text-muted">Belum ada user terdaftar.</p>
                <?php else: ?>
                    <div class="table-responsive">
                        <table class="table table-striped table-sm">
                            <thead>
                                <tr>
                                    <th>Username</th>
                                    <th>No. WhatsApp</th>
                                    <th>Expiry Date</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($users_list as $user): ?>
                                    <tr>
                                        <td><?php echo htmlspecialchars($user['username']); ?></td>
                                        <td><?php echo htmlspecialchars($user['phone_number']); ?></td>
                                        <td><?php echo htmlspecialchars($user['expiry_date']); ?></td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <hr>
    <a href="dashboard.php" class="btn btn-secondary">← Kembali ke Dashboard</a>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
