<?php
ob_start();

session_start();
// Cek jika admin sudah login
if (!isset($_SESSION['admin_logged_in']) || $_SESSION['admin_logged_in'] !== true) {
    header('Location: login.php');
    exit;
}

// Panggil koneksi database terpusat
require_once __DIR__ . '/core/db_connect.php';

$error = ''; // Inisialisasi variabel error

// Fungsi untuk mengenkripsi HWID menggunakan algoritma yang sama dengan klien C++
function encrypt_hwid(string $plaintext): string
{
    // Kunci dan IV harus dalam format biner
    $key_string = "JCETOOLS-1830";
    $key = str_pad($key_string, 32, "\0", STR_PAD_RIGHT);

    // Perbaikan: IV diubah menjadi 16 byte (32 karakter hex)
    $iv_hex = "1234567890abcdef1234567800000000";
    $iv = hex2bin($iv_hex);

    // Enkripsi data
    $ciphertext_raw = openssl_encrypt(
        $plaintext,
        'aes-256-cbc',
        $key,
        OPENSSL_RAW_DATA,
        $iv
    );
    
    // Konversi hasil enkripsi (binary) ke format heksadesimal
    return bin2hex($ciphertext_raw);
}

// Proses form hanya jika methodnya POST
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $nama = $_POST['nama'];
    $hwid_unencrypted = $_POST['hwid'];
    $expiry_date = $_POST['expiry_date'];
    $phone_number = $_POST['phone_number'] ?? null;

    // Validasi sederhana agar tidak ada field yang kosong
    if (empty($nama) || empty($hwid_unencrypted) || empty($expiry_date)) {
        $error = "Semua field wajib diisi.";
    } else {
        // Enkripsi HWID sebelum dimasukkan ke database
        $hwid_encrypted = encrypt_hwid($hwid_unencrypted);

        // Perbaikan: Cek apakah HWID sudah ada di database
        $check_stmt = $conn->prepare("SELECT COUNT(*) FROM user_jce WHERE hwid_encrypted = ?");
        $check_stmt->bind_param('s', $hwid_encrypted);
        $check_stmt->execute();
        $check_result = $check_stmt->get_result();
        $row = $check_result->fetch_row();
        $count = $row[0];
        $check_stmt->close();

        if ($count > 0) {
            $error = "Gagal: HWID ini sudah terdaftar. Harap gunakan HWID yang berbeda.";
        } else {
            // Menggunakan prepared statement untuk keamanan
            $stmt = $conn->prepare("INSERT INTO user_jce (Nama, hwid_encrypted, expiry_date, phone_number) VALUES (?, ?, ?, ?)");
            $stmt->bind_param('ssss', $nama, $hwid_encrypted, $expiry_date, $phone_number);

            if ($stmt->execute()) {
                $stmt->close();
                $conn->close();
                ob_end_clean();
                header('Location: dashboard.php?status=tambah_sukses');
                exit;
            } else {
                $error = "Gagal menambahkan user: " . $stmt->error;
            }
            $stmt->close();
        }
    }
}
// Koneksi ditutup di sini jika tidak ada redirect
if (isset($conn) && $conn->ping()) {
    $conn->close();
}
ob_end_flush();
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Tambah User Baru - Premium</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600&display=swap" rel="stylesheet">
    
    <style>
        /* Palet Warna: Hitam (#1a1a1a), Emas (#daa520), Merah (#dc3545), Putih (#f8f9fa) */
        body {
            font-family: 'Poppins', sans-serif;
            background-color: #1a1a1a;
            color: #f8f9fa;
        }

        .container {
            padding-top: 50px;
        }

        .card {
            border: 1px solid #444;
            border-radius: 12px;
            background-color: #2c2c2c;
            box-shadow: 0 8px 25px rgba(0, 0, 0, 0.3);
        }
        
        .card-header {
            background-color: transparent;
            border-bottom: 1px solid #444;
            padding: 20px 25px;
            font-weight: 600;
            font-size: 1.3rem;
            color: #daa520;
            text-align: center;
        }
        
        .card-body {
            padding: 30px 25px;
        }

        .form-label {
            font-weight: 500;
            color: #adb5bd;
        }
        
        .form-control {
            border-radius: 8px;
            border: 1px solid #555;
            background-color: #333;
            color: #f8f9fa;
            padding: 10px 12px;
        }

        .form-control:focus {
            border-color: #daa520;
            background-color: #383838;
            color: #f8f9fa;
            box-shadow: 0 0 0 0.25rem rgba(218, 165, 32, 0.25);
        }
        
        .form-control::-webkit-calendar-picker-indicator {
            filter: invert(1);
        }

        .btn-primary {
            background-color: #daa520;
            border-color: #daa520;
            color: #1a1a1a;
            border-radius: 8px;
            padding: 10px 20px;
            font-weight: 600;
            transition: all 0.2s;
        }

        .btn-primary:hover {
            background-color: #c89617;
            border-color: #c89617;
            color: #000;
            transform: translateY(-2px);
        }
        
        .btn-secondary {
            background-color: #495057;
            border-color: #495057;
            border-radius: 8px;
            padding: 10px 20px;
            font-weight: 500;
        }
        
        .alert-danger {
            background-color: #dc3545;
            color: white;
            border: none;
            border-radius: 8px;
        }
    </style>
</head>
<body>

<div class="container">
    <div class="row justify-content-center">
        <div class="col-lg-6">
            <div class="card">
                <div class="card-header">
                    FORMULIR PENAMBAHAN USER
                </div>
                <div class="card-body">
                    
                    <?php if (!empty($error)): ?>
                        <div class="alert alert-danger"><?php echo htmlspecialchars($error); ?></div>
                    <?php endif; ?>

                    <form action="tambah_user.php" method="POST">
                        <div class="mb-3">
                            <label for="nama" class="form-label">Nama</label>
                            <input type="text" class="form-control" id="nama" name="nama" required>
                        </div>
                        <div class="mb-3">
                            <label for="hwid" class="form-label">HWID Tidak Terenkripsi</label>
                            <input type="text" class="form-control" id="hwid" name="hwid" required>
                        </div>
                        <div class="mb-3">
                            <label for="phone_number" class="form-label">Nomor Telepon</label>
                            <input type="tel" class="form-control" id="phone_number" name="phone_number" placeholder="Contoh: 6281234567890">
                        </div>
                        <div class="mb-3">
                            <label for="expiry_date" class="form-label">Tanggal Kedaluwarsa</label>
                            <input type="datetime-local" class="form-control" id="expiry_date" name="expiry_date" required>
                        </div>
                        <div class="d-flex justify-content-end pt-3">
                            <a href="dashboard.php" class="btn btn-secondary me-2">Batal</a>
                            <button type="submit" class="btn btn-primary">Simpan User</button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>