<?php
// File: check_user.php (Versi Final)
header('Content-Type: application/json');

// Muat autoloader dan file .env
require_once __DIR__ . '/vendor/autoload.php';
try {
    $dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
    $dotenv->load();
} catch (Exception $e) {
    echo json_encode(['success' => false, 'message' => 'Error: Gagal memuat environment.']);
    exit();
}

// Ambil kredensial database
$servername = $_ENV['DB_HOST'];
$username_db = $_ENV['DB_USER'];
$password_db = $_ENV['DB_PASS'];
$dbname = $_ENV['DB_NAME'];

// Buat koneksi
$conn = new mysqli($servername, $username_db, $password_db, $dbname);
if ($conn->connect_error) {
    echo json_encode(['success' => false, 'message' => 'Koneksi database gagal: ' . $conn->connect_error]);
    exit();
}

// Pastikan metode request adalah POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(['success' => false, 'message' => 'Metode tidak valid.']);
    exit();
}

// Ambil data dari input
$type = $_POST['type'] ?? '';
$value = trim($_POST['value'] ?? '');
$orderType = $_POST['orderType'] ?? '';

if (empty($type) || empty($value) || empty($orderType)) {
    echo json_encode(['success' => false, 'message' => 'Data input tidak lengkap.']);
    exit();
}

$response = ['success' => true, 'valid' => false, 'message' => ''];

// Tentukan kolom database berdasarkan tipe pengecekan
$column = '';
if ($type === 'username') {
    $column = 'username';
} elseif ($type === 'hwid') {
    $column = 'hwid';
} else {
    echo json_encode(['success' => false, 'message' => 'Tipe pengecekan tidak valid.']);
    exit();
}

// Gunakan prepared statement untuk keamanan query
// Berdasarkan file Anda, nama tabel sudah benar yaitu 'users'
$stmt = $conn->prepare("SELECT COUNT(*) as count FROM users WHERE $column = ?");
if ($stmt === false) {
    echo json_encode(['success' => false, 'message' => 'Gagal mempersiapkan query.']);
    exit();
}

$stmt->bind_param("s", $value);
$stmt->execute();
$result = $stmt->get_result()->fetch_assoc();
$userExists = $result['count'] > 0;
$stmt->close();

// Logika validasi
if ($orderType === 'baru') {
    // Untuk order baru, username tidak boleh ada (harus unik)
    if ($userExists) {
        $response['valid'] = false;
        $response['message'] = 'Username sudah terdaftar, silakan gunakan username lain.';
    } else {
        $response['valid'] = true; // Username tersedia
    }
} elseif ($orderType === 'perpanjang') {
    // Untuk perpanjangan, username atau HWID harus sudah terdaftar
    if ($userExists) {
        $response['valid'] = true; // Ditemukan, boleh perpanjang
    } else {
        $response['valid'] = false;
        $response['message'] = ucfirst($type) . ' tidak ditemukan atau belum terdaftar.';
    }
}

// Kirim hasil validasi
echo json_encode($response);

$conn->close();
?>