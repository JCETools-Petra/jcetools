<?php
header('Content-Type: application/json');

// Menggunakan koneksi database yang sama
require __DIR__ . '/vendor/autoload.php';
$dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
$dotenv->load();

$servername = $_ENV['DB_HOST'];
$username_db = $_ENV['DB_USER'];
$password_db = $_ENV['DB_PASS'];
$dbname = $_ENV['DB_NAME'];

$conn = new mysqli($servername, $username_db, $password_db, $dbname);
if ($conn->connect_error) {
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'Koneksi database gagal.']);
    exit();
}

// Hanya izinkan metode POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['success' => false, 'message' => 'Metode request tidak diizinkan.']);
    exit();
}

// Validasi CSRF Token
session_start();
if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
    http_response_code(403);
    echo json_encode(['success' => false, 'message' => 'Validasi token CSRF gagal.']);
    exit();
}

$tipe_order = $_POST['tipe_order'] ?? '';
$input_value = '';
$check_table = '';
$check_column = '';

// Tentukan tabel dan kolom berdasarkan tipe order
switch ($tipe_order) {
    case 'perpanjang-hwid':
        $input_value = $_POST['hwid'] ?? '';
        // Perbaikan: HWID harus dienkripsi sebelum dicari
        // ASUMSI: Fungsi enkripsi berada di file api/crypto_helper.php
        require_once __DIR__ . '/api/encrypt.php';
        $input_value = encrypt_hwid($input_value);
        $check_table = 'user_jce';
        $check_column = 'hwid_encrypted';
        break;
    case 'perpanjang-paket':
        $input_value = $_POST['username'] ?? '';
        $check_table = 'licensed_users';
        $check_column = 'username';
        break;
    default:
        echo json_encode(['success' => false, 'message' => 'Tipe order tidak valid.']);
        exit();
}

if (empty($input_value)) {
    echo json_encode(['success' => false, 'message' => 'Input tidak boleh kosong.']);
    exit();
}

// Gunakan prepared statement untuk mencegah SQL Injection
$sql = "SELECT COUNT(*) FROM `{$check_table}` WHERE `{$check_column}` = ?";
$stmt = $conn->prepare($sql);
if (!$stmt) {
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'Gagal menyiapkan statement.']);
    exit();
}

$stmt->bind_param("s", $input_value);
$stmt->execute();
$stmt->bind_result($count);
$stmt->fetch();
$stmt->close();
$conn->close();

if ($count > 0) {
    echo json_encode(['success' => true, 'message' => 'Akun ditemukan.']);
} else {
    echo json_encode(['success' => false, 'message' => "Maaf, input yang Anda masukkan tidak terdaftar. Silakan periksa kembali."]);
}
?>