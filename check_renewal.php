<?php
require __DIR__ . '/core/session_starter.php'; // Mulai sesi dengan cara yang benar
header('Content-Type: application/json');

require __DIR__ . '/vendor/autoload.php';
$dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
$dotenv->load();

// Validasi CSRF Token
if (empty($_SESSION['csrf_token']) || !isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
    http_response_code(403);
    echo json_encode(['success' => false, 'message' => 'Sesi tidak valid atau telah kedaluwarsa. Silakan muat ulang halaman.']);
    exit();
}

// Hanya izinkan metode POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['success' => false, 'message' => 'Metode request tidak diizinkan.']);
    exit();
}

// Atur koneksi database
$conn = new mysqli($_ENV['DB_HOST'], $_ENV['DB_USER'], $_ENV['DB_PASS'], $_ENV['DB_NAME']);
if ($conn->connect_error) {
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'Koneksi database gagal.']);
    exit();
}

$tipe_order = $_POST['tipe_order'] ?? '';
$response = ['success' => false, 'message' => 'Tipe order tidak valid.'];

if ($tipe_order === 'perpanjang-paket') {
    $username = $_POST['username'] ?? '';
    if (empty($username)) {
        $response['message'] = 'Username tidak boleh kosong.';
    } else {
        $stmt = $conn->prepare("SELECT p.nama_produk, p.harga FROM licensed_users u JOIN produk p ON u.produk_id = p.id WHERE u.username = ? AND p.is_active = TRUE");
        $stmt->bind_param('s', $username);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($result->num_rows > 0) {
            $data = $result->fetch_assoc();
            $response = ['success' => true, 'message' => 'Username ditemukan. Paket: ' . htmlspecialchars($data['nama_produk']), 'harga' => $data['harga']];
        } else {
            $response['message'] = 'Username tidak ditemukan atau paket lisensi sudah tidak aktif.';
        }
        $stmt->close();
    }
} else if ($tipe_order === 'perpanjang-hwid') {
    $hwid = $_POST['hwid'] ?? '';
    if (empty($hwid)) {
        $response['message'] = 'HWID tidak boleh kosong.';
    } else {
        $key_string = "JCETOOLS-1830"; $key = str_pad($key_string, 32, "\0", STR_PAD_RIGHT);
        $iv_hex = "1234567890abcdef1234567800000000"; $iv = hex2bin($iv_hex);
        $ciphertext_raw = openssl_encrypt($hwid, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
        $hwid_encrypted = bin2hex($ciphertext_raw);

        $stmt = $conn->prepare("SELECT COUNT(*) FROM user_jce WHERE hwid_encrypted = ?");
        $stmt->bind_param('s', $hwid_encrypted);
        $stmt->execute();
        $stmt->bind_result($count);
        $stmt->fetch();
        $stmt->close();

        if ($count > 0) {
            $response = ['success' => true, 'message' => 'HWID ditemukan dan valid.'];
        } else {
            $response['message'] = 'HWID yang Anda masukkan tidak terdaftar.';
        }
    }
}

$conn->close();
echo json_encode($response);
?>