<?php
require __DIR__ . '/vendor/autoload.php';
require __DIR__ . '/core/session_starter.php';
header('Content-Type: application/json');

$dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
$dotenv->load();

// REVISI: Validasi CSRF dengan metode Double Submit Cookie yang lebih andal
$token_from_header = isset($_SERVER['HTTP_X_CSRF_TOKEN']) ? $_SERVER['HTTP_X_CSRF_TOKEN'] : '';
$token_from_cookie = isset($_COOKIE['X-CSRF-TOKEN']) ? $_COOKIE['X-CSRF-TOKEN'] : '';

if (empty($token_from_header) || empty($token_from_cookie) || !hash_equals($token_from_cookie, $token_from_header)) {
    http_response_code(403);
    echo json_encode(['success' => false, 'message' => 'Validasi keamanan gagal. Silakan muat ulang halaman.']);
    exit();
}

// Hanya izinkan metode POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['success' => false, 'message' => 'Metode request tidak diizinkan.']);
    exit();
}

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
        // REVISI: Query disesuaikan dengan tabel 'user_jce' dan kolom 'Nama'
        // Asumsi: Harga perpanjangan akun diambil dari produk termurah, karena tidak ada relasi produk di tabel user_jce
        $stmt = $conn->prepare("SELECT COUNT(*) as user_count FROM user_jce WHERE Nama = ?");
        $stmt->bind_param('s', $username);
        $stmt->execute();
        $result = $stmt->get_result();
        $user = $result->fetch_assoc();
        
        if ($user['user_count'] > 0) {
            // Ambil harga produk termurah sebagai acuan harga perpanjangan
            $product_stmt = $conn->prepare("SELECT harga FROM produk WHERE is_active = TRUE ORDER BY harga ASC LIMIT 1");
            $product_stmt->execute();
            $product_result = $product_stmt->get_result();
            if($product_result->num_rows > 0) {
                $product = $product_result->fetch_assoc();
                $response = ['success' => true, 'message' => 'Username ditemukan dan valid.', 'harga' => $product['harga']];
            } else {
                $response['message'] = 'Tidak ada produk aktif yang bisa digunakan untuk perpanjangan.';
            }
            $product_stmt->close();
        } else {
            $response['message'] = 'Username tidak ditemukan.';
        }
        $stmt->close();
    }
} else if ($tipe_order === 'perpanjang-hwid') {
    $hwid = $_POST['hwid'] ?? '';
    if (empty($hwid)) {
        $response['message'] = 'HWID tidak boleh kosong.';
    } else {
        // Enkripsi HWID sesuai dengan logika yang ada
        $key_string = $_ENV['HWID_ENCRYPTION_KEY']; $key = str_pad($key_string, 32, "\0", STR_PAD_RIGHT);
        $iv_hex = "1234567890abcdef1234567800000000"; $iv = hex2bin($iv_hex);
        $ciphertext_raw = openssl_encrypt($hwid, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
        $hwid_encrypted = bin2hex($ciphertext_raw);

        // REVISI: Query sudah benar, menggunakan tabel 'user_jce' dan kolom 'hwid_encrypted'
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