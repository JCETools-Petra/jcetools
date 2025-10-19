<?php
require __DIR__ . '/vendor/autoload.php';
require __DIR__ . '/core/session_starter.php';
header('Content-Type: application/json');

$dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
$dotenv->load();

// Validasi CSRF yang konsisten
$token_from_header = isset($_SERVER['HTTP_X_CSRF_TOKEN']) ? $_SERVER['HTTP_X_CSRF_TOKEN'] : '';
$token_from_cookie = isset($_COOKIE['X-CSRF-TOKEN']) ? $_COOKIE['X-CSRF-TOKEN'] : '';

if (empty($token_from_header) || empty($token_from_cookie) || !hash_equals($token_from_cookie, $token_from_header)) {
    http_response_code(403);
    echo json_encode(['success' => false, 'message' => 'Validasi keamanan gagal.']);
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

// --- AWAL BAGIAN PERBAIKAN LOGIKA ---

if ($tipe_order === 'perpanjang-paket') {
    $username = $_POST['username'] ?? '';
    if (empty($username)) {
        $response['message'] = 'Username tidak boleh kosong.';
    } else {
        // PERBAIKAN: Query sekarang ke tabel `licensed_users` dan kolom `username`
        $stmt = $conn->prepare(
            "SELECT p.harga 
             FROM licensed_users u 
             JOIN produk p ON u.produk_id = p.id 
             WHERE u.username = ?"
        );
        $stmt->bind_param('s', $username);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($result->num_rows > 0) {
            $data = $result->fetch_assoc();
            $response = [
                'success' => true, 
                'message' => 'Username ditemukan dan valid.',
                'harga' => $data['harga'] // Mengirim harga asli produk milik user
            ];
        } else {
            $response['message'] = 'Username tidak ditemukan di data lisensi.';
        }
        $stmt->close();
    }
} else if ($tipe_order === 'perpanjang-hwid') {
    $hwid = $_POST['hwid'] ?? '';
    if (empty($hwid)) {
        $response['message'] = 'HWID tidak boleh kosong.';
    } else {
        // Logika enkripsi HWID Anda (asumsi sudah benar)
        $key_string = $_ENV['HWID_ENCRYPTION_KEY'] ?? 'default_key'; 
        $key = str_pad($key_string, 32, "\0", STR_PAD_RIGHT);
        $iv_hex = "1234567890abcdef1234567800000000"; 
        $iv = hex2bin($iv_hex);
        $ciphertext_raw = openssl_encrypt($hwid, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
        $hwid_encrypted = bin2hex($ciphertext_raw);

        // Query ke tabel 'user_jce' untuk HWID (sudah benar)
        $stmt = $conn->prepare("SELECT COUNT(*) as hwid_count FROM user_jce WHERE hwid_encrypted = ?");
        $stmt->bind_param('s', $hwid_encrypted);
        $stmt->execute();
        $result = $stmt->get_result()->fetch_assoc();
        $stmt->close();

        if ($result['hwid_count'] > 0) {
            $response = ['success' => true, 'message' => 'HWID ditemukan dan valid.'];
        } else {
            $response['message'] = 'HWID yang Anda masukkan tidak terdaftar.';
        }
    }
}

// --- AKHIR BAGIAN PERBAIKAN LOGIKA ---

$conn->close();
echo json_encode($response);
?>