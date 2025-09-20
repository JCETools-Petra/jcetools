<?php
require __DIR__ . '/vendor/autoload.php';
require __DIR__ . '/core/session_starter.php';

ini_set('display_errors', 1);
error_reporting(E_ALL);

$dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
$dotenv->load();
header('Content-Type: application/json');

// REVISI: Validasi CSRF dengan metode Double Submit Cookie agar konsisten
$token_from_header = isset($_SERVER['HTTP_X_CSRF_TOKEN']) ? $_SERVER['HTTP_X_CSRF_TOKEN'] : '';
$token_from_cookie = isset($_COOKIE['X-CSRF-TOKEN']) ? $_COOKIE['X-CSRF-TOKEN'] : '';

if (empty($token_from_header) || empty($token_from_cookie) || !hash_equals($token_from_cookie, $token_from_header)) {
    http_response_code(403);
    echo json_encode(['success' => false, 'message' => 'Validasi keamanan gagal. Silakan muat ulang halaman.']);
    exit();
}

// Sanitasi input
$tipe_order = filter_input(INPUT_POST, 'tipe_order', FILTER_SANITIZE_SPECIAL_CHARS);
$nama_pembeli = filter_input(INPUT_POST, 'nama_pembeli', FILTER_SANITIZE_SPECIAL_CHARS);
$nomor_whatsapp = filter_input(INPUT_POST, 'nomor_whatsapp', FILTER_SANITIZE_SPECIAL_CHARS);
$license_username = filter_input(INPUT_POST, 'license_username', FILTER_SANITIZE_SPECIAL_CHARS);
$raw_password = $_POST['license_password'] ?? '';
// HASH PASSWORD SEBELUM DISIMPAN!
$license_password = password_hash($raw_password, PASSWORD_BCRYPT);
$hwid = filter_input(INPUT_POST, 'hwid', FILTER_SANITIZE_SPECIAL_CHARS);
$renewal_type = filter_input(INPUT_POST, 'renewal_type', FILTER_SANITIZE_SPECIAL_CHARS);
$produk_id = filter_input(INPUT_POST, 'produk_id', FILTER_VALIDATE_INT);
$jumlah_bulan = filter_input(INPUT_POST, 'jumlah_bulan', FILTER_VALIDATE_INT, ["options" => ["default" => 1, "min_range" => 1]]);

// Validasi tambahan
if (empty($tipe_order) || $produk_id === false) {
    echo json_encode(['success' => false, 'message' => 'Data order tidak valid.']);
    exit();
}
if ($tipe_order === 'baru' && (empty($nama_pembeli) || empty($nomor_whatsapp) || empty($license_username) || empty($license_password))) {
    echo json_encode(['success' => false, 'message' => 'Semua field untuk akun baru wajib diisi.']);
    exit();
}

$conn = new mysqli($_ENV['DB_HOST'], $_ENV['DB_USER'], $_ENV['DB_PASS'], $_ENV['DB_NAME']);
if ($conn->connect_error) {
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'Terjadi masalah pada server kami.']);
    exit();
}

$stmt = $conn->prepare("SELECT nama_produk, harga FROM produk WHERE id = ?");
$stmt->bind_param('i', $produk_id);
$stmt->execute();
$produk = $stmt->get_result()->fetch_assoc();
$stmt->close();
if (!$produk) {
    echo json_encode(['success' => false, 'message' => 'Produk yang dipilih tidak ditemukan.']);
    exit();
}

$harga = 0;
$item_details = [];
$order_id = 'ORD-' . strtoupper(bin2hex(random_bytes(8)));

if ($tipe_order === 'baru') {
    $harga = (int)$produk['harga'];
    $item_details[] = ['id' => $produk_id, 'price' => $harga, 'quantity' => 1, 'name' => $produk['nama_produk']];
    
    $stmt = $conn->prepare("INSERT INTO `transaksi` (order_id, nama_pembeli, nomor_whatsapp, license_username, license_password, produk_id, tipe_order, jumlah_bulan, harga, status_pembayaran) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
    $status_pembayaran = 'pending';
    $jumlah_bulan_baru = 1;
    $stmt->bind_param('sssssisiis', $order_id, $nama_pembeli, $nomor_whatsapp, $license_username, $license_password, $produk_id, $tipe_order, $jumlah_bulan_baru, $harga, $status_pembayaran);

} else if ($tipe_order === 'perpanjang') {
    $harga = (int)$produk['harga'] * (int)$jumlah_bulan;
    $item_details[] = ['id' => $produk_id, 'price' => (int)$produk['harga'], 'quantity' => (int)$jumlah_bulan, 'name' => $produk['nama_produk'] . ' (' . $jumlah_bulan . ' Bulan)'];

    $stmt = $conn->prepare("INSERT INTO `transaksi` (order_id, tipe_order, renewal_type, produk_id, jumlah_bulan, license_username, hwid, harga, status_pembayaran) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
    $status_pembayaran = 'pending';
    $stmt->bind_param('sssiisiss', $order_id, $tipe_order, $renewal_type, $produk_id, $jumlah_bulan, $license_username, $hwid, $harga, $status_pembayaran);
}

if (!$stmt->execute()) {
    echo json_encode(['success' => false, 'message' => 'Gagal menyimpan data transaksi: ' . $stmt->error]);
    exit();
}
$stmt->close();

\Midtrans\Config::$serverKey = $_ENV['MIDTRANS_SERVER_KEY'];
\Midtrans\Config::$isProduction = ($_ENV['APP_ENV'] === 'production');
\Midtrans\Config::$isSanitized = true;
\Midtrans\Config::$is3ds = true;

$params = [
    'transaction_details' => ['order_id' => $order_id, 'gross_amount' => $harga],
    'customer_details' => ['first_name' => $nama_pembeli ?: $license_username, 'phone' => $nomor_whatsapp],
    'item_details' => $item_details,
];

try {
    $snapToken = \Midtrans\Snap::getSnapToken($params);
    echo json_encode(['success' => true, 'snap_token' => $snapToken]);
} catch (\Exception $e) {
    echo json_encode(['success' => false, 'message' => 'Gagal membuat sesi pembayaran: ' . $e->getMessage()]);
}

$conn->close();
?>