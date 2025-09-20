<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('log_errors', 1);
ini_set('error_log', __DIR__ . '/error_log_pembayaran.txt');

// Load .env dan koneksi database
require __DIR__ . '/vendor/autoload.php';
$dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
$dotenv->load();

// Sertakan file crypto_helper untuk enkripsi HWID
require_once __DIR__ . '/api/crypto_helper.php';

header('Content-Type: application/json');

session_start();

// Periksa CSRF token. Penting!
if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
    http_response_code(403);
    echo json_encode(['success' => false, 'message' => 'Validasi token CSRF gagal.']);
    exit();
}

// Gunakan filter_input untuk sanitasi input
$tipe_order = filter_input(INPUT_POST, 'tipe_order', FILTER_SANITIZE_STRING);
$nama_pembeli = filter_input(INPUT_POST, 'nama_pembeli', FILTER_SANITIZE_STRING);
$nomor_whatsapp = filter_input(INPUT_POST, 'nomor_whatsapp', FILTER_SANITIZE_STRING);
$license_username = filter_input(INPUT_POST, 'license_username', FILTER_SANITIZE_STRING);
$license_password = $_POST['license_password'] ?? '';
$hwid = filter_input(INPUT_POST, 'hwid', FILTER_SANITIZE_STRING);
$renewal_type = filter_input(INPUT_POST, 'renewal_type', FILTER_SANITIZE_STRING);
$produk_id = filter_input(INPUT_POST, 'produk_id', FILTER_SANITIZE_NUMBER_INT);
$jumlah_bulan = filter_input(INPUT_POST, 'jumlah_bulan', FILTER_SANITIZE_NUMBER_INT);

// Validasi tambahan
if (empty($tipe_order) || empty($produk_id)) {
    echo json_encode(['success' => false, 'message' => 'Data order tidak lengkap.']);
    exit();
}
if ($tipe_order === 'baru') {
    if (empty($nama_pembeli) || empty($nomor_whatsapp) || empty($license_username) || empty($license_password)) {
        echo json_encode(['success' => false, 'message' => 'Data akun baru tidak lengkap.']);
        exit();
    }
}

// Atur koneksi database
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

// Ambil data produk
$stmt = $conn->prepare("SELECT nama_produk, harga FROM produk WHERE id = ?");
$stmt->bind_param('i', $produk_id);
$stmt->execute();
$result = $stmt->get_result();
$produk = $result->fetch_assoc();
$stmt->close();
if (!$produk) {
    echo json_encode(['success' => false, 'message' => 'Produk tidak ditemukan.']);
    exit();
}

// Tentukan harga
$harga = 0;
$item_details = [];
$order_id = 'ORD-' . strtoupper(bin2hex(random_bytes(6)));

if ($tipe_order === 'baru') {
    $harga = $produk['harga'];
    $item_details[] = [
        'id' => $produk_id,
        'price' => $produk['harga'],
        'quantity' => 1,
        'name' => $produk['nama_produk']
    ];
    
    // Periksa apakah username sudah ada (opsional tapi disarankan)
    $stmt = $conn->prepare("SELECT COUNT(*) FROM licensed_users WHERE username = ?");
    $stmt->bind_param('s', $license_username);
    $stmt->execute();
    $result_check = $stmt->get_result();
    $row = $result_check->fetch_row();
    if ($row[0] > 0) {
        echo json_encode(['success' => false, 'message' => 'Username sudah digunakan. Silakan pilih yang lain.']);
        exit();
    }
    $stmt->close();

    // Simpan data order baru ke tabel `transaksi`
    // Menyesuaikan dengan nama kolom yang ada di tabel Anda
    $stmt = $conn->prepare("INSERT INTO `transaksi` (`order_id`, `nama_pembeli`, `nomor_whatsapp`, `license_username`, `license_password`, `produk_id`, `tipe_order`, `jumlah_bulan`, `harga`, `status_pembayaran`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
    $status_pembayaran = 'pending';
    // PERBAIKAN: Ubah 'sssssisiss' menjadi 'sssssiissi'
    $stmt->bind_param('sssssiissi', $order_id, $nama_pembeli, $nomor_whatsapp, $license_username, $license_password, $produk_id, $tipe_order, $jumlah_bulan, $harga, $status_pembayaran);
    $stmt->execute();
    $stmt->close();

} else if ($tipe_order === 'perpanjang') {
    $harga = $produk['harga'] * $jumlah_bulan;
    $item_details[] = [
        'id' => $produk_id,
        'price' => $produk['harga'],
        'quantity' => $jumlah_bulan,
        'name' => $produk['nama_produk'] . ' (' . $jumlah_bulan . ' Bulan)'
    ];

    // Simpan data perpanjangan ke tabel `transaksi`
    // Menyesuaikan dengan nama kolom yang ada di tabel Anda
    $stmt = $conn->prepare("INSERT INTO `transaksi` (`order_id`, `tipe_order`, `renewal_type`, `produk_id`, `jumlah_bulan`, `license_username`, `hwid`, `harga`, `status_pembayaran`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
    $status_pembayaran = 'pending';
    // PERBAIKAN: Ubah 'ssssissss' menjadi 'sssiisiss'
    $stmt->bind_param('sssiisiss', $order_id, $tipe_order, $renewal_type, $produk_id, $jumlah_bulan, $license_username, $hwid, $harga, $status_pembayaran);
    $stmt->execute();
    $stmt->close();
}

// Konfigurasi Midtrans
\Midtrans\Config::$serverKey = $_ENV['MIDTRANS_SERVER_KEY'];
\Midtrans\Config::$isProduction = false;
\Midtrans\Config::$isSanitized = true;
\Midtrans\Config::$is3ds = true;

// Buat parameter transaksi
$transaction_details = [
    'order_id' => $order_id,
    'gross_amount' => $harga,
];

// Informasi pelanggan
$customer_details = [];
if (!empty($nama_pembeli)) {
    $customer_details['first_name'] = $nama_pembeli;
}
if (!empty($nomor_whatsapp)) {
    $customer_details['phone'] = $nomor_whatsapp;
}

$params = [
    'transaction_details' => $transaction_details,
    'customer_details' => $customer_details,
    'item_details' => $item_details,
];

try {
    $snapToken = \Midtrans\Snap::getSnapToken($params);
    echo json_encode(['success' => true, 'snap_token' => $snapToken]);
} catch (\Exception $e) {
    echo json_encode(['success' => false, 'message' => $e->getMessage()]);
}

$conn->close();
?>