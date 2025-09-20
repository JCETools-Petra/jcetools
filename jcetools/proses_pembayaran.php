<?php
error_reporting(E_ALL & ~E_WARNING);
ini_set('display_errors', 0);

session_start();
header('Content-Type: application/json');

require __DIR__ . '/vendor/autoload.php';
$dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
$dotenv->load();
require __DIR__ . '/admin/core/db_connect.php'; 

$response = ['success' => false, 'message' => 'Terjadi kesalahan.'];

if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
    $response['message'] = 'Sesi tidak valid.';
    echo json_encode($response);
    exit;
}

// Ambil semua data dari POST
$tipe_order = $_POST['tipe_order'] ?? '';
$produk_id = (int)($_POST['produk_id'] ?? 0);
$nama = trim($_POST['nama_pembeli'] ?? '');
$whatsapp = trim($_POST['nomor_whatsapp'] ?? '');
$hwid_plain = trim($_POST['hwid'] ?? '');
$license_username = trim($_POST['license_username'] ?? '');
$license_password = $_POST['license_password'] ?? '';
$renewal_type = $_POST['renewal_type'] ?? '';
$jumlah_bulan = (int)($_POST['jumlah_bulan'] ?? 1);

$harga = 0;

if (($tipe_order === 'perpanjang' && $renewal_type === 'hwid') || ($tipe_order === 'perpanjang' && $renewal_type === 'session')) {
    $stmt_harga = $conn->prepare("SELECT harga FROM produk WHERE id = ?");
    $stmt_harga->bind_param("i", $produk_id);
    $stmt_harga->execute();
    $result_harga = $stmt_harga->get_result();
    if ($result_harga->num_rows > 0) {
        $produk_harga = $result_harga->fetch_assoc();
        $harga_bulanan = $produk_harga['harga'];
        if ($jumlah_bulan < 1) $jumlah_bulan = 1;
        $harga = $harga_bulanan * $jumlah_bulan;
    }
    $stmt_harga->close();
} else {
    $stmt_prod = $conn->prepare("SELECT harga FROM produk WHERE id = ?");
    $stmt_prod->bind_param("i", $produk_id);
    $stmt_prod->execute();
    $result_prod = $stmt_prod->get_result();
    if ($result_prod->num_rows > 0) {
        $produk = $result_prod->fetch_assoc();
        $harga = $produk['harga'];
    }
    $stmt_prod->close();
}

if ($harga <= 0) {
    $response['message'] = 'Produk atau perhitungan harga tidak valid.';
    echo json_encode($response);
    exit;
}

if ($tipe_order === 'baru' && !empty($license_username)) {
    $stmt = $conn->prepare("SELECT id FROM licensed_users WHERE username = ?");
    $stmt->bind_param("s", $license_username);
    $stmt->execute();
    if ($stmt->get_result()->num_rows > 0) {
        $response['message'] = 'Username untuk lisensi sudah terdaftar.';
        echo json_encode($response);
        exit;
    }
    $stmt->close();
} elseif ($tipe_order === 'perpanjang') {
    if ($renewal_type === 'hwid' && !empty($hwid_plain)) {
        function encryptHwid($p, $k, $i) { return openssl_encrypt($p, 'aes-256-cbc', $k, OPENSSL_RAW_DATA, $i); }
        function binToHex($d) { return bin2hex($d); }
        $key_string = "JCETOOLS-1830"; $key = str_pad($key_string, 32, "\0", STR_PAD_RIGHT);
        $iv_hex = "1234567890abcdef1234567800000000"; $iv = hex2bin($iv_hex);
        $hwid_encrypted = binToHex(encryptHwid($hwid_plain, $key, $iv));
        
        $stmt = $conn->prepare("SELECT Nama, phone_number FROM user_jce WHERE hwid_encrypted = ?");
        $stmt->bind_param("s", $hwid_encrypted);
        $stmt->execute();
        $result = $stmt->get_result();
        if ($result->num_rows === 0) {
            $response['message'] = 'HWID tidak terdaftar. Pastikan HWID Anda benar.';
            echo json_encode($response);
            exit;
        } else {
            $user_data = $result->fetch_assoc();
            $nama = $user_data['Nama'];
            $whatsapp = $user_data['phone_number'];
        }
        $stmt->close();
    } elseif ($renewal_type === 'session' && !empty($license_username)) {
        $stmt = $conn->prepare("SELECT username, phone_number FROM licensed_users WHERE username = ?");
        $stmt->bind_param("s", $license_username);
        $stmt->execute();
        $result_user = $stmt->get_result();
        if ($result_user->num_rows === 0) {
            $response['message'] = 'Username tidak ditemukan. Silakan gunakan menu Beli Baru.';
            echo json_encode($response);
            exit;
        } else {
             $user_data = $result_user->fetch_assoc();
             $nama = $user_data['username'];
             $whatsapp = $user_data['phone_number'];
        }
        $stmt->close();
    }
}

$stmt_insert = $conn->prepare("INSERT INTO transaksi (nama_pembeli, nomor_whatsapp, hwid, license_username, license_password, produk_id, tipe_order, renewal_type, jumlah_bulan, harga, status_pembayaran) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
$status_pembayaran_default = 'pending';
$stmt_insert->bind_param("sssssissids", $nama, $whatsapp, $hwid_plain, $license_username, $license_password, $produk_id, $tipe_order, $renewal_type, $jumlah_bulan, $harga, $status_pembayaran_default);
if (!$stmt_insert->execute()) {
    $response['message'] = 'Gagal menyimpan transaksi awal: ' . $stmt_insert->error;
    echo json_encode($response);
    exit;
}

$transaksi_id = $stmt_insert->insert_id;
$order_id = 'JCE-' . $transaksi_id . '-' . time();
$stmt_insert->close();
$stmt_update = $conn->prepare("UPDATE transaksi SET order_id = ? WHERE id = ?");
$stmt_update->bind_param("si", $order_id, $transaksi_id);
$stmt_update->execute();
$stmt_update->close();

\Midtrans\Config::$serverKey = $_ENV['MIDTRANS_SERVER_KEY'];
\Midtrans\Config::$isProduction = ($_ENV['MIDTRANS_IS_PRODUCTION'] === 'true');
\Midtrans\Config::$isSanitized = true;
\Midtrans\Config::$is3ds = true;
$params = ['transaction_details' => ['order_id' => $order_id, 'gross_amount' => $harga], 'customer_details' => ['first_name' => $nama, 'phone' => $whatsapp]];

try {
    $snapToken = \Midtrans\Snap::getSnapToken($params);
    $conn->query("UPDATE transaksi SET snap_token = '$snapToken' WHERE id = '$transaksi_id'");
    $response['success'] = true;
    $response['snap_token'] = $snapToken;
} catch (Exception $e) {
    $response['message'] = $e->getMessage();
}
echo json_encode($response);