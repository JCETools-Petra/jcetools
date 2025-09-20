<?php
require __DIR__ . '/vendor/autoload.php';
$dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
$dotenv->load();

function log_message(string $file, string $message): void { /*...*/ }
function encrypt_hwid_identik(string $plaintext): string {
    $key_string = "JCETOOLS-1830"; $key = str_pad($key_string, 32, "\0", STR_PAD_RIGHT);
    $iv_hex = "1234567890abcdef1234567800000000"; $iv = hex2bin($iv_hex);
    $ciphertext_raw = openssl_encrypt($plaintext, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
    return bin2hex($ciphertext_raw);
}
function kirimWhatsApp(string $target, string $pesan): bool { /*...*/ }

$conn = new mysqli($_ENV['DB_HOST'], $_ENV['DB_USER'], $_ENV['DB_PASS'], $_ENV['DB_NAME']);
if ($conn->connect_error) { /*...*/ }

\Midtrans\Config::$serverKey = $_ENV['MIDTRANS_SERVER_KEY'];
\Midtrans\Config::$isProduction = ($_ENV['MIDTRANS_IS_PRODUCTION'] === 'true');
$result = $conn->query("SELECT setting_value FROM settings WHERE setting_key = 'download_link' LIMIT 1");
$download_link = ($result && $result->num_rows > 0) ? $result->fetch_assoc()['setting_value'] : '';

try { $notif = new \Midtrans\Notification(); } catch (Exception $e) { /*...*/ }

$transaction = $notif->transaction_status; $order_id = $notif->order_id; $fraud = $notif->fraud_status;
$conn->begin_transaction();
try {
    $stmt = $conn->prepare("SELECT * FROM transaksi WHERE order_id = ? FOR UPDATE");
    $stmt->bind_param("s", $order_id); $stmt->execute();
    $transaksi = $stmt->get_result()->fetch_assoc(); $stmt->close();

    if (!$transaksi || $transaksi['status_pembayaran'] !== 'pending') {
        $conn->commit(); http_response_code(200); exit("Order tidak ditemukan atau sudah diproses.");
    }

    if (($transaction == 'capture' || $transaction == 'settlement') && $fraud == 'accept') {
        $conn->query("UPDATE transaksi SET status_pembayaran = 'paid' WHERE order_id = '{$order_id}'");
        $produk_res = $conn->query("SELECT durasi_hari, nama_produk FROM produk WHERE id = " . (int)$transaksi['produk_id']);
        $produk = $produk_res->fetch_assoc(); $nama_produk = $produk['nama_produk'];
        $pesan_wa = "";

        if ($transaksi['tipe_order'] === 'baru') {
            $durasi = (int)$produk['durasi_hari']; $expiry_date = date('Y-m-d H:i:s', strtotime("+$durasi days"));
            if (!empty($transaksi['license_username']) && !empty($transaksi['license_password'])) {
                $hashed_password = password_hash($transaksi['license_password'], PASSWORD_BCRYPT);
                $stmt_lic = $conn->prepare("INSERT INTO licensed_users (username, password, expiry_date, phone_number) VALUES (?, ?, ?, ?)");
                $stmt_lic->bind_param("ssss", $transaksi['license_username'], $hashed_password, $expiry_date, $transaksi['nomor_whatsapp']);
                $stmt_lic->execute(); $stmt_lic->close();
                $pesan_wa = "✅ *Pembayaran Berhasil!*\n\nTerima kasih, *{$transaksi['nama_pembeli']}*.\n\nLisensi *{$nama_produk}* Anda telah diaktifkan. Berikut detail login Anda:\n\nUsername: `{$transaksi['license_username']}`\nPassword: `{$transaksi['license_password']}`\nAktif hingga: *{$expiry_date}*\n\nSilakan unduh launcher di:\n{$download_link}\n\nTerima kasih!";
            }
        } elseif ($transaksi['tipe_order'] === 'perpanjang') {
            if ($transaksi['renewal_type'] === 'hwid') {
                $jumlah_bulan = (int)$transaksi['jumlah_bulan']; if($jumlah_bulan < 1) $jumlah_bulan = 1;
                $total_durasi_hari = 30 * $jumlah_bulan;
                $hwid_encrypted = encrypt_hwid_identik($transaksi['hwid']);
                $stmt_jce = $conn->prepare("UPDATE user_jce SET expiry_date = DATE_ADD(IF(expiry_date > NOW(), expiry_date, NOW()), INTERVAL ? DAY) WHERE hwid_encrypted = ?");
                $stmt_jce->bind_param("is", $total_durasi_hari, $hwid_encrypted);
                $stmt_jce->execute(); $stmt_jce->close();
                $pesan_wa = "✅ *Pembayaran Berhasil!*\n\nTerima kasih, *{$transaksi['nama_pembeli']}*.\n\nLisensi HWID Anda telah berhasil diperpanjang selama *{$jumlah_bulan} bulan*.";
            } elseif ($transaksi['renewal_type'] === 'session') {
                $jumlah_bulan = (int)$transaksi['jumlah_bulan']; if($jumlah_bulan < 1) $jumlah_bulan = 1;
                $total_durasi_hari = 30 * $jumlah_bulan;
                $stmt_lic = $conn->prepare("UPDATE licensed_users SET expiry_date = DATE_ADD(IF(expiry_date > NOW(), expiry_date, NOW()), INTERVAL ? DAY) WHERE username = ?");
                $stmt_lic->bind_param("is", $total_durasi_hari, $transaksi['license_username']);
                $stmt_lic->execute(); $stmt_lic->close();
                $pesan_wa = "✅ *Pembayaran Berhasil!*\n\nTerima kasih, *{$transaksi['nama_pembeli']}*.\n\nLisensi *{$nama_produk}* untuk akun '{$transaksi['license_username']}' telah berhasil diperpanjang selama *{$jumlah_bulan} bulan*.";
            }
        }
        
        if (!empty($pesan_wa)) { kirimWhatsApp($transaksi['nomor_whatsapp'], $pesan_wa); }
    } else if (in_array($transaction, ['expire', 'deny', 'cancel'])) {
        $new_status = ($transaction == 'expire') ? 'expired' : 'failed';
        $conn->query("UPDATE transaksi SET status_pembayaran = '{$new_status}' WHERE order_id = '{$order_id}'");
    }
    $conn->commit();
} catch (Exception $e) { $conn->rollback(); log_message('midtrans_error.log', "--- ERROR KRITIS #{$order_id} ---: " . $e->getMessage()); http_response_code(500); exit("Failed."); }
http_response_code(200);
echo "OK";