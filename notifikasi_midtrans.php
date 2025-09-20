<?php
require __DIR__ . '/vendor/autoload.php';
$dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
$dotenv->load();

// Fungsi untuk mencatat pesan ke file log
function log_message(string $file, string $message): void {
    file_put_contents($file, '['.date('Y-m-d H:i:s').'] ' . $message . "\n", FILE_APPEND);
}

// Fungsi untuk mengenkripsi HWID
function encrypt_hwid_identik(string $plaintext): string {
    $key_string = "JCETOOLS-1830"; $key = str_pad($key_string, 32, "\0", STR_PAD_RIGHT);
    $iv_hex = "1234567890abcdef1234567800000000"; $iv = hex2bin($iv_hex);
    $ciphertext_raw = openssl_encrypt($plaintext, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
    return bin2hex($ciphertext_raw);
}

// Fungsi untuk mengirim pesan WhatsApp
function kirimWhatsApp(string $target, string $pesan): bool {
    // URL API FonNte
    $url = "https://api.fonnte.com/send";
    
    // Data yang akan dikirim ke API
    $data = [
        'target' => $target,
        'message' => $pesan
    ];
    
    // Header request dengan token API
    $headers = [
        'Authorization: ' . $_ENV['FONNTE_TOKEN']
    ];
    
    // Inisialisasi cURL
    $ch = curl_init($url);
    
    // Opsi cURL
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($data));
    
    // Jalankan cURL dan dapatkan respons
    $response = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    // Log respons untuk debugging
    log_message('whatsapp_response.log', "Target: {$target}, Response: " . $response);

    if ($http_code == 200) {
        $result = json_decode($response, true);
        if (isset($result['status']) && $result['status'] === 'success') {
            return true;
        }
    }
    
    return false;
}

// Atur koneksi database
$conn = new mysqli($_ENV['DB_HOST'], $_ENV['DB_USER'], $_ENV['DB_PASS'], $_ENV['DB_NAME']);
if ($conn->connect_error) {
    log_message('midtrans_error.log', "Connection failed: " . $conn->connect_error);
    exit("Connection failed.");
}

// Konfigurasi Midtrans
\Midtrans\Config::$serverKey = $_ENV['MIDTRANS_SERVER_KEY'];
\Midtrans\Config::$isProduction = ($_ENV['MIDTRANS_IS_PRODUCTION'] === 'true');

try {
    $notif = new \Midtrans\Notification();
} catch (Exception $e) {
    log_message('midtrans_error.log', "Failed to get Midtrans notification: " . $e->getMessage());
    exit("Failed to get notification.");
}

// Verifikasi Signature Key (Sangat Penting!)
$signature_key = hash('sha512', $notif->order_id . $notif->status_code . $notif->gross_amount . \Midtrans\Config::$serverKey);
if ($signature_key != $notif->signature_key) {
    http_response_code(403);
    log_message('midtrans_error.log', "Invalid signature key for Order ID: " . $notif->order_id);
    exit("Invalid signature.");
}

$transaction_status = $notif->transaction_status;
$order_id = $notif->order_id;
$fraud_status = $notif->fraud_status;

$conn->begin_transaction();
try {
    $stmt = $conn->prepare("SELECT * FROM transaksi WHERE order_id = ? FOR UPDATE");
    $stmt->bind_param("s", $order_id);
    $stmt->execute();
    $transaksi = $stmt->get_result()->fetch_assoc();
    $stmt->close();

    if (!$transaksi || $transaksi['status_pembayaran'] !== 'pending') {
        $conn->commit();
        http_response_code(200);
        exit("Order tidak ditemukan atau sudah diproses.");
    }

    // Hanya proses jika pembayaran lunas dan aman
    if (($transaction_status == 'capture' || $transaction_status == 'settlement') && $fraud_status == 'accept') {
        
        $stmt_update_trans = $conn->prepare("UPDATE transaksi SET status_pembayaran = 'paid', waktu_pemesanan = NOW() WHERE order_id = ?");
        $stmt_update_trans->bind_param('s', $order_id);
        $stmt_update_trans->execute();
        $stmt_update_trans->close();
        
        // Ambil detail produk termasuk link download spesifik
        $stmt_produk = $conn->prepare("SELECT durasi_hari, nama_produk, download_link FROM produk WHERE id = ?");
        $stmt_produk->bind_param('i', $transaksi['produk_id']);
        $stmt_produk->execute();
        $produk = $stmt_produk->get_result()->fetch_assoc();
        $stmt_produk->close();

        $nama_produk = $produk['nama_produk'];
        $download_link_produk = $produk['download_link'];
        $pesan_wa = "";
        $nomor_wa_tujuan = $transaksi['nomor_whatsapp'];

        if ($transaksi['tipe_order'] === 'baru') {
            $durasi = (int)$produk['durasi_hari'];
            $expiry_date_obj = new DateTime();
            $expiry_date_obj->add(new DateInterval("P{$durasi}D"));
            $expiry_date = $expiry_date_obj->format('Y-m-d H:i:s');

            if (!empty($transaksi['license_username']) && !empty($transaksi['license_password'])) {
                $hashed_password = password_hash($transaksi['license_password'], PASSWORD_BCRYPT);
                
                $stmt_lic = $conn->prepare("INSERT INTO licensed_users (username, password, produk_id, expiry_date, phone_number) VALUES (?, ?, ?, ?, ?)");
                $stmt_lic->bind_param("ssiss", $transaksi['license_username'], $hashed_password, $transaksi['produk_id'], $expiry_date, $transaksi['nomor_whatsapp']);
                $stmt_lic->execute();
                $stmt_lic->close();
                
                $pesan_wa = "✅ *Pembayaran Berhasil!*\n\nTerima kasih, *{$transaksi['nama_pembeli']}*.\n\nLisensi *{$nama_produk}* Anda telah diaktifkan. Berikut detail login Anda:\n\nUsername: `{$transaksi['license_username']}`\nPassword: `{$transaksi['license_password']}`\nAktif hingga: *{$expiry_date}*\n\nSilakan unduh launcher di:\n{$download_link_produk}\n\nTerima kasih!";
            }
        } elseif ($transaksi['tipe_order'] === 'perpanjang') {
            $jumlah_bulan = (int)$transaksi['jumlah_bulan'] > 0 ? (int)$transaksi['jumlah_bulan'] : 1;
            $total_durasi_hari = 30 * $jumlah_bulan;

            if ($transaksi['renewal_type'] === 'hwid') {
                $hwid_encrypted = encrypt_hwid_identik($transaksi['hwid']);
                
                $stmt_jce = $conn->prepare("UPDATE user_jce SET expiry_date = DATE_ADD(IF(expiry_date > NOW(), expiry_date, NOW()), INTERVAL ? DAY) WHERE hwid_encrypted = ?");
                $stmt_jce->bind_param("is", $total_durasi_hari, $hwid_encrypted);
                $stmt_jce->execute();
                $stmt_jce->close();
                
                $stmt_get_expiry = $conn->prepare("SELECT Nama, expiry_date, phone_number FROM user_jce WHERE hwid_encrypted = ?");
                $stmt_get_expiry->bind_param('s', $hwid_encrypted);
                $stmt_get_expiry->execute();
                $user_info = $stmt_get_expiry->get_result()->fetch_assoc();
                $stmt_get_expiry->close();

                $nama_pembeli = $user_info['Nama'] ?? 'Pelanggan';
                $nomor_wa_tujuan = $user_info['phone_number'] ?? '';
                $new_expiry_date = $user_info['expiry_date'] ?? 'N/A';
                
                $pesan_wa = "✅ *Perpanjangan Lisensi Berhasil!*\n\nTerima kasih, *{$nama_pembeli}*.\n\nLisensi HWID Anda telah diperpanjang selama *{$jumlah_bulan} bulan*.\n\nAktif hingga: *{$new_expiry_date}*";

            } elseif ($transaksi['renewal_type'] === 'session') {
                $stmt_lic = $conn->prepare("UPDATE licensed_users SET expiry_date = DATE_ADD(IF(expiry_date > NOW(), expiry_date, NOW()), INTERVAL ? DAY) WHERE username = ?");
                $stmt_lic->bind_param("is", $total_durasi_hari, $transaksi['license_username']);
                $stmt_lic->execute();
                $stmt_lic->close();
                
                // --- TAMBAHKAN KODE INI ---
                // Ambil nomor WA dari tabel licensed_users
                $stmt_get_phone = $conn->prepare("SELECT phone_number FROM licensed_users WHERE username = ?");
                $stmt_get_phone->bind_param('s', $transaksi['license_username']);
                $stmt_get_phone->execute();
                $user_phone_info = $stmt_get_phone->get_result()->fetch_assoc();
                $stmt_get_phone->close();
                $nomor_wa_tujuan = $user_phone_info['phone_number'] ?? $nomor_wa_tujuan; // Ambil dari DB, fallback ke data transaksi
                // --- SELESAI PENAMBAHAN ---
            
                // Ambil link download berdasarkan produk milik user
                $stmt_user_product = $conn->prepare(
                    "SELECT p.download_link 
                     FROM licensed_users u 
                     JOIN produk p ON u.produk_id = p.id 
                     WHERE u.username = ?"
                );
                $stmt_user_product->bind_param("s", $transaksi['license_username']);
                $stmt_user_product->execute();
                $user_product = $stmt_user_product->get_result()->fetch_assoc();
                $stmt_user_product->close();
                $download_link_user = $user_product['download_link'] ?? '#';
            
                $pesan_wa = "✅ *Perpanjangan Lisensi Berhasil!*\n\nLisensi *{$nama_produk}* untuk akun '{$transaksi['license_username']}' telah diperpanjang selama *{$jumlah_bulan} bulan*.\n\nSilakan unduh update launcher di:\n{$download_link_user}";
            }
        }
        
        if (!empty($pesan_wa) && !empty($nomor_wa_tujuan)) {
            kirimWhatsApp($nomor_wa_tujuan, $pesan_wa);
        }

    } else if (in_array($transaction_status, ['expire', 'deny', 'cancel'])) {
        $new_status = ($transaction_status == 'expire') ? 'expired' : 'failed';
        $stmt_fail_trans = $conn->prepare("UPDATE transaksi SET status_pembayaran = ?, waktu_pemesanan = NOW() WHERE order_id = ?");
        $stmt_fail_trans->bind_param('ss', $new_status, $order_id);
        $stmt_fail_trans->execute();
        $stmt_fail_trans->close();
    }

    $conn->commit();

} catch (Exception $e) {
    $conn->rollback();
    log_message('midtrans_error.log', "--- ERROR KRITIS #{$order_id} ---: " . $e->getMessage());
    http_response_code(500);
    exit("Failed.");
}

http_response_code(200);
echo "OK";
?>