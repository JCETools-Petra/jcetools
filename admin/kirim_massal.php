<?php
session_start();
if (!isset($_SESSION['admin_logged_in']) || $_SESSION['admin_logged_in'] !== true) {
    header('Location: login.php');
    exit;
}

require_once __DIR__ . '/core/db_connect.php';
require_once __DIR__ . '/core/whatsapp_helper.php';

// Ambil template pesan dari database
$template_result = $conn->query("SELECT message_template FROM admins WHERE username = '{$_SESSION['username']}'");
$template_row = $template_result->fetch_assoc();
$pesan = $template_row['message_template'] ?? '';

if (empty($pesan)) {
    header('Location: dashboard.php?status=template_kosong');
    exit;
}

// Ambil semua user yang punya nomor telepon valid, termasuk hwid dan expiry_date
$result = $conn->query("SELECT Nama, phone_number, hwid_encrypted, expiry_date FROM user_jce WHERE phone_number IS NOT NULL AND phone_number != ''");

$berhasil_kirim = 0;
$gagal_kirim = 0;

while ($user = $result->fetch_assoc()) {
    // Tentukan apakah tanggal kedaluwarsa adalah "Permanent"
    $expiry_year = (int)date('Y', strtotime($user['expiry_date']));
    $formatted_expiry_date = ($expiry_year > 2030) ? 'Permanent' : $user['expiry_date'];
    
    // Ganti placeholder {nama}, {hwid}, dan {expiry_date}
    $pesan_personal = str_replace('{nama}', $user['Nama'], $pesan);
    $pesan_personal = str_replace('{hwid}', $user['hwid_encrypted'], $pesan_personal);
    $pesan_personal = str_replace('{expiry_date}', $formatted_expiry_date, $pesan_personal);

    if (kirimWhatsApp($user['phone_number'], $pesan_personal)) {
        $berhasil_kirim++;
    } else {
        $gagal_kirim++;
    }
    sleep(1); 
}

$pesan_sukses = "Proses pengiriman selesai. Berhasil: {$berhasil_kirim}. Gagal: {$gagal_kirim}.";
$conn->close();

header('Location: dashboard.php?status=kirim_selesai&berhasil='.$berhasil_kirim.'&gagal='.$gagal_kirim);
exit;
?>