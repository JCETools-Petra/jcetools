<?php
session_start();
// Pastikan hanya admin yang sudah login yang bisa mengakses
if (!isset($_SESSION['admin_logged_in']) || $_SESSION['admin_logged_in'] !== true) {
    header('Location: login.php');
    exit;
}

require_once __DIR__ . '/core/db_connect.php';
require_once __DIR__ . '/core/crypto_helper.php'; // Panggil helper dekripsi yang baru

// Ambil template pesan dari database berdasarkan admin yang login
$template_result = $conn->prepare("SELECT message_template FROM admins WHERE username = ?");
$template_result->bind_param('s', $_SESSION['username']);
$template_result->execute();
$template_row = $template_result->get_result()->fetch_assoc();
$pesan_template = $template_row['message_template'] ?? '';
$template_result->close();

// Jika admin tidak memiliki template pesan, kembalikan ke dashboard
if (empty($pesan_template)) {
    header('Location: dashboard.php?status=template_kosong');
    exit;
}

// Ambil semua user yang memiliki alamat email yang valid
$result = $conn->query("SELECT Nama, email, hwid_encrypted, expiry_date FROM user_jce WHERE email IS NOT NULL AND email != '' AND email LIKE '%@%.%'");

// Siapkan prepared statement untuk memasukkan email ke dalam antrean
$stmt = $conn->prepare("INSERT INTO email_queue (email_address, recipient_name, subject, message) VALUES (?, ?, ?, ?)");

// Atur subjek default untuk email massal ini
$subjek_massal = "Informasi Penting Terkait Lisensi JCE Tools Anda"; 

$jumlah_antrean = 0;
while ($user = $result->fetch_assoc()) {
    // Validasi format email sebelum diproses lebih lanjut
    if (filter_var($user['email'], FILTER_VALIDATE_EMAIL)) {
        
        // ==================================================================
        // PERUBAHAN UTAMA: Dekripsi HWID sebelum digunakan
        // ==================================================================
        $hwid_decrypted = decrypt_hwid($user['hwid_encrypted']);
        // Jika dekripsi gagal, tampilkan pesan error agar tidak kosong
        if ($hwid_decrypted === false) {
            $hwid_decrypted = '[Gagal Mendekripsi HWID]';
        }
        // ==================================================================
        
        // Format tanggal kedaluwarsa
        $expiry_year = (int)date('Y', strtotime($user['expiry_date']));
        $formatted_expiry_date = ($expiry_year > 2030) ? 'Permanent' : date('d F Y H:i', strtotime($user['expiry_date']));
        
        // Ganti placeholder di template pesan dengan data pengguna
        $pesan_personal = str_replace('{nama}', $user['Nama'], $pesan_template);
        $pesan_personal = str_replace('{hwid}', $hwid_decrypted, $pesan_personal); // Gunakan HWID yang sudah di-dekripsi
        $pesan_personal = str_replace('{expiry_date}', $formatted_expiry_date, $pesan_personal);
        
        // Masukkan data ke dalam tabel antrean email
        $stmt->bind_param('ssss', $user['email'], $user['Nama'], $subjek_massal, $pesan_personal);
        $stmt->execute();
        
        $jumlah_antrean++;
    }
}

// Tutup statement dan koneksi database
$stmt->close();
$conn->close();

// Alihkan kembali ke dashboard dengan pesan sukses
header('Location: dashboard.php?status=antrean_email_dibuat&total='.$jumlah_antrean);
exit;
?>