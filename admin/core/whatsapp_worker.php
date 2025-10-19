<?php
// Skrip ini akan dijalankan oleh Cron Job

// Pastikan path-nya benar dari lokasi file ini
require_once __DIR__ . '/db_connect.php';
require_once __DIR__ . '/whatsapp_helper.php';

// Ambil 5 pesan yang masih pending dari antrean
$limit = 5;
$stmt = $conn->prepare("SELECT id, phone_number, message FROM whatsapp_queue WHERE status = 'pending' ORDER BY id ASC LIMIT ?");
$stmt->bind_param('i', $limit);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows === 0) {
    // Tidak ada pesan untuk dikirim, keluar
    $conn->close();
    exit;
}

while ($job = $result->fetch_assoc()) {
    $job_id = $job['id'];
    $target = $job['phone_number'];
    $pesan = $job['message'];

    $new_status = 'failed';
    if (kirimWhatsApp($target, $pesan)) {
        $new_status = 'sent';
    }

    // Update status pesan di antrean
    $update_stmt = $conn->prepare("UPDATE whatsapp_queue SET status = ? WHERE id = ?");
    $update_stmt->bind_param('si', $new_status, $job_id);
    $update_stmt->execute();
    $update_stmt->close();

    sleep(1); // Tetap berikan jeda untuk keamanan
}

$stmt->close();
$conn->close();
?>