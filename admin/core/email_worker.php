#!/usr/bin/php
<?php
require_once __DIR__ . '/db_connect.php';
require_once __DIR__ . '/email_helper.php';

// Ambil 10 email dari antrean (bisa disesuaikan)
$limit = 10;
$stmt = $conn->prepare("SELECT * FROM email_queue WHERE status = 'pending' ORDER BY id ASC LIMIT ?");
$stmt->bind_param('i', $limit);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows === 0) exit; // Keluar jika tidak ada pekerjaan

while ($job = $result->fetch_assoc()) {
    $job_id = $job['id'];

    $berhasil = kirimEmail($job['email_address'], $job['recipient_name'], $job['subject'], $job['message']);

    $new_status = $berhasil ? 'sent' : 'failed';

    $update_stmt = $conn->prepare("UPDATE email_queue SET status = ? WHERE id = ?");
    $update_stmt->bind_param('si', $new_status, $job_id);
    $update_stmt->execute();
    $update_stmt->close();

    sleep(2); // Beri jeda 2 detik antar email untuk menjaga reputasi IP
}
$stmt->close();
$conn->close();
?>