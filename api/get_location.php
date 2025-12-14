<?php
// Set header agar outputnya berupa JSON
header('Content-Type: application/json');

// Ambil parameter 'ip' dari URL, pastikan valid
$ip_address = $_GET['ip'] ?? null;

// Validasi alamat IP
if (!filter_var($ip_address, FILTER_VALIDATE_IP)) {
    // Jika IP tidak valid, kirim pesan error
    http_response_code(400); // Bad Request
    echo json_encode(['success' => false, 'message' => 'Alamat IP tidak valid.']);
    exit();
}

// URL API dari layanan pihak ketiga (ip-api.com, gratis untuk penggunaan non-komersial)
// Dokumentasi: https://ip-api.com/docs/api:json
$api_url = "http://ip-api.com/json/{$ip_address}?fields=status,message,country,regionName,city,lat,lon,isp";

// Ambil data dari API menggunakan file_get_contents (cara mudah)
// Catatan: Pastikan 'allow_url_fopen' diaktifkan di php.ini Anda.
// Jika tidak, gunakan cURL sebagai alternatif yang lebih baik.
$response = @file_get_contents($api_url);

if ($response === false) {
    // Jika gagal menghubungi API
    http_response_code(502); // Bad Gateway
    echo json_encode(['success' => false, 'message' => 'Gagal menghubungi layanan geolokasi.']);
    exit();
}

// Decode response JSON
$data = json_decode($response, true);

// Cek apakah API eksternal memberikan status sukses
if ($data && $data['status'] === 'success') {
    // Jika sukses, kita ubah formatnya sedikit agar lebih rapi
    $output = [
        'success'     => true,
        'ip'          => $ip_address,
        'country'     => $data['country'] ?? null,
        'region_name' => $data['regionName'] ?? null,
        'city'        => $data['city'] ?? null,
        'isp'         => $data['isp'] ?? null,
        'latitude'    => $data['lat'] ?? null,
        'longitude'   => $data['lon'] ?? null,
    ];
    echo json_encode($output);
} else {
    // Jika API eksternal gagal menemukan info IP
    http_response_code(404); // Not Found
    $error_message = $data['message'] ?? 'Informasi lokasi tidak ditemukan untuk IP ini.';
    echo json_encode(['success' => false, 'message' => $error_message]);
}