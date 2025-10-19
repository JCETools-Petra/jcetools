<?php
// Script untuk memperbarui data geolokasi yang masih kosong di database.
// Versi ini menggunakan ipapi.co (HTTPS) sebagai sumber geolokasi.

// =====================[ AKSES KEY ]=====================
$secret_key = 'JCETools-18572184129058715'; // Ganti dengan kunci rahasia unik kamu

// (Opsional, tapi disarankan) Gunakan hash_equals agar aman dari timing attack
$provided = $_GET['cron_key'] ?? '';
if (!hash_equals($secret_key, $provided)) {
    http_response_code(403); // Forbidden
    die('Akses ditolak.');
}

// =====================[ BOOTSTRAP ]=====================
require __DIR__ . '/vendor/autoload.php';
$dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
$dotenv->load();

// Koneksi Database
$conn = new mysqli($_ENV['DB_HOST'], $_ENV['DB_USER'], $_ENV['DB_PASS'], $_ENV['DB_NAME']);
if ($conn->connect_error) {
    die("Koneksi gagal: " . $conn->connect_error);
}

echo "<h1>Memulai Proses Pembaruan Data Lokasi (ipapi.co)...</h1>";
set_time_limit(300); // 5 menit

// =====================[ HELPER ]=====================
/**
 * GET ke URL dengan timeout & header sederhana, return array JSON atau null.
 */
function http_get_json(string $url, int $timeout = 6): ?array {
    $headers = [
        'User-Agent: JCETools-GeoUpdater/1.0',
        'Accept: application/json',
    ];
    $ctx = stream_context_create([
        'http' => [
            'method'        => 'GET',
            'timeout'       => $timeout,
            'ignore_errors' => true,
            'header'        => implode("\r\n", $headers),
        ],
        // Jika hosting punya masalah sertifikat lama, bisa aktifkan ini sementara (TIDAK disarankan):
        // 'ssl'  => [ 'verify_peer' => true, 'verify_peer_name' => true ],
    ]);
    $raw = @file_get_contents($url, false, $ctx);
    if ($raw === false) return null;
    $data = json_decode($raw, true);
    return is_array($data) ? $data : null;
}

/**
 * Lookup ke ipapi.co dan mapping ke skema DB kamu.
 * Return:
 *  ['ok'=>true,  'country'=>..., 'region'=>..., 'city'=>..., 'lat'=>..., 'lon'=>..., 'isp'=>...]
 *  ['ok'=>false, 'error'=>'...']
 */
function lookup_ipapi(string $ip): array {
    // ipapi.co, tanpa API key untuk basic; rate limit ~1000/hari
    // Docs: https://ipapi.co/{ip}/json/
    $url = "https://ipapi.co/{$ip}/json/";
    $d = http_get_json($url, 8);
    if (!$d) {
        return ['ok'=>false, 'error'=>'no_response'];
    }

    // Jika error (mis. private IP, rate limit, dll)
    if (!empty($d['error'])) {
        // ipapi.co sering mengirim 'reason' dan/atau 'message'
        $msg = $d['reason'] ?? ($d['message'] ?? 'lookup_failed');
        return ['ok'=>false, 'error'=> (string)$msg ];
    }

    // Mapping field
    $country = $d['country_name'] ?? ($d['country'] ?? null); // prefer nama negara
    $region  = $d['region'] ?? null;
    $city    = $d['city'] ?? null;
    $lat     = $d['latitude'] ?? null;
    $lon     = $d['longitude'] ?? null;
    $isp     = $d['org'] ?? ($d['asn'] ?? null); // org sering = ISP/Org

    // Minimal harus ada country / lat lon / city untuk dianggap sukses
    if ($country === null && $lat === null && $lon === null && $city === null && $region === null) {
        return ['ok'=>false, 'error'=>'empty_payload'];
    }

    return ['ok'=>true, 'country'=>$country, 'region'=>$region, 'city'=>$city, 'lat'=>$lat, 'lon'=>$lon, 'isp'=>$isp];
}

// =====================[ QUERY PREPARE ]=====================
// Ambil baris yang country masih NULL (batasi 20 per eksekusi)
$stmt_select = $conn->prepare("SELECT id, ip_address FROM visitor_logs WHERE country IS NULL LIMIT 20");
$stmt_select->execute();
$result = $stmt_select->get_result();

if ($result->num_rows === 0) {
    echo "Tidak ada data lokasi baru yang perlu diperbarui. Semua sudah lengkap.";
    // cleanup
    $stmt_select->close();
    $conn->close();
    exit();
}

// Statement UPDATE saat berhasil (semua kolom diisi normal)
$stmt_update_ok = $conn->prepare(
    "UPDATE visitor_logs SET 
        country = ?, 
        region_name = ?, 
        city = ?, 
        isp = ?, 
        latitude = ?, 
        longitude = ? 
     WHERE id = ?"
);

// Statement UPDATE saat gagal (hindari isi 0 pada kolom double)
$stmt_update_err = $conn->prepare(
    "UPDATE visitor_logs SET 
        country = ?, 
        region_name = NULL, 
        city = NULL, 
        isp = NULL, 
        latitude = NULL, 
        longitude = NULL
     WHERE id = ?"
);

// =====================[ LOOP PROSES ]=====================
while ($row = $result->fetch_assoc()) {
    $id = (int)$row['id'];
    $ip = trim((string)$row['ip_address']);

    echo "<p>Memproses ID: {$id} - IP: {$ip} ... ";

    // Validasi basic IP
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        $err = 'invalid_ip';
        $stmt_update_err->bind_param('si', $err, $id);
        $stmt_update_err->execute();
        echo "<span style='color:red;'>GAGAL: {$err}.</span></p>";
        continue;
    }

    // Panggil ipapi
    $geo = lookup_ipapi($ip);

    if ($geo['ok']) {
        $country = $geo['country'];
        $region  = $geo['region'];
        $city    = $geo['city'];
        $isp     = $geo['isp'];
        $lat     = $geo['lat'];
        $lon     = $geo['lon'];

        // Bind & execute
        // Tipe: s s s s d d i
        $stmt_update_ok->bind_param('ssssddi', $country, $region, $city, $isp, $lat, $lon, $id);
        $stmt_update_ok->execute();

        echo "<span style='color:green;'>BERHASIL diperbarui (ipapi.co).</span></p>";
    } else {
        // Tandai country dengan pesan error agar tidak diproses berulang
        $err = (string)($geo['error'] ?? 'lookup_failed');
        $stmt_update_err->bind_param('si', $err, $id);
        $stmt_update_err->execute();

        echo "<span style='color:red;'>GAGAL: {$err}.</span></p>";
    }

    // Jeda kecil agar tidak membanjiri layanan
    usleep(300000); // 0.3 detik (lebih ramah dari 1 detik tapi bisa diubah)
}

// =====================[ CLEANUP ]=====================
$stmt_select->close();
$stmt_update_ok->close();
$stmt_update_err->close();
$conn->close();

echo "<h2>Proses Selesai.</h2>";
