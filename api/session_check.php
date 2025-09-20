<?php
header("Content-Type: application/json");
require_once __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/crypto_helper.php'; // Memuat helper enkripsi

try {
    $dotenv = Dotenv\Dotenv::createImmutable(__DIR__ . '/..');
    $dotenv->load();
} catch (Exception $e) {
    error_log("Gagal memuat file .env: " . $e->getMessage());
    http_response_code(500);
    echo json_encode(["status" => "error", "message" => "Server configuration error."]);
    exit();
}

$secret_key = $_ENV['PAYLOAD_SECRET_KEY'];
$conn = new mysqli($_ENV['DB_HOST'], $_ENV['DB_USER'], $_ENV['DB_PASS'], $_ENV['DB_NAME']);

if ($conn->connect_error) {
    error_log("Koneksi Database Gagal: " . $conn->connect_error);
    http_response_code(500);
    echo encrypt_payload(json_encode(["status" => "error", "message" => "Server database error."]), $secret_key);
    exit();
}

$encrypted_input = file_get_contents("php://input");
$decrypted_json = decrypt_payload($encrypted_input, $secret_key);

if ($decrypted_json === false) {
    http_response_code(400);
    echo encrypt_payload(json_encode(["status" => "error", "message" => "Invalid payload."]), $secret_key);
    exit();
}

$input = json_decode($decrypted_json, true);
$session_token = $input['session_token'] ?? '';
// Untuk saat ini, kita belum memvalidasi challenge response di sisi server
// $challenge_response = $input['response'] ?? ''; 

if (empty($session_token)) {
    http_response_code(400);
    echo encrypt_payload(json_encode(["status" => "error", "message" => "Session token is required."]), $secret_key);
    exit();
}

$stmt = $conn->prepare("SELECT expiry_date FROM licensed_users WHERE session_token = ?");
$stmt->bind_param('s', $session_token);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows > 0) {
    $user = $result->fetch_assoc();
    if (strtotime($user['expiry_date']) < time()) {
        $response_data = ["status" => "error", "message" => "License has expired."];
    } else {
        $response_data = ["status" => "success", "message" => "Session is valid."];
    }
} else {
    // Token tidak ditemukan. Ini berarti sesi sudah tidak valid, kemungkinan karena login dari perangkat lain.
    $response_data = ["status" => "error", "message" => "Invalid session. Another device may have logged in."];
}
$stmt->close();

// Enkripsi respons sebelum mengirim
echo encrypt_payload(json_encode($response_data), $secret_key);

$conn->close();