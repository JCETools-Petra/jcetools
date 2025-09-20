<?php
header("Content-Type: application/json");
require_once __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/crypto_helper.php'; // Memuat helper enkripsi

try {
    $dotenv = Dotenv\Dotenv::createImmutable(__DIR__ . '/..');
    $dotenv->load();
} catch (Exception $e) {
    // Jangan tampilkan detail error ke publik, cukup log
    error_log("Gagal memuat file .env: " . $e->getMessage());
    http_response_code(500);
    // Kita tidak bisa mengenkripsi respons jika kunci tidak ada, jadi kirim plain text
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
$username = $input['username'] ?? '';
$password = $input['password'] ?? '';

if (empty($username) || empty($password)) {
    http_response_code(400);
    echo encrypt_payload(json_encode(["status" => "error", "message" => "Username and password are required."]), $secret_key);
    exit();
}

$stmt = $conn->prepare("SELECT password, expiry_date FROM licensed_users WHERE username = ?");
$stmt->bind_param('s', $username);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows === 0) {
    echo encrypt_payload(json_encode(["status" => "error", "message" => "Invalid username or password."]), $secret_key);
    exit();
}

$user = $result->fetch_assoc();
$stmt->close();

if (!password_verify($password, $user['password'])) {
    echo encrypt_payload(json_encode(["status" => "error", "message" => "Invalid username or password."]), $secret_key);
    exit();
}

if (strtotime($user['expiry_date']) < time()) {
    echo encrypt_payload(json_encode(["status" => "error", "message" => "Your license has expired."]), $secret_key);
    exit();
}

// Jika semua valid, buat session token dan challenge baru
$session_token = bin2hex(random_bytes(32)); // "Tiket" unik untuk sesi ini
$challenge_code = bin2hex(random_bytes(16)); // "Pertanyaan" acak

// Simpan token baru ini ke database untuk user tersebut (menimpa token lama)
$update_stmt = $conn->prepare("UPDATE licensed_users SET session_token = ?, last_login = NOW() WHERE username = ?");
$update_stmt->bind_param('ss', $session_token, $username);
$update_stmt->execute();
$update_stmt->close();

// Siapkan respons untuk dikirim kembali
$response_data = [
    "status" => "success",
    "message" => "Login successful.",
    "session_token" => $session_token,
    "expiry_date" => $user['expiry_date'],
    "challenge" => $challenge_code // Kirim "pertanyaan" ke klien
];

// Enkripsi respons sebelum mengirim
echo encrypt_payload(json_encode($response_data), $secret_key);

$conn->close();