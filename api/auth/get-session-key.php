<?php
/**
 * Session Key Generator API
 *
 * Generates temporary encryption keys for dynamic HWID encryption
 * This replaces hardcoded AES keys in the client
 *
 * Flow:
 * 1. Client requests session key
 * 2. Server generates random key + IV with expiration
 * 3. Client uses this key to encrypt HWID
 * 4. Server validates using same session
 */

header("Content-Type: application/json");
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");

require_once __DIR__ . '/../../vendor/autoload.php';
require_once __DIR__ . '/../utils/TokenManager.php';
require_once __DIR__ . '/../utils/RateLimiter.php';

// Load environment
try {
    $dotenv = Dotenv\Dotenv::createImmutable(__DIR__ . '/../..');
    $dotenv->load();
} catch (Exception $e) {
    http_response_code(500);
    die(json_encode(["error" => "Server configuration error"]));
}

// Configuration
$config = [
    'db_host' => $_ENV['DB_HOST'] ?? '127.0.0.1',
    'db_user' => $_ENV['DB_USER'],
    'db_pass' => $_ENV['DB_PASS'],
    'db_name' => $_ENV['DB_NAME'],
    'jwt_secret' => $_ENV['JWT_SECRET'] ?? $_ENV['API_KEY'],
];

// Database connection
try {
    $conn = new mysqli($config['db_host'], $config['db_user'], $config['db_pass'], $config['db_name']);
    $conn->set_charset("utf8mb4");
} catch (mysqli_sql_exception $e) {
    http_response_code(500);
    die(json_encode(["error" => "Database connection error"]));
}

// Rate limiting
$rateLimiter = new RateLimiter($conn, 20, 60); // 20 requests per minute
$clientIp = $_SERVER['REMOTE_ADDR'] ?? 'unknown';

if ($rateLimiter->isRateLimited($clientIp)) {
    http_response_code(429);
    die(json_encode([
        "error" => "Too many requests",
        "retry_after" => 60
    ]));
}

// Generate session key and IV
$session_key = bin2hex(random_bytes(32)); // 256-bit key
$session_iv = bin2hex(random_bytes(16));  // 128-bit IV
$session_id = bin2hex(random_bytes(16));  // Unique session ID

// Create JWT token containing session info
$tokenManager = new TokenManager($config['jwt_secret'], 300); // 5 minute lifetime

$payload = [
    'session_id' => $session_id,
    'key' => $session_key,
    'iv' => $session_iv,
    'ip' => $clientIp,
    'purpose' => 'hwid_encryption'
];

$token = $tokenManager->generateToken($payload);

// Store session in database for validation
$stmt = null;
try {
    $stmt = $conn->prepare(
        "INSERT INTO session_keys (session_id, session_key, session_iv, client_ip, expires_at)
         VALUES (?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL 5 MINUTE))
         ON DUPLICATE KEY UPDATE
            session_key = VALUES(session_key),
            session_iv = VALUES(session_iv),
            expires_at = VALUES(expires_at)"
    );
} catch (mysqli_sql_exception $e) {
    // Table doesn't exist, create it
    $createTable = "CREATE TABLE IF NOT EXISTS session_keys (
        id INT AUTO_INCREMENT PRIMARY KEY,
        session_id VARCHAR(64) UNIQUE NOT NULL,
        session_key VARCHAR(128) NOT NULL,
        session_iv VARCHAR(64) NOT NULL,
        client_ip VARCHAR(45) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP NOT NULL,
        INDEX idx_session_id (session_id),
        INDEX idx_expires (expires_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci";

    if (!$conn->query($createTable)) {
        http_response_code(500);
        die(json_encode(["error" => "Failed to create session_keys table"]));
    }

    // Retry insert
    $stmt = $conn->prepare(
        "INSERT INTO session_keys (session_id, session_key, session_iv, client_ip, expires_at)
         VALUES (?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL 5 MINUTE))"
    );
}

$stmt->bind_param('ssss', $session_id, $session_key, $session_iv, $clientIp);
$stmt->execute();
$stmt->close();

// Clean up expired sessions
$conn->query("DELETE FROM session_keys WHERE expires_at < NOW()");

$conn->close();

// Return response
echo json_encode([
    "status" => "success",
    "session_token" => $token,
    "expires_in" => 300, // seconds
    "message" => "Session key generated successfully"
]);
?>
