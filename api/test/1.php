<?php
/**
 * JCE Tools - Secured HWID Validation API
 * Version: 2.0 (Security Enhanced)
 *
 * Security Features:
 * - JWT Token authentication (replaces API key in client)
 * - Database-based rate limiting
 * - Session-based encryption validation
 * - Minimal information disclosure
 * - Security headers
 * - Comprehensive logging outside webroot
 */

ob_start();

// Security Headers
header("Content-Type: application/json");
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");
header("Referrer-Policy: no-referrer");

// Load dependencies
require_once __DIR__ . '/../../vendor/autoload.php';
require_once __DIR__ . '/utils/RateLimiter.php';
require_once __DIR__ . '/utils/TokenManager.php';

// Load environment variables
try {
    $dotenv = Dotenv\Dotenv::createImmutable(__DIR__ . '/../..');
    $dotenv->load();
} catch (Exception $e) {
    http_response_code(500);
    die(json_encode(["status" => "error", "message" => "Server configuration error."]));
}

// Configuration
$config = [
    'db_host' => $_ENV['DB_HOST'] ?? '127.0.0.1',
    'db_user' => $_ENV['DB_USER'],
    'db_pass' => $_ENV['DB_PASS'],
    'db_name' => $_ENV['DB_NAME'],
    'jwt_secret' => $_ENV['JWT_SECRET'] ?? $_ENV['API_KEY'],
    'log_dir' => $_ENV['LOG_DIR'] ?? '/var/log/jcetools', // Outside webroot!
];

// Logging function - IMPROVED (outside webroot)
function log_message(string $level, string $message) {
    global $config;

    // Ensure log directory exists and is secure
    if (!is_dir($config['log_dir'])) {
        @mkdir($config['log_dir'], 0750, true);
    }

    $logFile = $config['log_dir'] . '/' . $level . '.log';
    $clientIp = $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN';
    $formattedMessage = date('[Y-m-d H:i:s]') . " | IP: $clientIp | " . $message . PHP_EOL;

    // Fallback to local directory if log_dir not writable
    if (!is_writable($config['log_dir'])) {
        $logFile = __DIR__ . '/../logs/' . $level . '.log';
        @mkdir(__DIR__ . '/../logs/', 0750, true);
    }

    @file_put_contents($logFile, $formattedMessage, FILE_APPEND | LOCK_EX);
}

// Database connection
mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
try {
    $conn = new mysqli($config['db_host'], $config['db_user'], $config['db_pass'], $config['db_name']);
    $conn->set_charset("utf8mb4");
} catch (mysqli_sql_exception $e) {
    log_message('error', 'Database connection failed: ' . $e->getMessage());
    http_response_code(500);
    die(json_encode(["status" => "error", "message" => "Service temporarily unavailable."]));
}

// Rate Limiting - IMPROVED (10 requests per minute per IP)
$rateLimiter = new RateLimiter($conn, 10, 60);
$clientIp = $_SERVER['REMOTE_ADDR'] ?? 'unknown';

if ($rateLimiter->isRateLimited($clientIp)) {
    log_message('intruder', "Rate limit exceeded from IP: $clientIp");
    http_response_code(429);
    $conn->close();
    die(json_encode([
        "status" => "error",
        "message" => "Too many requests. Please try again later.",
        "retry_after" => 60
    ]));
}

// Token Authentication - NEW (replaces API key)
$authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['HTTP_X_SESSION_TOKEN'] ?? '';
$sessionToken = TokenManager::extractFromHeader($authHeader);

if (empty($sessionToken)) {
    log_message('intruder', "Missing session token from IP: $clientIp");
    http_response_code(401);
    $conn->close();
    die(json_encode(["status" => "error", "message" => "Authentication required."]));
}

// Verify JWT token
$tokenManager = new TokenManager($config['jwt_secret']);
$tokenPayload = $tokenManager->verifyToken($sessionToken);

if ($tokenPayload === false) {
    log_message('intruder', "Invalid or expired token from IP: $clientIp");
    http_response_code(401);
    $conn->close();
    die(json_encode(["status" => "error", "message" => "Invalid or expired session."]));
}

// Verify session exists in database
$sessionId = $tokenPayload['session_id'] ?? '';
try {
    $stmt = $conn->prepare(
        "SELECT session_key, session_iv FROM session_keys
         WHERE session_id = ? AND expires_at > NOW() AND client_ip = ?"
    );
    $stmt->bind_param('ss', $sessionId, $clientIp);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows === 0) {
        log_message('intruder', "Session not found or expired: $sessionId from IP: $clientIp");
        http_response_code(401);
        $stmt->close();
        $conn->close();
        die(json_encode(["status" => "error", "message" => "Session expired. Please request new session."]));
    }

    $session = $result->fetch_assoc();
    $stmt->close();
} catch (mysqli_sql_exception $e) {
    log_message('error', "Session validation failed (table may not exist): " . $e->getMessage());
    http_response_code(500);
    $conn->close();
    die(json_encode(["status" => "error", "message" => "Session validation error. Please request a new session from /api/auth/get-session-key.php"]));
}

// Process HWID input
$input = file_get_contents("php://input");
$data = json_decode($input, true);

if (!isset($data["hwid"]) || !is_string($data["hwid"]) || empty($data["hwid"])) {
    log_message('error', 'Invalid HWID format in request from IP: ' . $clientIp);
    http_response_code(400);
    $conn->close();
    die(json_encode(["status" => "error", "message" => "Invalid request format."]));
}

$hwid = $data["hwid"];

// Validate HWID format (basic sanity check)
if (!preg_match('/^[a-f0-9]+$/i', $hwid) || strlen($hwid) > 512) {
    log_message('intruder', "Suspicious HWID format from IP: $clientIp - HWID length: " . strlen($hwid));
    http_response_code(400);
    $conn->close();
    die(json_encode(["status" => "error", "message" => "Invalid data format."]));
}

// Query database for HWID
try {
    $stmt = $conn->prepare("SELECT Nama, expiry_date FROM user_jce WHERE hwid_encrypted = ?");
    $stmt->bind_param('s', $hwid);
    $stmt->execute();
    $result = $stmt->get_result();
    $response = [];

    if ($result->num_rows > 0) {
        $row = $result->fetch_assoc();
        $expiry_date = strtotime($row["expiry_date"]);

        if (time() > $expiry_date) {
            // Expired license
            log_message('access', "Expired license attempt - User: {$row['Nama']} - IP: $clientIp");
            $response = [
                "status" => "error",
                "message" => "License expired.",
                "code" => "EXPIRED"
            ];
        } else {
            // Valid license
            log_message('success', "Valid access - User: {$row['Nama']} - Expires: {$row['expiry_date']} - IP: $clientIp");

            // Update last login and counter
            $updateStmt = $conn->prepare(
                "UPDATE user_jce SET counter = counter + 1, last_login = NOW()
                 WHERE hwid_encrypted = ?"
            );
            $updateStmt->bind_param('s', $hwid);
            $updateStmt->execute();
            $updateStmt->close();

            // Calculate days remaining
            $daysRemaining = floor(($expiry_date - time()) / 86400);

            $response = [
                "status" => "success",
                "message" => "Access granted",
                "expiry_date" => $row["expiry_date"],
                "days_remaining" => $daysRemaining,
                "user" => $row["Nama"]
            ];
        }
    } else {
        // HWID not found
        log_message('intruder', "Unknown HWID attempt from IP: $clientIp");
        $response = [
            "status" => "error",
            "message" => "Access denied.",
            "code" => "NOT_FOUND"
        ];
    }

    $stmt->close();
} catch (mysqli_sql_exception $e) {
    log_message('error', 'Database query failed: ' . $e->getMessage());
    http_response_code(500);
    $response = ["status" => "error", "message" => "Service error."];
}

// Close database connection
$conn->close();

// Send response
echo json_encode($response);

ob_end_flush();
?>
