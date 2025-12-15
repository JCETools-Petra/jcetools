<?php
/**
 * JCE Tools - Secured HWID Validation API
 * Version: 2.4 (Log Location Fix)
 * Changelog:
 * - Fixed: Log directory moved to inside /api/ folder to fix Permission Denied errors
 * - Added: Default Timezone Asia/Jakarta
 */

ob_start();

// Set Timezone agar log sesuai jam WIB
date_default_timezone_set('Asia/Jakarta');

// Security Headers
header("Content-Type: application/json");
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");
header("Referrer-Policy: no-referrer");

// Load dependencies
require_once __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/utils/RateLimiter.php';
require_once __DIR__ . '/utils/TokenManager.php';

// Load environment variables
try {
    $dotenv = Dotenv\Dotenv::createImmutable(__DIR__ . '/..');
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
    // [FIX] Memaksa log disimpan di dalam folder api/logs agar tidak kena permission error
    'log_dir' => __DIR__ . '/logs', 
];

// Logging function
function log_message(string $level, string $message) {
    global $config;
    
    // Pastikan direktori log ada (Auto Create)
    if (!is_dir($config['log_dir'])) {
        // Mode 0755 atau 0777 tergantung konfigurasi server hosting
        @mkdir($config['log_dir'], 0755, true); 
        
        // Buat .htaccess agar log tidak bisa dibaca publik (Security)
        if (!file_exists($config['log_dir'] . '/.htaccess')) {
            @file_put_contents($config['log_dir'] . '/.htaccess', "Order allow,deny\nDeny from all");
        }
    }

    $logFile = $config['log_dir'] . '/' . $level . '.log';
    $clientIp = $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN';
    
    $formattedMessage = date('[Y-m-d H:i:s]') . " | IP: $clientIp | " . $message . PHP_EOL;
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

// Rate Limiting
$rateLimiter = new RateLimiter($conn, 10, 60);
$clientIp = $_SERVER['REMOTE_ADDR'] ?? 'unknown';

if ($rateLimiter->isRateLimited($clientIp)) {
    http_response_code(429);
    $conn->close();
    die(json_encode(["status" => "error", "message" => "Too many requests.", "retry_after" => 60]));
}

// Token Authentication
$authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['HTTP_X_SESSION_TOKEN'] ?? '';
$sessionToken = TokenManager::extractFromHeader($authHeader);

if (empty($sessionToken)) {
    http_response_code(401);
    $conn->close();
    die(json_encode(["status" => "error", "message" => "Authentication required."]));
}

// Verify JWT token
$tokenManager = new TokenManager($config['jwt_secret']);
$tokenPayload = $tokenManager->verifyToken($sessionToken);

if ($tokenPayload === false) {
    http_response_code(401);
    $conn->close();
    die(json_encode(["status" => "error", "message" => "Invalid or expired session."]));
}

// Verify session exists in database and get KEYS
$sessionId = $tokenPayload['session_id'] ?? '';
$session = [];

try {
    $stmt = $conn->prepare(
        "SELECT session_key, session_iv FROM session_keys
         WHERE session_id = ? AND expires_at > NOW() AND client_ip = ?"
    );
    $stmt->bind_param('ss', $sessionId, $clientIp);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows === 0) {
        $stmt->close();
        $conn->close();
        die(json_encode(["status" => "error", "message" => "Session expired."]));
    }

    $session = $result->fetch_assoc();
    $stmt->close();
} catch (mysqli_sql_exception $e) {
    $conn->close();
    die(json_encode(["status" => "error", "message" => "Session validation error."]));
}

// Process HWID input
$input = file_get_contents("php://input");
$data = json_decode($input, true);

if (!isset($data["hwid"]) || !is_string($data["hwid"])) {
    http_response_code(400);
    $conn->close();
    die(json_encode(["status" => "error", "message" => "Invalid request format."]));
}

$encryptedHwidHex = $data["hwid"];

// === [DEKRIPSI HWID] ===
$decryptedHwid = false;

try {
    // Kunci dari database masih format hex string, konversi ke binary
    $keyBin = hex2bin($session['session_key']);
    $ivBin = hex2bin($session['session_iv']);
    
    // Data dari client (C#) dikirim dalam format Hex String, konversi ke binary
    $ciphertextBin = hex2bin($encryptedHwidHex);
    
    if ($ciphertextBin !== false && $keyBin !== false && $ivBin !== false) {
        $decryptedHwid = openssl_decrypt(
            $ciphertextBin, 
            'aes-256-cbc', 
            $keyBin, 
            OPENSSL_RAW_DATA, 
            $ivBin
        );
    }
} catch (Exception $e) {
    log_message('error', "Decryption failed details: " . $e->getMessage());
}

if ($decryptedHwid === false) {
    log_message('intruder', "Gagal mendekripsi HWID dari IP: $clientIp. Kemungkinan serangan Replay atau Key Mismatch.");
    $conn->close();
    die(json_encode(["status" => "error", "message" => "Security verification failed."]));
}

// Pastikan HWID bersih (hanya angka/huruf dari VolumeSerial)
$finalHwid = preg_replace('/[^a-zA-Z0-9]/', '', $decryptedHwid);

// === [HASHING SHA-256] ===
// Kita hash HWID asli menjadi SHA-256 untuk dicocokkan dengan database
$hwidHash = hash('sha256', $finalHwid);

// === [QUERY DATABASE] ===
try {
    // Mengambil Nama, Expiry, dan KUNCI PENTING (sk, sck) untuk Updater
    $stmt = $conn->prepare("SELECT Nama, expiry_date, sk, sck, maintenance, status1_text FROM user_jce WHERE hwid_encrypted = ?");
    
    $stmt->bind_param('s', $hwidHash); 
    $stmt->execute();
    $result = $stmt->get_result();
    $response = [];

    if ($result->num_rows > 0) {
        $row = $result->fetch_assoc();
        $expiry_date = strtotime($row["expiry_date"]);

        if (time() > $expiry_date) {
            log_message('access', "Expired license - User: {$row['Nama']}");
            $response = ["status" => "error", "message" => "License expired.", "code" => "EXPIRED"];
        } else {
            log_message('success', "Access granted - User: {$row['Nama']}");
            
            // Update last login
            $updateStmt = $conn->prepare("UPDATE user_jce SET counter = counter + 1, last_login = NOW() WHERE hwid_encrypted = ?");
            $updateStmt->bind_param('s', $hwidHash);
            $updateStmt->execute();
            $updateStmt->close();

            $daysRemaining = floor(($expiry_date - time()) / 86400);
            
            // Response Lengkap untuk C# Client
            $response = [
                "status" => "success", 
                "message" => "Access granted",
                "expiry_date" => $row["expiry_date"],
                "days_remaining" => $daysRemaining,
                "user" => $row["Nama"],
                "sk" => $row["sk"],              
                "sck" => $row["sck"],            
                "maintenance" => $row["maintenance"] ?? "no", 
                "status1_text" => $row["status1_text"] ?? ""
            ];
        }
    } else {
        log_message('intruder', "Hash not found. HWID Asli: [$finalHwid]");
        $response = ["status" => "error", "message" => "Access denied (HWID Not Found).", "code" => "NOT_FOUND"];
    }
    $stmt->close();
} catch (mysqli_sql_exception $e) {
    log_message('error', 'Query Error: ' . $e->getMessage());
    http_response_code(500);
    $response = ["status" => "error", "message" => "Database error."];
}

$conn->close();
echo json_encode($response);
ob_end_flush();
?>