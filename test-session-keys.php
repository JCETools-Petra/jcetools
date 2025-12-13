<?php
/**
 * Test script untuk mengecek session_keys table dan endpoint
 */

// Load environment from .env file manually
if (file_exists(__DIR__ . '/.env')) {
    $lines = file(__DIR__ . '/.env', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($lines as $line) {
        if (strpos($line, '#') === 0 || strpos($line, '=') === false) continue;
        list($key, $value) = explode('=', $line, 2);
        $_ENV[trim($key)] = trim($value);
    }
}

// Database connection
$conn = new mysqli(
    $_ENV['DB_HOST'] ?? '127.0.0.1',
    $_ENV['DB_USER'] ?? 'root',
    $_ENV['DB_PASS'] ?? '',
    $_ENV['DB_NAME'] ?? 'jce-data'
);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error . "\n");
}

echo "=== JCE Tools - Session Keys Table Test ===\n\n";

// Check if session_keys table exists
$result = $conn->query("SHOW TABLES LIKE 'session_keys'");
if ($result->num_rows > 0) {
    echo "✓ Table 'session_keys' EXISTS\n\n";

    // Show table structure
    echo "Table structure:\n";
    $structure = $conn->query("DESCRIBE session_keys");
    while ($row = $structure->fetch_assoc()) {
        echo "  - {$row['Field']} ({$row['Type']})\n";
    }
    echo "\n";

    // Count records
    $count = $conn->query("SELECT COUNT(*) as total FROM session_keys")->fetch_assoc();
    echo "Total records: {$count['total']}\n";

    // Show recent sessions
    if ($count['total'] > 0) {
        echo "\nRecent sessions:\n";
        $sessions = $conn->query("SELECT session_id, client_ip, created_at, expires_at FROM session_keys ORDER BY created_at DESC LIMIT 5");
        while ($row = $sessions->fetch_assoc()) {
            $status = strtotime($row['expires_at']) > time() ? 'ACTIVE' : 'EXPIRED';
            echo "  - {$row['session_id']} | IP: {$row['client_ip']} | Status: $status\n";
        }
    }
} else {
    echo "✗ Table 'session_keys' DOES NOT EXIST\n";
    echo "\nTo create the table, run:\n";
    echo "1. Via phpMyAdmin: Execute database/migrations/add_session_keys_table.sql\n";
    echo "2. OR call /api/auth/get-session-key.php once (auto-create)\n";
}

$conn->close();

echo "\n=== Test Complete ===\n";
?>
