<?php
/**
 * Database-based Rate Limiter for Shared Hosting
 *
 * This implementation uses MySQL database instead of Redis
 * to be compatible with shared hosting environments.
 */

class RateLimiter {
    private $conn;
    private $max_requests;
    private $time_window; // in seconds
    private $table_name = 'rate_limit_tracker';

    /**
     * @param mysqli $conn Database connection
     * @param int $max_requests Maximum requests allowed
     * @param int $time_window Time window in seconds
     */
    public function __construct($conn, $max_requests = 10, $time_window = 60) {
        $this->conn = $conn;
        $this->max_requests = $max_requests;
        $this->time_window = $time_window;
        $this->ensureTableExists();
    }

    /**
     * Create rate limit tracking table if it doesn't exist
     */
    private function ensureTableExists() {
        $sql = "CREATE TABLE IF NOT EXISTS {$this->table_name} (
            id INT AUTO_INCREMENT PRIMARY KEY,
            ip_address VARCHAR(45) NOT NULL,
            request_count INT DEFAULT 1,
            window_start TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_request TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            INDEX idx_ip (ip_address),
            INDEX idx_window (window_start)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4";

        try {
            $this->conn->query($sql);
        } catch (mysqli_sql_exception $e) {
            error_log("RateLimiter: Failed to create table - " . $e->getMessage());
        }
    }

    /**
     * Check if request should be rate limited
     *
     * @param string $ip_address Client IP address
     * @return bool True if rate limit exceeded, False if allowed
     */
    public function isRateLimited($ip_address) {
        // Clean up old entries first (older than time window)
        $this->cleanup();

        // Get current window start time
        $window_start = date('Y-m-d H:i:s', time() - $this->time_window);

        // Check existing record
        $stmt = $this->conn->prepare(
            "SELECT id, request_count FROM {$this->table_name}
             WHERE ip_address = ? AND window_start >= ?"
        );
        $stmt->bind_param('ss', $ip_address, $window_start);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($row = $result->fetch_assoc()) {
            // Record exists - check count
            if ($row['request_count'] >= $this->max_requests) {
                $stmt->close();
                return true; // Rate limit exceeded
            }

            // Increment count
            $update_stmt = $this->conn->prepare(
                "UPDATE {$this->table_name}
                 SET request_count = request_count + 1
                 WHERE id = ?"
            );
            $update_stmt->bind_param('i', $row['id']);
            $update_stmt->execute();
            $update_stmt->close();
        } else {
            // New record
            $insert_stmt = $this->conn->prepare(
                "INSERT INTO {$this->table_name} (ip_address, request_count, window_start)
                 VALUES (?, 1, NOW())"
            );
            $insert_stmt->bind_param('s', $ip_address);
            $insert_stmt->execute();
            $insert_stmt->close();
        }

        $stmt->close();
        return false; // Not rate limited
    }

    /**
     * Get remaining requests for an IP
     *
     * @param string $ip_address Client IP address
     * @return int Number of remaining requests
     */
    public function getRemainingRequests($ip_address) {
        $window_start = date('Y-m-d H:i:s', time() - $this->time_window);

        $stmt = $this->conn->prepare(
            "SELECT request_count FROM {$this->table_name}
             WHERE ip_address = ? AND window_start >= ?"
        );
        $stmt->bind_param('ss', $ip_address, $window_start);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($row = $result->fetch_assoc()) {
            $remaining = $this->max_requests - $row['request_count'];
            $stmt->close();
            return max(0, $remaining);
        }

        $stmt->close();
        return $this->max_requests;
    }

    /**
     * Clean up old rate limit records
     */
    private function cleanup() {
        $cleanup_time = date('Y-m-d H:i:s', time() - ($this->time_window * 2));

        try {
            $stmt = $this->conn->prepare(
                "DELETE FROM {$this->table_name} WHERE window_start < ?"
            );
            $stmt->bind_param('s', $cleanup_time);
            $stmt->execute();
            $stmt->close();
        } catch (mysqli_sql_exception $e) {
            error_log("RateLimiter: Cleanup failed - " . $e->getMessage());
        }
    }

    /**
     * Reset rate limit for specific IP (admin function)
     *
     * @param string $ip_address Client IP address
     */
    public function reset($ip_address) {
        $stmt = $this->conn->prepare(
            "DELETE FROM {$this->table_name} WHERE ip_address = ?"
        );
        $stmt->bind_param('s', $ip_address);
        $stmt->execute();
        $stmt->close();
    }

    /**
     * Get stats for monitoring
     *
     * @return array Statistics about rate limiting
     */
    public function getStats() {
        $stats = [];

        // Total tracked IPs
        $result = $this->conn->query(
            "SELECT COUNT(DISTINCT ip_address) as total_ips FROM {$this->table_name}"
        );
        $stats['total_ips'] = $result->fetch_assoc()['total_ips'] ?? 0;

        // Currently rate limited IPs
        $window_start = date('Y-m-d H:i:s', time() - $this->time_window);
        $stmt = $this->conn->prepare(
            "SELECT COUNT(*) as limited_ips FROM {$this->table_name}
             WHERE request_count >= ? AND window_start >= ?"
        );
        $stmt->bind_param('is', $this->max_requests, $window_start);
        $stmt->execute();
        $result = $stmt->get_result();
        $stats['rate_limited_ips'] = $result->fetch_assoc()['limited_ips'] ?? 0;
        $stmt->close();

        return $stats;
    }
}
?>
