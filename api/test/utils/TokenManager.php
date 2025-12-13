<?php
/**
 * JWT Token Manager for Shared Hosting
 *
 * Simple JWT implementation without requiring external dependencies
 * Compatible with shared hosting environments
 */

class TokenManager {
    private $secret_key;
    private $algorithm = 'HS256';
    private $token_lifetime = 300; // 5 minutes

    /**
     * @param string $secret_key Secret key for signing tokens
     * @param int $token_lifetime Token lifetime in seconds (default: 300s = 5min)
     */
    public function __construct($secret_key, $token_lifetime = 300) {
        $this->secret_key = $secret_key;
        $this->token_lifetime = $token_lifetime;
    }

    /**
     * Generate a JWT token
     *
     * @param array $payload Data to include in token
     * @return string JWT token
     */
    public function generateToken($payload) {
        $header = [
            'typ' => 'JWT',
            'alg' => $this->algorithm
        ];

        // Add standard claims
        $payload['iat'] = time(); // Issued at
        $payload['exp'] = time() + $this->token_lifetime; // Expiration
        $payload['jti'] = $this->generateJti(); // JWT ID (unique)

        // Encode header and payload
        $headerEncoded = $this->base64UrlEncode(json_encode($header));
        $payloadEncoded = $this->base64UrlEncode(json_encode($payload));

        // Create signature
        $signature = $this->sign($headerEncoded . '.' . $payloadEncoded);
        $signatureEncoded = $this->base64UrlEncode($signature);

        // Return complete JWT
        return $headerEncoded . '.' . $payloadEncoded . '.' . $signatureEncoded;
    }

    /**
     * Verify and decode a JWT token
     *
     * @param string $token JWT token to verify
     * @return array|false Decoded payload or false if invalid
     */
    public function verifyToken($token) {
        $parts = explode('.', $token);

        if (count($parts) !== 3) {
            return false; // Invalid token format
        }

        list($headerEncoded, $payloadEncoded, $signatureEncoded) = $parts;

        // Verify signature
        $signature = $this->base64UrlDecode($signatureEncoded);
        $expectedSignature = $this->sign($headerEncoded . '.' . $payloadEncoded);

        if (!hash_equals($expectedSignature, $signature)) {
            return false; // Signature verification failed
        }

        // Decode payload
        $payload = json_decode($this->base64UrlDecode($payloadEncoded), true);

        if (!$payload) {
            return false; // Invalid payload
        }

        // Check expiration
        if (isset($payload['exp']) && $payload['exp'] < time()) {
            return false; // Token expired
        }

        // Check not before (if set)
        if (isset($payload['nbf']) && $payload['nbf'] > time()) {
            return false; // Token not yet valid
        }

        return $payload;
    }

    /**
     * Create HMAC signature
     *
     * @param string $data Data to sign
     * @return string Signature
     */
    private function sign($data) {
        return hash_hmac('sha256', $data, $this->secret_key, true);
    }

    /**
     * Base64 URL encode
     *
     * @param string $data Data to encode
     * @return string Encoded data
     */
    private function base64UrlEncode($data) {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * Base64 URL decode
     *
     * @param string $data Data to decode
     * @return string Decoded data
     */
    private function base64UrlDecode($data) {
        return base64_decode(strtr($data, '-_', '+/'));
    }

    /**
     * Generate unique JWT ID
     *
     * @return string Unique identifier
     */
    private function generateJti() {
        return bin2hex(random_bytes(16));
    }

    /**
     * Refresh a token (extend expiration)
     *
     * @param string $token Existing valid token
     * @return string|false New token or false if invalid
     */
    public function refreshToken($token) {
        $payload = $this->verifyToken($token);

        if ($payload === false) {
            return false;
        }

        // Remove old timestamps
        unset($payload['iat']);
        unset($payload['exp']);
        unset($payload['jti']);

        // Generate new token with same payload
        return $this->generateToken($payload);
    }

    /**
     * Extract token from Authorization header
     *
     * @param string $authHeader Authorization header value
     * @return string|false Token or false if not found
     */
    public static function extractFromHeader($authHeader) {
        if (empty($authHeader)) {
            return false;
        }

        // Support both "Bearer TOKEN" and just "TOKEN"
        if (preg_match('/Bearer\s+(.*)$/i', $authHeader, $matches)) {
            return $matches[1];
        }

        return $authHeader;
    }

    /**
     * Get token expiration time
     *
     * @param string $token JWT token
     * @return int|false Unix timestamp or false if invalid
     */
    public function getExpiration($token) {
        $payload = $this->verifyToken($token);

        if ($payload === false) {
            return false;
        }

        return $payload['exp'] ?? false;
    }

    /**
     * Check if token is expired
     *
     * @param string $token JWT token
     * @return bool True if expired, false otherwise
     */
    public function isExpired($token) {
        $exp = $this->getExpiration($token);

        if ($exp === false) {
            return true; // Invalid token = considered expired
        }

        return $exp < time();
    }
}
?>
