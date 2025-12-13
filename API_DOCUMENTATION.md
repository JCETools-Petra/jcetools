# JCE Tools API Documentation v2.0
## Security-Enhanced HWID Validation System

---

## 📋 Apa Yang Berubah?

### Versi Lama (v1.x) - INSECURE ❌
- API Key hardcoded di client binary
- AES encryption key/IV hardcoded
- No rate limiting
- HWID validation bug (tidak cek HWID, hanya cek tanggal)
- No anti-debugging protection

### Versi Baru (v2.0) - SECURE ✅
- JWT Token-based authentication
- Dynamic session-based encryption keys
- Database rate limiting (10 req/min per IP)
- Fixed HWID validation logic
- Multi-layer anti-debugging checks
- Comprehensive security logging

**Security Improvement:** dari 9.5/10 Risk → 4.0/10 Risk 🎉

---

## 🔄 API Flow Baru

```
Client                          Server
  |                               |
  | 1. Request Session Key        |
  |------------------------------>|
  |                               | Generate random key/IV
  |                               | Create JWT token
  | 2. Session Token + Key        |
  |<------------------------------|
  |                               |
  | Encrypt HWID with session key |
  |                               |
  | 3. Validate HWID (with token) |
  |------------------------------>|
  |                               | Verify token
  |                               | Validate HWID
  | 4. Access granted/denied      |
  |<------------------------------|
```

---

## 📡 API Endpoints

### 1. Get Session Key (NEW)
**Endpoint:** `POST /api/auth/get-session-key.php`

**Description:** Request temporary encryption key untuk HWID encryption

**Headers:** None required

**Response:**
```json
{
    "status": "success",
    "session_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
    "expires_in": 300,
    "message": "Session key generated successfully"
}
```

**Session Token Payload (JWT):**
```json
{
    "session_id": "abc123...",
    "key": "64-char-hex-key",
    "iv": "32-char-hex-iv",
    "ip": "client.ip.address",
    "purpose": "hwid_encryption",
    "iat": 1234567890,
    "exp": 1234567890,
    "jti": "unique-token-id"
}
```

**Rate Limit:** 20 requests/minute per IP

**Errors:**
```json
// Too many requests
{
    "error": "Too many requests",
    "retry_after": 60
}

// Server error
{
    "error": "Server configuration error"
}
```

---

### 2. Validate HWID (UPDATED)
**Endpoint:** `POST /api/jcetools-check.php`

**Description:** Validate encrypted HWID terhadap database

**Headers:**
```
Authorization: Bearer <session_token>
# OR
X-Session-Token: <session_token>
Content-Type: application/json
```

**Request Body:**
```json
{
    "hwid": "encrypted-hwid-hex-string"
}
```

**Responses:**

**Success - Valid License:**
```json
{
    "status": "success",
    "message": "Access granted",
    "expiry_date": "2025-12-31",
    "days_remaining": 180,
    "user": "John Doe"
}
```

**Error - Expired License:**
```json
{
    "status": "error",
    "message": "License expired.",
    "code": "EXPIRED"
}
```

**Error - HWID Not Found:**
```json
{
    "status": "error",
    "message": "Access denied.",
    "code": "NOT_FOUND"
}
```

**Error - Invalid/Expired Session:**
```json
{
    "status": "error",
    "message": "Invalid or expired session."
}
```

**Error - Rate Limited:**
```json
{
    "status": "error",
    "message": "Too many requests. Please try again later.",
    "retry_after": 60
}
```

**Rate Limit:** 10 requests/minute per IP

---

## 🔐 Security Features

### 1. JWT Token Authentication
- Replaces hardcoded API key
- Short-lived tokens (5 minutes)
- Signed with HMAC-SHA256
- Includes IP validation

### 2. Dynamic Encryption Keys
- Random 256-bit AES key per session
- Random 128-bit IV per session
- Keys stored server-side only
- Automatic expiration after 5 minutes

### 3. Rate Limiting
- Database-based (shared hosting compatible)
- Per-IP tracking
- Automatic cleanup of old records
- Different limits per endpoint

### 4. Anti-Debugging (Client-Side)
- IsDebuggerPresent() checks
- CheckRemoteDebuggerPresent() checks
- Hardware breakpoint detection (DR0-DR7)
- Timing anomaly detection
- PEB BeingDebugged flag check
- Multi-layer protection

### 5. Security Logging
- Logs stored outside webroot (`/var/log/jcetools/`)
- Separate files: success.log, error.log, intruder.log
- IP tracking for all events
- Comprehensive audit trail

### 6. Additional Protections
- Security headers (X-Frame-Options, CSP, etc.)
- Input validation and sanitization
- Minimal information disclosure
- HTTPS enforcement ready

---

## 🛠️ Client Implementation Example (C++)

### Step 1: Request Session Key
```cpp
std::string RequestSessionKey() {
    CURL* curl = curl_easy_init();
    std::string response;

    curl_easy_setopt(curl, CURLOPT_URL, "https://jcetools.my.id/api/auth/get-session-key.php");
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (res == CURLE_OK) {
        return response; // Parse JSON to get session_token
    }

    return "";
}
```

### Step 2: Extract Key from Token
```cpp
// Decode JWT token to get session key and IV
// Use a JWT library or base64 decode + JSON parse
SessionInfo ParseToken(const std::string& token) {
    // Implementation depends on your JWT library
    // Extract: session_id, key, iv
}
```

### Step 3: Encrypt HWID with Session Key
```cpp
std::string EncryptHWID(DWORD hwid, const std::string& key, const std::string& iv) {
    std::string plaintext = std::to_string(hwid);

    // Convert hex key/iv to binary
    unsigned char* keyBinary = HexToBinary(key);
    unsigned char* ivBinary = HexToBinary(iv);

    // Encrypt using AES-256-CBC
    std::vector<unsigned char> ciphertext;
    AES_Encrypt(plaintext, keyBinary, ivBinary, ciphertext);

    return BinaryToHex(ciphertext);
}
```

### Step 4: Validate HWID
```cpp
bool ValidateHWID(const std::string& encryptedHWID, const std::string& sessionToken) {
    CURL* curl = curl_easy_init();
    std::string response;

    std::string jsonPayload = "{\"hwid\":\"" + encryptedHWID + "\"}";
    std::string authHeader = "Authorization: Bearer " + sessionToken;

    struct curl_slist* headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, authHeader.c_str());

    curl_easy_setopt(curl, CURLOPT_URL, "https://jcetools.my.id/api/jcetools-check.php");
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonPayload.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    CURLcode res = curl_easy_perform(curl);

    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);

    // Parse response JSON
    auto json = nlohmann::json::parse(response);
    return json["status"] == "success";
}
```

---

## 🗄️ Database Changes

### New Table: `session_keys`
```sql
CREATE TABLE IF NOT EXISTS session_keys (
    id INT AUTO_INCREMENT PRIMARY KEY,
    session_id VARCHAR(64) UNIQUE NOT NULL,
    session_key VARCHAR(128) NOT NULL,
    session_iv VARCHAR(64) NOT NULL,
    client_ip VARCHAR(45) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    INDEX idx_session_id (session_id),
    INDEX idx_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

### New Table: `rate_limit_tracker`
```sql
CREATE TABLE IF NOT EXISTS rate_limit_tracker (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    request_count INT DEFAULT 1,
    window_start TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_request TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_ip (ip_address),
    INDEX idx_window (window_start)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

**Note:** Tables akan dibuat otomatis oleh API saat first run.

---

## 📦 Deployment ke Shared Hosting

### 1. Upload Files
```
public_html/
├── api/
│   ├── jcetools-check.php
│   ├── .htaccess
│   ├── auth/
│   │   └── get-session-key.php
│   └── utils/
│       ├── RateLimiter.php
│       └── TokenManager.php
├── vendor/  (from composer install)
└── .env
```

### 2. Configure .env
```env
DB_HOST=localhost
DB_USER=your_db_user
DB_PASS=your_db_password
DB_NAME=your_db_name
JWT_SECRET=your-very-long-secret-key-here
LOG_DIR=/home/username/logs  # Outside public_html!
```

### 3. Set Permissions
```bash
chmod 755 api/
chmod 644 api/*.php
chmod 640 .env
chmod 750 logs/  # Outside webroot
```

### 4. Create Log Directory
```bash
mkdir -p /home/username/logs
chmod 750 /home/username/logs
```

### 5. Test Endpoints
```bash
# Test session key generation
curl -X POST https://yourdomain.com/api/auth/get-session-key.php

# Test HWID validation (with token)
curl -X POST https://yourdomain.com/api/jcetools-check.php \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"hwid":"encrypted_hwid_here"}'
```

---

## 🔍 Troubleshooting

### Issue: "Session expired" error
**Solution:** Request new session key. Sessions expire after 5 minutes.

### Issue: "Too many requests" error
**Solution:** Wait 60 seconds. Rate limit is 10 req/min for validation, 20 req/min for session keys.

### Issue: "Database connection error"
**Solution:** Check .env configuration. Verify database credentials.

### Issue: Logs not being written
**Solution:**
1. Check LOG_DIR in .env points to writable directory
2. Ensure directory exists and has correct permissions (750)
3. Check disk space

### Issue: "Invalid request format"
**Solution:** Ensure HWID is valid hex string (a-f, 0-9) and not too long (max 512 chars).

---

## 📈 Monitoring & Maintenance

### Check Rate Limit Stats
```php
<?php
require_once 'api/utils/RateLimiter.php';
$rateLimiter = new RateLimiter($conn);
$stats = $rateLimiter->getStats();
print_r($stats);
```

### Clean Up Old Sessions
```sql
-- Automatic cleanup runs on each session key request
-- Manual cleanup:
DELETE FROM session_keys WHERE expires_at < NOW();
DELETE FROM rate_limit_tracker WHERE window_start < DATE_SUB(NOW(), INTERVAL 2 HOUR);
```

### Monitor Logs
```bash
# Success log
tail -f /home/username/logs/success.log

# Error log
tail -f /home/username/logs/error.log

# Intruder attempts
tail -f /home/username/logs/intruder.log
```

---

## 🛡️ Best Practices

1. **Always use HTTPS** - Never send tokens over HTTP
2. **Rotate JWT_SECRET regularly** - At least every 3 months
3. **Monitor intruder.log** - Watch for suspicious activity
4. **Keep backups** - Regular database backups
5. **Update dependencies** - Run `composer update` regularly
6. **Monitor rate limits** - Adjust if legitimate users are blocked
7. **Use strong passwords** - For database and .env secrets

---

## 📞 Support

Jika ada pertanyaan atau issues, check:
1. API logs di `/home/username/logs/`
2. Database connection settings di `.env`
3. File permissions (755 for dirs, 644 for PHP files)
4. Security analysis report: `SECURITY_ANALYSIS_REPORT.md`

---

**Version:** 2.0
**Last Updated:** 2025-12-13
**Compatibility:** Shared Hosting (PHP 7.4+, MySQL 5.7+)
