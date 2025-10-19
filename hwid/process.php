<?php
// ===============================================
// BLOK ERROR REPORTING DAN LOGGING KUSTOM
// ===============================================

// Aktifkan tampilan semua error untuk debugging (Hapus di lingkungan produksi!)
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

$logFileError = __DIR__ . '/debug_process_error.log';

function logError($message) {
    global $logFileError;
    $timestamp = date('Y-m-d H:i:s');
    file_put_contents($logFileError, "[$timestamp] $message\n", FILE_APPEND);
    error_log("[$timestamp] $message");
}

// ===============================================

session_start();

// --- PERBAIKAN PATH AUTOLOAD VENDOR ---
try {
    $autoloadPath = __DIR__ . '/../vendor/autoload.php';
    if (!file_exists($autoloadPath)) {
        throw new Exception("Autoloader tidak ditemukan di: " . $autoloadPath . ". Jalankan 'composer install' di folder root.");
    }
    require $autoloadPath;
} catch (Exception $e) {
    logError("AUTOLOAD GAGAL: " . $e->getMessage());
    http_response_code(500);
    echo "Fatal Error: " . $e->getMessage();
    exit;
}

// --- IMPORT KELAS PHPMailer ---
use Dotenv\Dotenv;
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;
use PHPMailer\PHPMailer\SMTP; 

// --- PERBAIKAN PATH FILE .ENV ---
try {
    $dotenvPath = __DIR__ . '/../';
    if (!is_dir($dotenvPath)) {
        throw new Exception("Direktori .env tidak valid: " . $dotenvPath);
    }
    $dotenv = Dotenv::createImmutable($dotenvPath);
    $dotenv->safeLoad();
} catch (Exception $e) {
    logError("DOTENV GAGAL: " . $e->getMessage());
}

// Konfigurasi dari .env
$servername = $_ENV['DB_HOST'] ?? '';
$username = $_ENV['DB_USER'] ?? '';
$password = $_ENV['DB_PASS'] ?? '';
$dbname = $_ENV['DB_NAME'] ?? '';

// Pengaturan file log & kunci enkripsi
$logFile = 'ip_block_log.json';
$successLogFile = 'success.log';
$successCounterFile = 'success_counter.txt';

// Kunci dan IV (TIDAK DIUBAH sesuai permintaan Anda sebelumnya)
$key = hex2bin("4A4345544F4F4C532D31383330");
$iv = hex2bin("1234567890ABCDEF12345678");

// --- KUMPULAN FUNGSI ---

function getUserIP() {
    return $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN';
}

function encryptHwid($plaintext, $key, $iv) {
    return openssl_encrypt($plaintext, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
}

function binToHex($binaryData) {
    return bin2hex($binaryData);
}

/**
 * FUNGSI BARU: Membuat template email HTML yang menggunakan TEMA DARK MODE
 * dan mengembalikan body pesan HTML/AltBody dalam format array
 */
function createHwidChangeEmailContent(string $userNama, string $oldHwidTeks, string $newHwidTeks): array {
    
    // --- Variabel Tema Dark Mode ---
    $accentColor = '#FFD700'; // Emas
    $bgColor = '#121212';     // Hitam
    $cardColor = '#1e1e1e';   // Abu-abu Gelap
    $textColor = '#f1f1f1';   // Putih
    $secondaryColor = '#888'; // Abu-abu
    $oldHwidColor = '#e74c3c'; // Merah
    $logoUrl = 'https://jcetools.my.id/admin/logo.png';
    $siteName = 'JCE Tools';

    $subject = "Notifikasi Perubahan HWID Berhasil";

    // Konten Pesan Teks
    $isi_pesan_teks = "
HWID pada lisensi Anda telah berhasil diubah.

Detail:
HWID Lama: {$oldHwidTeks}
HWID Baru: {$newHwidTeks}

Jika Anda tidak merasa melakukan perubahan ini, harap segera hubungi admin atau tim dukungan kami.
";
    $pesan_html_konten = nl2br($isi_pesan_teks);


    // Template HTML menggunakan sintaks heredoc
    $template_html = <<<HTML
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$subject</title>
</head>
<body style="margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: $bgColor;">
    <table border="0" cellpadding="0" cellspacing="0" width="100%">
        <tr>
            <td style="padding: 20px 0;">
                <table align="center" border="0" cellpadding="0" cellspacing="0" width="600" style="border-collapse: collapse; background-color: $cardColor; border-radius: 12px; overflow: hidden;">
                    <tr>
                        <td align="center" style="padding: 30px 20px; border-bottom: 2px solid $accentColor;">
                            <img src="$logoUrl" alt="JCE Tools Logo" width="150" style="display: block;" />
                        </td>
                    </tr>
                    <tr>
                        <td style="padding: 40px 30px; color: $textColor; font-size: 16px; line-height: 1.6;">
                            <h1 style="color: $accentColor; font-size: 24px; margin-top: 0;">&#x2705; $subject</h1>
                            <p>Halo <strong>$userNama</strong>,</p>
                            
                            <p style="margin-top: 15px;">HWID pada lisensi Anda telah berhasil diubah pada <strong><span style="color: $accentColor;">{$siteName}</span></strong>.</p>

                            <p style="color: $oldHwidColor; margin-top: 20px; font-weight: bold;">HWID Lama:</p>
                            <p style="background-color: #2a2a2a; padding: 10px; border-radius: 6px; font-family: monospace; color: $textColor; word-break: break-all;">$oldHwidTeks</p>

                            <p style="color: $accentColor; margin-top: 20px; font-weight: bold;">HWID Baru:</p>
                            <p style="background-color: #2a2a2a; padding: 10px; border-radius: 6px; font-family: monospace; color: $textColor; word-break: break-all;">$newHwidTeks</p>

                            <p style="margin-top: 30px; font-size: 14px; color: $secondaryColor;">Jika Anda tidak merasa melakukan perubahan ini, harap segera hubungi admin atau tim dukungan kami.</p>

                        </td>
                    </tr>
                    <tr>
                        <td style="padding: 30px; text-align: center; font-size: 12px; color: $secondaryColor; border-top: 1px solid #444;">
                            <p>&copy; 2025 $siteName. Semua Hak Cipta Dilindungi.</p>
                            <p>Email ini dikirim secara otomatis. Untuk berhenti menerima notifikasi, Anda dapat <a href="mailto:unsubscribe@jcetools.my.id?subject=Unsubscribe" style="color: $accentColor;">berhenti berlangganan</a>.</p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>
HTML;

    return [
        'subject' => "[". date('d M Y, H:i') . "] " . $subject,
        'html_body' => $template_html,
        'alt_body' => strip_tags($isi_pesan_teks) . "\n\n---\nUntuk berhenti menerima notifikasi, kirim email ke unsubscribe@jcetools.my.id"
    ];
}


/**
 * FUNGSI UTAMA: Mengirim notifikasi perubahan HWID ke pengguna melalui PHPMailer dan SMTP
 */
function sendUserHwidChangeEmail($userEmail, $oldHwidTeks, $newHwidTeks, $userNama) {
    if (empty($userEmail)) {
        logError("Gagal mengirim email: Alamat email pengguna kosong.");
        return;
    }

    $mail = new PHPMailer(true);
    
    // Ambil kredensial SMTP dari .env
    $host = $_ENV['SMTP_HOST'] ?? '';
    $port = $_ENV['SMTP_PORT'] ?? 587;
    $secure = $_ENV['SMTP_SECURE'] ?? 'tls';
    $user = $_ENV['SMTP_USER'] ?? '';
    $pass = $_ENV['SMTP_PASS'] ?? '';
    $fromEmail = $_ENV['SMTP_FROM_EMAIL'] ?? 'noreply@jcetools.my.id';
    $fromName = $_ENV['SMTP_FROM_NAME'] ?? 'JCE Tools Notifier';

    $siteName = 'JCE Tools';
    
    // Panggil fungsi pembuat konten
    $content = createHwidChangeEmailContent($userNama, $oldHwidTeks, $newHwidTeks);

    try {
        // Konfigurasi Server
        // $mail->SMTPDebug = SMTP::DEBUG_SERVER; // Aktifkan ini untuk debugging
        $mail->isSMTP();
        $mail->Host       = $host;
        $mail->SMTPAuth   = true;
        $mail->Username   = $user;
        $mail->Password   = $pass;
        $mail->SMTPSecure = ($secure === 'ssl') ? PHPMailer::ENCRYPTION_SMTPS : PHPMailer::ENCRYPTION_STARTTLS;
        $mail->Port       = $port;

        // Pengirim dan Penerima
        $mail->setFrom($fromEmail, $fromName);
        $mail->addAddress($userEmail, $userNama);
        $mail->addReplyTo($fromEmail, $fromName);
        
        // Header List-Unsubscribe untuk mencegah spam
        $mail->addCustomHeader('List-Unsubscribe', '<mailto:unsubscribe@jcetools.my.id?subject=Unsubscribe>');


        // Konten
        $mail->isHTML(true);
        $mail->Subject = $content['subject'];
        $mail->Body    = $content['html_body'];
        $mail->AltBody = $content['alt_body'];

        $mail->send();

    } catch (Exception $e) {
        logError("PHPMailer GAGAL: Email tidak dapat dikirim ke {$userEmail}. Mailer Error: {$mail->ErrorInfo}.");
    }
}


/**
 * FUNGSI NOTIFIKASI KE ADMIN (DARI KODE ASLI ANDA)
 * DINONAKTIFKAN SESUAI PERMINTAAN
 */
function sendFonnteNotification($oldHwidTeks, $newHwidTeks, $userNama, $ip) {
    // KODE DINONAKTIFKAN
}

/**
 * FUNGSI NOTIFIKASI KE PENGGUNA (WhatsApp)
 * DINONAKTIFKAN SESUAI PERMINTAAN
 */
function sendUserHwidChangeNotification($userPhoneNumber, $oldHwidTeks, $newHwidTeks, $userNama) {
    // KODE DINONAKTIFKAN
}

function updateIpLog($ip, $logFile, $action) {
    $ipLogs = file_exists($logFile) ? json_decode(file_get_contents($logFile), true) ?? [] : [];
    if (!isset($ipLogs[$ip])) {
        $ipLogs[$ip] = ['violations' => 0, 'block_time' => 0];
    }
    if ($action === 'increment') {
        $ipLogs[$ip]['violations']++;
        if ($ipLogs[$ip]['violations'] >= 3) {
            $ipLogs[$ip]['block_time'] = time();
        }
    } elseif ($action === 'reset') {
        $ipLogs[$ip]['violations'] = 0;
        $ipLogs[$ip]['block_time'] = 0;
    }
    file_put_contents($logFile, json_encode($ipLogs, JSON_PRETTY_PRINT));
}

function isIpBlocked($ip, $logFile) {
    if (!file_exists($logFile)) return false;
    $ipLogs = json_decode(file_get_contents($logFile), true) ?? [];
    return isset($ipLogs[$ip]) && $ipLogs[$ip]['violations'] >= 3;
}

function validateCsrfToken($csrfToken) {
    if (empty($_SESSION['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $csrfToken)) {
        $_SESSION['notification'] = ["status" => "error", "message" => "Sesi tidak valid, silakan coba lagi."];
        header("Location: index.php");
        exit;
    }
}

/**
 * Fungsi utama yang dimodifikasi untuk mengambil email dan mencegah duplicate entry
 */
function replaceEncryptedHWIDInDB($originalText, $newText, $originalEncrypted, $newEncrypted, $successLogFile) {
    global $successCounterFile;
    $ip = getUserIP();
    
    // Cek koneksi DB
    try {
        $conn = new mysqli($GLOBALS['servername'], $GLOBALS['username'], $GLOBALS['password'], $GLOBALS['dbname']);
    } catch (\Throwable $e) {
        logError("Koneksi DB GAGAL: " . $e->getMessage());
        updateIpLog($ip, $GLOBALS['logFile'], 'increment');
        $_SESSION['notification'] = ["status" => "error", "message" => "Koneksi database gagal. (Kode 101)"];
        header("Location: index.php");
        exit;
    }
    
    if ($conn->connect_error) {
        logError("Koneksi DB GAGAL: " . $conn->connect_error);
        updateIpLog($ip, $GLOBALS['logFile'], 'increment');
        $_SESSION['notification'] = ["status" => "error", "message" => "Koneksi database gagal. (Kode 102)"];
        header("Location: index.php");
        exit;
    }

    // PERBAIKAN: VALIDASI DUPLICATE ENTRY
    $sql_check_new = "SELECT id FROM user_jce WHERE hwid_encrypted = ?";
    if ($stmt_check = $conn->prepare($sql_check_new)) {
        $stmt_check->bind_param("s", $newEncrypted);
        $stmt_check->execute();
        $result_check = $stmt_check->get_result();
        
        if ($result_check->num_rows > 0) {
            $stmt_check->close();
            $conn->close();
            logError("DUPLICATE ENTRY DITEMUKAN: HWID baru '$newEncrypted' sudah digunakan.");
            updateIpLog($ip, $GLOBALS['logFile'], 'increment');
            $_SESSION['notification'] = ["status" => "error", "message" => "Gagal: HWID Baru sudah digunakan oleh pengguna lain."];
            header("Location: index.php");
            exit;
        }
        $stmt_check->close();
    } else {
        logError("PREPARE SQL CHECK GAGAL: " . $conn->error);
    }
    
    $userName = "N/A";
    $userPhoneNumber = null; 
    $userEmail = null; 

    // ✅ PENTING: Ambil 'Nama', 'phone_number', dan 'email' dari database
    $sql_select = "SELECT Nama, phone_number, email FROM user_jce WHERE hwid_encrypted = ?";
    if ($stmt_select = $conn->prepare($sql_select)) {
        $stmt_select->bind_param("s", $originalEncrypted);
        $stmt_select->execute();
        $result = $stmt_select->get_result();
        if ($row = $result->fetch_assoc()) {
            $userName = $row['Nama']; 
            $userPhoneNumber = $row['phone_number']; 
            $userEmail = $row['email'] ?? null; 
        }
        $stmt_select->close();
    } else {
        logError("PREPARE SQL SELECT GAGAL: " . $conn->error);
    }

    // UPDATE HWID
    $sql_update = "UPDATE user_jce SET hwid_encrypted = ? WHERE hwid_encrypted = ?";
    if (!$stmt_update = $conn->prepare($sql_update)) {
        logError("PREPARE SQL UPDATE GAGAL: " . $conn->error);
        updateIpLog($ip, $GLOBALS['logFile'], 'increment');
        $_SESSION['notification'] = ["status" => "error", "message" => "Gagal menyiapkan perubahan. (Kode 103)"];
        $conn->close();
        header("Location: index.php");
        exit;
    }
    
    $stmt_update->bind_param("ss", $newEncrypted, $originalEncrypted);

    if ($stmt_update->execute()) {
        if ($stmt_update->affected_rows > 0) {
            updateIpLog($ip, $GLOBALS['logFile'], 'reset');
            
            $successCount = file_exists($successCounterFile) ? (int)file_get_contents($successCounterFile) : 0;
            file_put_contents($successCounterFile, $successCount + 1);
            
            $logMessage = sprintf(
                "[%s] HWID diganti dari '%s' ke '%s' oleh pengguna: %s (IP: %s)\n",
                date('Y-m-d H:i:s'), $originalEncrypted, $newEncrypted, $userName, $ip
            );
            file_put_contents($successLogFile, $logMessage, FILE_APPEND);
            
            $_SESSION['notification'] = ["status" => "success", "message" => "HWID berhasil diganti!"];
            
            // PANGGIL FUNGSI NOTIFIKASI
            sendUserHwidChangeEmail($userEmail, $originalText, $newText, $userName); // Notif User (EMAIL - AKTIF)
            
        } else {
            updateIpLog($ip, $GLOBALS['logFile'], 'increment');
            $_SESSION['notification'] = ["status" => "error", "message" => "HWID Lama tidak ditemukan!"];
        }
    } else {
        logError("EKSEKUSI SQL GAGAL: " . $stmt_update->error);
        updateIpLog($ip, $GLOBALS['logFile'], 'increment');
        $_SESSION['notification'] = ["status" => "error", "message" => "Gagal menyimpan perubahan: " . $stmt_update->error];
    }

    $stmt_update->close();
    $conn->close();
    header("Location: index.php");
    exit;
}

// --- ALUR EKSEKUSI UTAMA ---

$ip = getUserIP();
if (isIpBlocked($ip, $logFile)) {
    $_SESSION['notification'] = ["status" => "error", "message" => "Akses Anda diblokir karena terlalu banyak percobaan gagal."];
    header("Location: index.php");
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    validateCsrfToken($_POST['csrf_token'] ?? '');

    $originalText = $_POST['textbox1'] ?? '';
    $newText = $_POST['textbox2'] ?? '';

    if (empty($originalText) || empty($newText) || !preg_match('/^[0-9-]+$/', $originalText) || !preg_match('/^[0-9-]+$/', $newText)) {
        updateIpLog($ip, $logFile, 'increment');
        $_SESSION['notification'] = ["status" => "error", "message" => "Input tidak valid! Hanya angka dan tanda '-' yang diizinkan."];
        header("Location: index.php");
        exit;
    }

    $originalEncrypted = binToHex(encryptHwid($originalText, $key, $iv));
    $newEncrypted = binToHex(encryptHwid($newText, $key, $iv));
    
    replaceEncryptedHWIDInDB($originalText, $newText, $originalEncrypted, $newEncrypted, $successLogFile);
}
?>