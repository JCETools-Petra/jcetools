<?php
// Menggunakan class dari library PHPMailer
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

// Memuat autoloader dari Composer.
require_once __DIR__ . '/../../vendor/autoload.php';

function kirimEmail(string $tujuan, string $nama_tujuan, string $subjek, string $isi_pesan): bool {
    $mail = new PHPMailer(true);

    try {
        // Konfigurasi Server SMTP dari file .env
        $mail->isSMTP();
        $mail->Host       = $_ENV['SMTP_HOST'];
        $mail->SMTPAuth   = true;
        $mail->Username   = $_ENV['SMTP_USER'];
        $mail->Password   = $_ENV['SMTP_PASS'];
        $mail->SMTPSecure = $_ENV['SMTP_SECURE'] ?? PHPMailer::ENCRYPTION_STARTTLS;
        $mail->Port       = (int)$_ENV['SMTP_PORT'];

        // Pengirim dan Penerima
        $mail->setFrom($_ENV['SMTP_FROM_EMAIL'], $_ENV['SMTP_FROM_NAME']);
        $mail->addAddress($tujuan, $nama_tujuan);

        // Header List-Unsubscribe untuk mencegah spam
        $mail->addCustomHeader('List-Unsubscribe', '<mailto:unsubscribe@jcetools.my.id?subject=Unsubscribe>');

        // Template HTML (tidak ada perubahan di sini)
        $pesan_html = nl2br($isi_pesan);
        $logo_url = 'https://jcetools.my.id/admin/logo.png';

        $template_html = <<<HTML
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$subjek</title>
</head>
<body style="margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #121212;">
    <table border="0" cellpadding="0" cellspacing="0" width="100%">
        <tr>
            <td style="padding: 20px 0;">
                <table align="center" border="0" cellpadding="0" cellspacing="0" width="600" style="border-collapse: collapse; background-color: #1e1e1e; border-radius: 12px; overflow: hidden;">
                    <tr>
                        <td align="center" style="padding: 30px 20px; border-bottom: 2px solid #FFD700;">
                            <img src="$logo_url" alt="JCE Tools Logo" width="150" style="display: block;" />
                        </td>
                    </tr>
                    <tr>
                        <td style="padding: 40px 30px; color: #f1f1f1; font-size: 16px; line-height: 1.6;">
                            <h1 style="color: #FFD700; font-size: 24px; margin-top: 0;">$subjek</h1>
                            <p>Halo <strong>$nama_tujuan</strong>,</p>
                            $pesan_html
                        </td>
                    </tr>
                    <tr>
                        <td style="padding: 30px; text-align: center; font-size: 12px; color: #888; border-top: 1px solid #444;">
                            <p>&copy; 2025 JCE Tools. Semua Hak Cipta Dilindungi.</p>
                            <p>Email ini dikirim secara otomatis. Untuk berhenti menerima notifikasi, Anda dapat <a href="mailto:unsubscribe@jcetools.my.id?subject=Unsubscribe" style="color: #FFD700;">berhenti berlangganan</a>.</p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>
HTML;

        // Konten Email
        $mail->isHTML(true);
        
        // ==================================================================
        // PERUBAHAN UTAMA: Menambahkan timestamp ke subjek email
        // Format: [14 Oct 2025, 00:15] Subjek Asli Email
        // ==================================================================
        $mail->Subject = "[" . date('d M Y, H:i') . "] " . $subjek;
        
        $mail->Body    = $template_html;
        $mail->AltBody = strip_tags($isi_pesan) . "\n\n---\nUntuk berhenti menerima notifikasi, kirim email ke unsubscribe@jcetools.my.id";


        $mail->send();
        return true;
    } catch (Exception $e) {
        // Jika gagal, catat error ke log server untuk debugging
        error_log("Gagal mengirim email ke {$tujuan}: " . $mail->ErrorInfo);
        return false;
    }
}
?>