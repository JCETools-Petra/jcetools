<?php
/**
 * JCE Tools - Admin Helper for Bulk HWID Update
 * WARNING: Hapus file ini setelah selesai migrasi/maintenance!
 */

// --- KONFIGURASI KEAMANAN ---
// Ganti PIN ini dengan kode rahasia yang hanya kamu yang tahu
$admin_pin = "joshhh1830"; 
// ----------------------------

require_once __DIR__ . '/../vendor/autoload.php';
$dotenv = Dotenv\Dotenv::createImmutable(__DIR__ . '/..');
$dotenv->load();

$conn = new mysqli($_ENV['DB_HOST'], $_ENV['DB_USER'], $_ENV['DB_PASS'], $_ENV['DB_NAME']);

// Proses Update Form
$message = "";
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if ($_POST['pin'] !== $admin_pin) {
        $message = "<div style='color:red'>PIN Salah!</div>";
    } else {
        $username = $_POST['username'];
        $raw_hwid = $_POST['raw_hwid'];
        
        // Bersihkan input (hanya angka)
        $clean_hwid = preg_replace('/[^0-9]/', '', $raw_hwid);
        
        if (!empty($clean_hwid)) {
            // === DISINI KEAJAIBANNYA ===
            // Script otomatis mengubah angka menjadi HASH SHA-256
            $new_hash = hash('sha256', $clean_hwid);
            
            $stmt = $conn->prepare("UPDATE user_jce SET hwid_encrypted = ? WHERE Nama = ?");
            $stmt->bind_param("ss", $new_hash, $username);
            
            if ($stmt->execute()) {
                $message = "<div style='color:green'>Sukses! User <b>$username</b> diupdate.<br>HWID: $clean_hwid<br>Hash: " . substr($new_hash, 0, 10) . "...</div>";
            } else {
                $message = "<div style='color:red'>Gagal update database.</div>";
            }
        } else {
            $message = "<div style='color:red'>HWID tidak valid (harus angka).</div>";
        }
    }
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>JCE HWID Migrator</title>
    <style>
        body { font-family: sans-serif; padding: 20px; }
        table { border-collapse: collapse; width: 100%; max-width: 800px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        input[type=text] { width: 100%; padding: 5px; }
        input[type=password] { width: 100px; }
        button { padding: 5px 10px; cursor: pointer; background: #007bff; color: white; border: none; }
        .hash-preview { font-size: 10px; color: #666; }
    </style>
</head>
<body>
    <h2>⚡ JCE Tools - Quick Update HWID</h2>
    <p>Masukkan HWID Asli (Angka), tool ini akan otomatis mengubahnya menjadi Hash SHA-256 yang aman.</p>
    
    <?= $message ?>

    <table>
        <tr>
            <th>Username</th>
            <th>Status HWID Saat Ini</th>
            <th>Update HWID Baru (Angka Asli)</th>
        </tr>
        <?php
        $result = $conn->query("SELECT Nama, hwid_encrypted FROM user_jce ORDER BY Nama ASC");
        while ($row = $result->fetch_assoc()) {
            $is_hashed = (strlen($row['hwid_encrypted']) == 64); // SHA256 panjangnya 64 char
            $status = $is_hashed ? "<span style='color:green'>✅ Sudah Hash (Aman)</span>" : "<span style='color:orange'>⚠️ Format Lama/Kosong</span>";
            $val_preview = substr($row['hwid_encrypted'], 0, 15) . "...";
            ?>
            <tr>
                <td><b><?= htmlspecialchars($row['Nama']) ?></b></td>
                <td>
                    <?= $status ?><br>
                    <span class="hash-preview"><?= htmlspecialchars($val_preview) ?></span>
                </td>
                <td>
                    <form method="POST" style="display:flex; gap:5px;">
                        <input type="hidden" name="username" value="<?= htmlspecialchars($row['Nama']) ?>">
                        <input type="text" name="raw_hwid" placeholder="Cth: 14366231" required>
                        <input type="password" name="pin" placeholder="PIN" required>
                        <button type="submit">Update</button>
                    </form>
                </td>
            </tr>
        <?php } ?>
    </table>
</body>
</html>