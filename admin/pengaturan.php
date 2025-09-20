<?php
session_start();
if (!isset($_SESSION['admin_logged_in'])) {
    header('Location: login.php');
    exit();
}

require 'core/db_connect.php'; // Sesuaikan dengan path koneksi database Anda

$pesan = '';

// Proses form jika ada data yang dikirim
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['harga_perpanjangan_hwid'])) {
        $harga_baru = filter_input(INPUT_POST, 'harga_perpanjangan_hwid', FILTER_SANITIZE_NUMBER_INT);

        // Update atau Insert (UPSERT)
        $stmt = $conn->prepare("INSERT INTO settings (setting_key, setting_value) VALUES ('harga_perpanjangan_hwid', ?) ON DUPLICATE KEY UPDATE setting_value = ?");
        $stmt->bind_param('ss', $harga_baru, $harga_baru);
        
        if ($stmt->execute()) {
            $pesan = '<div class="alert alert-success">Pengaturan berhasil disimpan!</div>';
        } else {
            $pesan = '<div class="alert alert-danger">Gagal menyimpan pengaturan.</div>';
        }
        $stmt->close();
    }
}

// Ambil nilai saat ini dari database
$stmt = $conn->prepare("SELECT setting_value FROM settings WHERE setting_key = 'harga_perpanjangan_hwid'");
$stmt->execute();
$result = $stmt->get_result();
$pengaturan = $result->fetch_assoc();
$stmt->close();

$harga_perpanjangan_hwid = $pengaturan['setting_value'] ?? '0';

// Sertakan header dashboard
include 'includes/header.php'; // Asumsi Anda punya file header
?>

<div class="container mt-4">
    <h2>Pengaturan Aplikasi</h2>
    <hr>
    <?php echo $pesan; ?>

    <div class="card">
        <div class="card-header">
            Pengaturan Harga
        </div>
        <div class="card-body">
            <form method="POST" action="pengaturan.php">
                <div class="form-group mb-3">
                    <label for="harga_perpanjangan_hwid" class="form-label">
                        <strong>Harga Perpanjangan HWID (Per Bulan)</strong>
                    </label>
                    <div class="input-group">
                        <span class="input-group-text">Rp</span>
                        <input type="number" class="form-control" id="harga_perpanjangan_hwid" name="harga_perpanjangan_hwid" value="<?php echo htmlspecialchars($harga_perpanjangan_hwid); ?>" required>
                    </div>
                    <small class="form-text text-muted">
                        Harga ini akan digunakan sebagai biaya perpanjangan lisensi berbasis HWID per bulan.
                    </small>
                </div>
                <button type="submit" class="btn btn-primary">Simpan Pengaturan</button>
            </form>
        </div>
    </div>
</div>

<?php
include 'includes/footer.php'; // Asumsi Anda punya file footer
?>