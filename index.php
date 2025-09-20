<?php
// Load .env dan koneksi database
require __DIR__ . '/vendor/autoload.php';
$dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
$dotenv->load();

// Sembunyikan error di environment produksi untuk keamanan
// error_reporting(0);
// ini_set('display_errors', 0);

// Perbaikan: Konfigurasi cookie sesi yang aman HARUS sebelum session_start()
$samesite = 'Lax'; // or 'Strict'
if (PHP_VERSION_ID >= 70300) {
    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'domain' => $_SERVER['HTTP_HOST'],
        'secure' => true, // Gunakan hanya di HTTPS
        'httponly' => true,
        'samesite' => $samesite
    ]);
} else {
    // Fallback untuk versi PHP lama
    session_set_cookie_params(0, '/; SameSite=' . $samesite, $_SERVER['HTTP_HOST'], true, true);
}

session_start();

// Perbaikan: Regenerasi ID sesi untuk mencegah serangan session fixation
if (!isset($_SESSION['initiated'])) {
    session_regenerate_id(true);
    $_SESSION['initiated'] = true;
}

$servername = $_ENV['DB_HOST'];
$username_db = $_ENV['DB_USER'];
$password_db = $_ENV['DB_PASS'];
$dbname = $_ENV['DB_NAME'];

// Atur koneksi database
$conn = new mysqli($servername, $username_db, $password_db, $dbname);
if ($conn->connect_error) {
    // Jika koneksi gagal, tampilkan halaman maintenance
    include('maintenance.php');
    exit();
}

// Cek status maintenance dari database
// Menggunakan prepared statement untuk keamanan
$stmt = $conn->prepare("SELECT setting_value FROM settings WHERE setting_key = 'maintenance_mode' LIMIT 1");
$stmt->execute();
$result = $stmt->get_result();
$maintenance_status = 'on';
if ($result && $result->num_rows > 0) {
    $maintenance_status = $result->fetch_assoc()['setting_value'];
}
$stmt->close();

if ($maintenance_status === 'on') {
    include('maintenance.php');
    exit();
}

// Ambil produk yang aktif dari database
$products_result = $conn->query("SELECT * FROM produk WHERE is_active = TRUE ORDER BY harga ASC");
$products = [];
if ($products_result) {
    while ($row = $products_result->fetch_assoc()) {
        $products[] = $row;
    }
}
// Ambil harga dan ID produk bulanan (produk dengan harga terendah)
$harga_bulanan = !empty($products) ? $products[0]['harga'] : 0;
$produk_bulanan_id = !empty($products) ? $products[0]['id'] : 0;

// Buat CSRF token jika belum ada
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>JCE Tools - Pembelian Lisensi</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700&display=swap" rel="stylesheet">
    <script type="text/javascript" src="https://app.sandbox.midtrans.com/snap/snap.js" data-client-key="<?php echo htmlspecialchars($_ENV['MIDTRANS_CLIENT_KEY']); ?>"></script>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/sweetalert2@11/dist/sweetalert2.min.css">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css">
    <style>
        :root {
            --bg-dark: #121212;
            --bg-light: #1e1e1e;
            --bg-card: #2a2a2a;
            --gold: #ffd700;
            --gold-dark: #cca300;
            --text-light: #e0e0e0;
            --text-muted: #888;
            --border-color: #444;
            --font-family: 'Poppins', sans-serif;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        html {
            scroll-behavior: smooth;
        }

        body {
            font-family: var(--font-family);
            background-color: var(--bg-dark);
            color: var(--text-light);
            display: flex;
            justify-content: center;
            align-items: flex-start;
            min-height: 100vh;
            padding: 2rem 1rem;
        }

        .wizard-container {
            width: 100%;
            max-width: 700px;
            background-color: var(--bg-light);
            border-radius: 16px;
            box-shadow: 0 10px 40px rgba(0, 0, 0, 0.5);
            padding: 2.5rem;
            border-top: 5px solid var(--gold);
            overflow: hidden;
        }

        .wizard-header {
            text-align: center;
            margin-bottom: 2rem;
        }

        .wizard-header img {
            max-width: 120px;
            margin-bottom: 1rem;
        }

        .wizard-header h1 {
            color: var(--gold);
            font-weight: 700;
            font-size: 2.25rem;
        }
        
        .wizard-progress {
            display: flex;
            justify-content: space-between;
            margin-bottom: 2rem;
            position: relative;
        }
        .wizard-progress::before {
            content: '';
            position: absolute;
            top: 50%;
            left: 0;
            transform: translateY(-50%);
            height: 4px;
            width: 100%;
            background-color: var(--border-color);
            z-index: 1;
        }
        .progress-bar-line {
            position: absolute;
            top: 50%;
            left: 0;
            transform: translateY(-50%);
            height: 4px;
            background-color: var(--gold);
            z-index: 2;
            width: 0%;
            transition: width 0.4s ease;
        }
        .progress-step {
            display: flex;
            flex-direction: column;
            align-items: center;
            position: relative;
            z-index: 3;
            text-align: center;
        }
        .progress-step-dot {
            width: 30px;
            height: 30px;
            border-radius: 50%;
            background-color: var(--border-color);
            border: 3px solid var(--bg-light);
            transition: background-color 0.4s ease, border-color 0.4s ease;
        }
        .progress-step-label {
            margin-top: 0.5rem;
            font-size: 0.8rem;
            color: var(--text-muted);
            transition: color 0.4s ease;
        }
        .progress-step.active .progress-step-dot {
            background-color: var(--gold);
        }
        .progress-step.active .progress-step-label {
            color: var(--text-light);
        }

        .wizard-step {
            display: none;
        }
        .wizard-step.active {
            display: block;
            animation: fadeIn 0.5s;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .step-title {
            text-align: center;
            font-size: 1.5rem;
            font-weight: 600;
            margin-bottom: 1.5rem;
        }

        .selection-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 1rem;
        }
        .selection-card {
            background-color: var(--bg-card);
            border: 2px solid var(--border-color);
            border-radius: 12px;
            padding: 1.5rem;
            text-align: center;
            cursor: pointer;
            transition: all 0.3s ease;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
        }
        .selection-card:hover {
            transform: translateY(-5px);
            border-color: var(--gold);
        }
        .selection-card.selected {
            border-color: var(--gold);
            box-shadow: 0 0 15px rgba(255, 215, 0, 0.4);
        }
        .selection-card i {
            font-size: 2.5rem;
            color: var(--gold);
            margin-bottom: 1rem;
        }
        .selection-card h5 {
            font-weight: 600;
            margin-bottom: 0.5rem;
        }
        .selection-card p {
            font-size: 0.85rem;
            color: var(--text-muted);
            line-height: 1.4;
        }
        /* Style baru untuk deskripsi produk */
        .selection-card .description {
            font-size: 0.8rem;
            color: var(--text-light);
            margin-bottom: 0.75rem;
            flex-grow: 1;
        }

        .form-group {
            margin-bottom: 1.25rem;
        }
        .form-group label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: 500;
        }
        .form-group input {
            width: 100%;
            padding: 0.75rem 1rem;
            background-color: var(--bg-card);
            color: var(--text-light);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            font-family: var(--font-family);
            font-size: 1rem;
            transition: border-color 0.3s ease, box-shadow 0.3s ease;
        }
        .form-group input:focus {
            outline: none;
            border-color: var(--gold);
            box-shadow: 0 0 0 3px rgba(255, 215, 0, 0.2);
        }
        .input-group {
            display: flex;
            align-items: center;
        }
        .input-group input {
            text-align: center;
            border-right: 0;
            border-left: 0;
        }
        .input-group button {
            background-color: var(--bg-card);
            border: 1px solid var(--border-color);
            color: var(--gold);
            padding: 0.75rem;
            cursor: pointer;
            font-size: 1.2rem;
            line-height: 1;
        }
        .input-group button:first-child { border-radius: 8px 0 0 8px; }
        .input-group button:last-child { border-radius: 0 8px 8px 0; }
        
        .summary {
            background-color: var(--bg-card);
            padding: 1.5rem;
            border-radius: 12px;
            border-left: 4px solid var(--gold);
        }
        .summary-item {
            display: flex;
            justify-content: space-between;
            margin-bottom: 1rem;
            font-size: 0.9rem;
        }
        .summary-item span:first-child { color: var(--text-muted); }
        .summary-item span:last-child { font-weight: 600; }
        .summary-total {
            border-top: 1px solid var(--border-color);
            padding-top: 1rem;
            margin-top: 1rem;
            font-size: 1.2rem;
            font-weight: 700;
        }
        .summary-total span:last-child { color: var(--gold); }

        .wizard-footer {
            display: flex;
            justify-content: space-between;
            margin-top: 2.5rem;
        }
        .btn {
            padding: 0.75rem 1.5rem;
            border: none;
            border-radius: 8px;
            font-family: var(--font-family);
            font-weight: 600;
            font-size: 1rem;
            cursor: pointer;
            transition: all 0.3s ease;
        }
        .btn-secondary {
            background-color: var(--bg-card);
            border: 1px solid var(--border-color);
            color: var(--text-light);
        }
        .btn-secondary:hover { background-color: #3a3a3a; }
        .btn-primary {
            background-color: var(--gold);
            color: var(--bg-dark);
        }
        .btn-primary:hover { background-color: var(--gold-dark); }
        .btn:disabled { background-color: #555; cursor: not-allowed; color: #888; }
    </style>
</head>
<body>
    <div class="wizard-container">
        <div class="wizard-header">
            <img src="logo.png" alt="Logo JCE Tools">
            <h1>Pembelian Lisensi</h1>
        </div>
        
        <div class="wizard-progress">
            <div class="progress-bar-line"></div>
            <div class="progress-step active" data-step="1">
                <div class="progress-step-dot"></div>
                <div class="progress-step-label">Layanan</div>
            </div>
            <div class="progress-step" data-step="2">
                <div class="progress-step-dot"></div>
                <div class="progress-step-label">Detail</div>
            </div>
            <div class="progress-step" data-step="3">
                <div class="progress-step-dot"></div>
                <div class="progress-step-label">Bayar</div>
            </div>
        </div>

        <form id="payment-form">
            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
            <input type="hidden" id="form_tipe_order" name="tipe_order">
            <input type="hidden" id="form_renewal_type" name="renewal_type">
            <input type="hidden" id="form_produk_id" name="produk_id">
            <input type="hidden" id="form_jumlah_bulan" name="jumlah_bulan" value="1">
            <input type="hidden" id="form_nama_pembeli" name="nama_pembeli">
            <input type="hidden" id="form_nomor_whatsapp" name="nomor_whatsapp">
            <input type="hidden" id="form_license_username" name="license_username">
            <input type="hidden" id="form_license_password" name="license_password">
            <input type="hidden" id="form_hwid" name="hwid">

            <div id="step-1" class="wizard-step active">
                <h3 class="step-title">Pilih Jenis Layanan</h3>
                <div class="selection-grid">
                    <div class="selection-card" data-choice="baru">
                        <i class="bi bi-box-seam"></i>
                        <h5>Beli Lisensi Baru</h5>
                        <p>Daftarkan akun baru untuk lisensi Anda.</p>
                    </div>
                    <div class="selection-card" data-choice="perpanjang-hwid">
                        <i class="bi bi-hdd-stack"></i>
                        <h5>Perpanjang HWID</h5>
                        <p>Perpanjang lisensi berbasis HWID lama.</p>
                    </div>
                    <div class="selection-card" data-choice="perpanjang-paket">
                        <i class="bi bi-person-badge"></i>
                        <h5>Perpanjang Akun</h5>
                        <p>Perpanjang lisensi berbasis Akun/Username.</p>
                    </div>
                </div>
            </div>

            <div id="step-2" class="wizard-step">
                <h3 id="step-2-title" class="step-title"></h3>
                <div id="step-2-content"></div>
            </div>

            <div id="step-3" class="wizard-step">
                <h3 class="step-title">Konfirmasi Pembelian</h3>
                <div class="summary">
                    <div class="summary-item">
                        <span>Layanan</span>
                        <span id="summary-layanan"></span>
                    </div>
                    <div class="summary-item">
                        <span>Detail</span>
                        <span id="summary-detail"></span>
                    </div>
                     <div class="summary-item">
                        <span>Durasi</span>
                        <span id="summary-durasi"></span>
                    </div>
                    <hr style="border-color: var(--border-color); margin: 1rem 0;">
                    <div class="summary-item summary-total">
                        <span>Total Pembayaran</span>
                        <span id="summary-total"></span>
                    </div>
                </div>
            </div>

            <div class="wizard-footer">
                <button type="button" id="prev-btn" class="btn btn-secondary" style="display: none;">Kembali</button>
                <button type="button" id="next-btn" class="btn btn-primary" disabled>Lanjutkan</button>
                <button type="submit" id="pay-btn" class="btn btn-primary" style="display: none;">Bayar Sekarang</button>
            </div>
        </form>
    </div>

    <template id="template-beli-baru">
        <div class="product-selection">
            <div class="selection-grid product-grid">
                <?php
                if (!empty($products)) {
                    foreach ($products as $p) {
                        // Pastikan ada kolom 'deskripsi' di tabel 'produk' Anda
                        $deskripsi = isset($p['deskripsi']) ? htmlspecialchars($p['deskripsi']) : 'Deskripsi tidak tersedia.';
                        // Perbaikan: Gunakan nl2br untuk mengubah baris baru menjadi tag <br>
                        echo "<div class='selection-card' data-product-id='{$p['id']}' data-harga='{$p['harga']}' data-durasi='{$p['durasi_hari']} Hari'>";
                        echo "<div><i class='bi bi-patch-check'></i>";
                        echo "<h5>" . htmlspecialchars($p['nama_produk']) . "</h5>";
                        echo "<p class='description'>" . nl2br($deskripsi) . "</p></div>";
                        echo "<div><p>Rp " . number_format($p['harga']) . "</p></div>";
                        echo "</div>";
                    }
                }
                ?>
            </div>
        </div>
        <div class="form-group"><label for="input_nama_pembeli_baru">Nama Lengkap</label><input type="text" id="input_nama_pembeli_baru" placeholder="Masukkan nama lengkap Anda" required autocomplete="name"></div>
        <div class="form-group"><label for="input_nomor_whatsapp_baru">Nomor WhatsApp</label><input type="tel" id="input_nomor_whatsapp_baru" placeholder="Contoh: 628123456789" required autocomplete="tel"></div>
        <div class="form-group"><label for="input_license_username_baru">Username untuk Login</label><input type="text" id="input_license_username_baru" placeholder="Buat username untuk lisensi Anda" required autocomplete="username"></div>
        <div class="form-group"><label for="input_license_password_baru">Password untuk Login</label><input type="password" id="input_license_password_baru" placeholder="Buat password yang kuat" required autocomplete="new-password"></div>
    </template>

    <template id="template-perpanjang-hwid">
        <div class="form-group"><label for="input_hwid_perpanjang">HWID yang Terdaftar</label><input type="text" id="input_hwid_perpanjang" placeholder="Masukkan HWID yang akan diperpanjang" required></div>
        <div class="form-group"><label>Jumlah Bulan Perpanjangan</label>
            <div class="input-group">
                <button type="button" class="quantity-btn" data-action="minus">-</button>
                <input type="number" id="input_jumlah_bulan_hwid" value="1" min="1" max="12" class="form-control" readonly>
                <button type="button" class="quantity-btn" data-action="plus">+</button>
            </div>
        </div>
    </template>

    <template id="template-perpanjang-paket">
        <div class="form-group"><label for="input_license_username_perpanjang">Username Akun Anda</label><input type="text" id="input_license_username_perpanjang" placeholder="Masukkan username akun yang akan diperpanjang" required></div>
        <div class="form-group"><label>Jumlah Bulan Perpanjangan</label>
            <div class="input-group">
                <button type="button" class="quantity-btn" data-action="minus">-</button>
                <input type="number" id="input_jumlah_bulan_paket" value="1" min="1" max="12" class="form-control" readonly>
                <button type="button" class="quantity-btn" data-action="plus">+</button>
            </div>
        </div>
    </template>
    
    <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const wizard = {
                currentStep: 1,
                totalSteps: 3,
                steps: document.querySelectorAll('.wizard-step'),
                progressSteps: document.querySelectorAll('.progress-step'),
                progressBar: document.querySelector('.progress-bar-line'),
                prevBtn: document.getElementById('prev-btn'),
                nextBtn: document.getElementById('next-btn'),
                payBtn: document.getElementById('pay-btn'),
                form: document.getElementById('payment-form'),
                formTipeOrder: document.getElementById('form_tipe_order'),
                formRenewalType: document.getElementById('form_renewal_type'),
                formProdukId: document.getElementById('form_produk_id'),
                formJumlahBulan: document.getElementById('form_jumlah_bulan'),
                formNamaPembeli: document.getElementById('form_nama_pembeli'),
                formNomorWhatsapp: document.getElementById('form_nomor_whatsapp'),
                formLicenseUsername: document.getElementById('form_license_username'),
                formLicensePassword: document.getElementById('form_license_password'),
                formHwid: document.getElementById('form_hwid'),
                hargaBulanan: <?php echo $harga_bulanan; ?>,
                produkBulananId: <?php echo $produk_bulanan_id; ?>,
                pilihan: {},
            };

            function init() {
                document.querySelectorAll('#step-1 .selection-card').forEach(card => {
                    card.addEventListener('click', () => selectChoice(card));
                });
                wizard.nextBtn.addEventListener('click', nextStep);
                wizard.prevBtn.addEventListener('click', prevStep);
                wizard.form.addEventListener('submit', handleFormSubmit);
                updateButtons();
            }

            function selectChoice(selectedCard) {
                document.querySelectorAll('#step-1 .selection-card').forEach(card => card.classList.remove('selected'));
                selectedCard.classList.add('selected');
                wizard.pilihan.layanan = selectedCard.dataset.choice;
                updateButtons(); // Aktifkan tombol "Lanjutkan"
            }

            async function nextStep() {
                if (wizard.currentStep < wizard.totalSteps) {
                    if (wizard.currentStep === 1) {
                        buildStep2();
                    } else if (wizard.currentStep === 2) {
                        // Validasi di sisi klien
                        if (!validateStep2()) {
                            Swal.fire('Data Belum Lengkap', 'Silakan isi semua data yang diperlukan.', 'warning');
                            return;
                        }
                        // Validasi di sisi server
                        const isValid = await validateStep2Server();
                        if (!isValid) return;
                        buildStep3();
                    }
                    wizard.currentStep++;
                    updateWizard();
                }
            }

            function prevStep() {
                if (wizard.currentStep > 1) {
                    wizard.currentStep--;
                    updateWizard();
                }
            }

            function updateWizard() {
                wizard.steps.forEach(step => step.classList.remove('active'));
                document.getElementById(`step-${wizard.currentStep}`).classList.add('active');
                wizard.progressSteps.forEach((step, index) => {
                    step.classList.toggle('active', index < wizard.currentStep);
                });
                const progressPercentage = ((wizard.currentStep - 1) / (wizard.totalSteps - 1)) * 100;
                wizard.progressBar.style.width = `${progressPercentage}%`;
                updateButtons();
            }

            function updateButtons() {
                wizard.prevBtn.style.display = wizard.currentStep > 1 ? 'inline-block' : 'none';
                wizard.nextBtn.style.display = wizard.currentStep < wizard.totalSteps ? 'inline-block' : 'none';
                wizard.payBtn.style.display = wizard.currentStep === wizard.totalSteps ? 'inline-block' : 'none';
                wizard.nextBtn.disabled = wizard.currentStep === 1 && !wizard.pilihan.layanan;
            }

            function buildStep2() {
                const titleEl = document.getElementById('step-2-title');
                const contentEl = document.getElementById('step-2-content');
                let templateId = '';
                switch (wizard.pilihan.layanan) {
                    case 'baru':
                        titleEl.textContent = 'Lengkapi Data Akun Baru';
                        templateId = 'template-beli-baru';
                        break;
                    case 'perpanjang-hwid':
                        titleEl.textContent = 'Detail Perpanjangan HWID';
                        templateId = 'template-perpanjang-hwid';
                        break;
                    case 'perpanjang-paket':
                        titleEl.textContent = 'Detail Perpanjangan Akun';
                        templateId = 'template-perpanjang-paket';
                        break;
                }
                const template = document.getElementById(templateId);
                contentEl.innerHTML = template.innerHTML;
                attachStep2Listeners();
                updateButtons();
            }

            function attachStep2Listeners() {
                document.querySelectorAll('#step-2 input').forEach(input => {
                    input.addEventListener('input', () => { wizard.nextBtn.disabled = !validateStep2(); });
                });
                document.querySelectorAll('#step-2 .selection-card').forEach(card => {
                    card.addEventListener('click', () => {
                        document.querySelectorAll('#step-2 .selection-card').forEach(c => c.classList.remove('selected'));
                        card.classList.add('selected');
                        wizard.nextBtn.disabled = !validateStep2();
                    });
                });
                document.querySelectorAll('#step-2 .quantity-btn').forEach(btn => {
                    btn.addEventListener('click', (e) => {
                        const action = e.target.dataset.action;
                        const input = e.target.parentElement.querySelector('input[type="number"]');
                        let value = parseInt(input.value, 10);
                        if (action === 'plus' && value < 12) value++;
                        if (action === 'minus' && value > 1) value--;
                        input.value = value;
                        wizard.nextBtn.disabled = !validateStep2();
                    });
                });
            }

            function validateStep2() {
                let isValid = true;
                const requiredInputs = document.querySelectorAll('#step-2 input[required]');
                requiredInputs.forEach(input => {
                    if (!input.value.trim()) isValid = false;
                });
                if (document.querySelector('#step-2 .product-grid')) {
                    if (!document.querySelector('#step-2 .selection-card.selected')) isValid = false;
                }
                return isValid;
            }

            async function validateStep2Server() {
                const layanan = wizard.pilihan.layanan;
                let formData = new FormData();
                formData.append('csrf_token', wizard.form.querySelector('input[name="csrf_token"]').value);

                if (layanan === 'perpanjang-hwid') {
                    const hwid = document.getElementById('input_hwid_perpanjang').value;
                    formData.append('tipe_order', 'perpanjang-hwid');
                    formData.append('hwid', hwid);
                } else if (layanan === 'perpanjang-paket') {
                    const username = document.getElementById('input_license_username_perpanjang').value;
                    formData.append('tipe_order', 'perpanjang-paket');
                    formData.append('username', username);
                } else {
                    // Untuk 'beli baru', tidak perlu validasi server di sini
                    return true;
                }

                wizard.nextBtn.disabled = true;
                wizard.nextBtn.textContent = 'Memvalidasi...';

                try {
                    const response = await fetch('check_renewal.php', {
                        method: 'POST',
                        body: formData
                    });
                    const result = await response.json();

                    if (result.success) {
                        Swal.fire('Validasi Berhasil', result.message, 'success');
                        return true;
                    } else {
                        Swal.fire('Validasi Gagal', result.message, 'error');
                        return false;
                    }
                } catch (error) {
                    console.error('Error Validasi:', error);
                    Swal.fire('Kesalahan Jaringan', 'Tidak dapat terhubung ke server validasi. Coba lagi.', 'error');
                    return false;
                } finally {
                    wizard.nextBtn.disabled = false;
                    wizard.nextBtn.textContent = 'Lanjutkan';
                }
            }
            
            function buildStep3() {
                const layanan = wizard.pilihan.layanan;
                let layananText = '',
                    detailText = '',
                    durasiText = '',
                    totalHarga = 0,
                    produkId = wizard.produkBulananId;

                if (layanan === 'baru') {
                    const selectedCard = document.querySelector('#step-2 .selection-card.selected');
                    if (selectedCard) {
                        totalHarga = parseInt(selectedCard.dataset.harga, 10);
                        durasiText = selectedCard.dataset.durasi;
                        produkId = selectedCard.dataset.productId;
                    }
                    layananText = 'Beli Lisensi Baru';
                    const nama = document.getElementById('input_nama_pembeli_baru').value;
                    const whatsapp = document.getElementById('input_nomor_whatsapp_baru').value;
                    const username = document.getElementById('input_license_username_baru').value;
                    const password = document.getElementById('input_license_password_baru').value;
                    detailText = username;

                    wizard.formTipeOrder.value = 'baru';
                    wizard.formProdukId.value = produkId;
                    wizard.formNamaPembeli.value = nama;
                    wizard.formNomorWhatsapp.value = whatsapp;
                    wizard.formLicenseUsername.value = username;
                    wizard.formLicensePassword.value = password;
                } else if (layanan === 'perpanjang-hwid' || layanan === 'perpanjang-paket') {
                    const inputBulan = document.getElementById(layanan === 'perpanjang-hwid' ? 'input_jumlah_bulan_hwid' : 'input_jumlah_bulan_paket');
                    const bulan = parseInt(inputBulan.value, 10);
                    totalHarga = wizard.hargaBulanan * bulan;
                    durasiText = `${bulan} Bulan`;
                    wizard.formTipeOrder.value = 'perpanjang';
                    wizard.formProdukId.value = wizard.produkBulananId;
                    wizard.formJumlahBulan.value = bulan;
                    if (layanan === 'perpanjang-hwid') {
                        layananText = 'Perpanjang HWID';
                        const hwid = document.getElementById('input_hwid_perpanjang').value;
                        detailText = `HWID: ...${hwid.slice(-6)}`;
                        wizard.formRenewalType.value = 'hwid';
                        wizard.formHwid.value = hwid;
                    } else {
                        layananText = 'Perpanjang Akun';
                        const username = document.getElementById('input_license_username_perpanjang').value;
                        detailText = `Username: ${username}`;
                        wizard.formRenewalType.value = 'session';
                        wizard.formLicenseUsername.value = username;
                    }
                }
                document.getElementById('summary-layanan').textContent = layananText;
                document.getElementById('summary-detail').textContent = detailText;
                document.getElementById('summary-durasi').textContent = durasiText;
                document.getElementById('summary-total').textContent = 'Rp ' + new Intl.NumberFormat('id-ID').format(totalHarga);
            }

            async function handleFormSubmit(event) {
                event.preventDefault();
                const payButton = document.getElementById('pay-btn');
                const originalButtonText = payButton.textContent;
                payButton.textContent = 'Memproses...';
                payButton.disabled = true;
                const formData = new FormData(wizard.form);

                try {
                    const response = await fetch('proses_pembayaran.php', {
                        method: 'POST',
                        body: formData
                    });
                    if (!response.ok) {
                        throw new Error(`HTTP error! status: ${response.status}`);
                    }
                    const result = await response.json();
                    if (result.success && result.snap_token) {
                        snap.pay(result.snap_token, {
                            onSuccess: function() {
                                window.location.href = '/halaman-sukses.html';
                            },
                            onPending: function() {
                                Swal.fire('Pembayaran Tertunda', 'Silakan selesaikan pembayaran Anda.', 'info');
                            },
                            onError: function() {
                                Swal.fire('Pembayaran Gagal', 'Terjadi kesalahan saat pemrosesan.', 'error');
                            },
                            onClose: function() {
                                if (!Swal.isVisible()) {
                                    payButton.textContent = originalButtonText;
                                    payButton.disabled = false;
                                }
                            }
                        });
                    } else {
                        Swal.fire({
                            icon: 'error',
                            title: 'Oops... Terjadi Kesalahan',
                            text: result.message || 'Gagal mendapatkan token pembayaran.'
                        });
                        payButton.textContent = originalButtonText;
                        payButton.disabled = false;
                    }
                } catch (error) {
                    console.error('Fetch Error:', error);
                    Swal.fire({
                        icon: 'error',
                        title: 'Kesalahan Jaringan',
                        text: 'Tidak dapat terhubung ke server. Silakan coba lagi.'
                    });
                    payButton.textContent = originalButtonText;
                    payButton.disabled = false;
                }
            }

            init();
        });
    </script>
</body>
</html>
<?php
// Selalu tutup koneksi database setelah selesai digunakan
$conn->close();
?>