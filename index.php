<?php
// Load .env, vendor, dan mulai sesi secara konsisten
require __DIR__ . '/vendor/autoload.php';
require __DIR__ . '/core/session_starter.php';

$dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
$dotenv->load();

// REVISI CSP: Mengizinkan 'unsafe-inline' dan koneksi ke Midtrans
$csp = "script-src 'self' https://app.sandbox.midtrans.com https://cdn.jsdelivr.net https://fonts.googleapis.com 'unsafe-eval' 'unsafe-inline'; ";
$csp .= "style-src 'self' https://cdn.jsdelivr.net https://fonts.googleapis.com 'unsafe-inline'; ";
$csp .= "font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net; ";
$csp .= "connect-src 'self' https://jcetools.my.id https://app.sandbox.midtrans.com; "; // Ganti dengan domain Anda jika perlu
header("Content-Security-Policy: " . $csp);

// Regenerasi ID sesi untuk mencegah serangan session fixation
if (!isset($_SESSION['initiated'])) {
    session_regenerate_id(true);
    $_SESSION['initiated'] = true;
}

// REVISI CSRF: Terapkan metode Double Submit Cookie
$csrf_token_value = '';
if (empty($_SESSION['csrf_token'])) {
    $csrf_token_value = bin2hex(random_bytes(32));
    $_SESSION['csrf_token'] = $csrf_token_value; // Simpan di sesi untuk disisipkan di form
    // Set token sebagai cookie yang akan divalidasi di server
    setcookie('X-CSRF-TOKEN', $csrf_token_value, [
        'expires' => time() + 3600, // Kadaluarsa dalam 1 jam
        'path' => '/',
        'samesite' => 'Strict',
    ]);
} else {
    $csrf_token_value = $_SESSION['csrf_token'];
}

$servername = $_ENV['DB_HOST'];
$username_db = $_ENV['DB_USER'];
$password_db = $_ENV['DB_PASS'];
$dbname = $_ENV['DB_NAME'];

$conn = new mysqli($servername, $username_db, $password_db, $dbname);
if ($conn->connect_error) {
    include('maintenance.php');
    exit();
}

$stmt = $conn->prepare("SELECT setting_value FROM settings WHERE setting_key = 'maintenance_mode' LIMIT 1");
$stmt->execute();
$result = $stmt->get_result();
$maintenance_status = ($result && $result->num_rows > 0) ? $result->fetch_assoc()['setting_value'] : 'off';
$stmt->close();

if ($maintenance_status === 'on') {
    include('maintenance.php');
    exit();
}

$products_result = $conn->query("SELECT * FROM produk WHERE is_active = TRUE ORDER BY harga ASC");
$products = [];
if ($products_result) {
    while ($row = $products_result->fetch_assoc()) {
        $products[] = $row;
    }
}

$stmt_harga = $conn->prepare("SELECT setting_value FROM settings WHERE setting_key = 'harga_perpanjangan_hwid' LIMIT 1");
$stmt_harga->execute();
$result_harga = $stmt_harga->get_result();
$harga_perpanjangan = $result_harga->fetch_assoc();
$stmt_harga->close();

$harga_bulanan = !empty($harga_perpanjangan) ? $harga_perpanjangan['setting_value'] : (!empty($products) ? $products[0]['harga'] : 0);
$produk_bulanan_id = !empty($products) ? $products[0]['id'] : 0;
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
        :root{--bg-dark:#121212;--bg-light:#1e1e1e;--bg-card:#2a2a2a;--gold:#ffd700;--gold-dark:#cca300;--text-light:#e0e0e0;--text-muted:#888;--border-color:#444;--font-family:'Poppins',sans-serif}*{box-sizing:border-box;margin:0;padding:0}html{scroll-behavior:smooth}body{font-family:var(--font-family);background-color:var(--bg-dark);color:var(--text-light);display:flex;justify-content:center;align-items:flex-start;min-height:100vh;padding:2rem 1rem}.wizard-container{width:100%;max-width:700px;background-color:var(--bg-light);border-radius:16px;box-shadow:0 10px 40px rgba(0,0,0,.5);padding:2.5rem;border-top:5px solid var(--gold);overflow:hidden}.wizard-header{text-align:center;margin-bottom:2rem}.wizard-header img{max-width:120px;margin-bottom:1rem}.wizard-header h1{color:var(--gold);font-weight:700;font-size:2.25rem}.wizard-progress{display:flex;justify-content:space-between;margin-bottom:2rem;position:relative}.wizard-progress::before{content:'';position:absolute;top:50%;left:0;transform:translateY(-50%);height:4px;width:100%;background-color:var(--border-color);z-index:1}.progress-bar-line{position:absolute;top:50%;left:0;transform:translateY(-50%);height:4px;background-color:var(--gold);z-index:2;width:0;transition:width .4s ease}.progress-step{display:flex;flex-direction:column;align-items:center;position:relative;z-index:3;text-align:center}.progress-step-dot{width:30px;height:30px;border-radius:50%;background-color:var(--border-color);border:3px solid var(--bg-light);transition:background-color .4s ease,border-color .4s ease}.progress-step-label{margin-top:.5rem;font-size:.8rem;color:var(--text-muted);transition:color .4s ease}.progress-step.active .progress-step-dot{background-color:var(--gold)}.progress-step.active .progress-step-label{color:var(--text-light)}.wizard-step{display:none}.wizard-step.active{display:block;animation:fadeIn .5s}@keyframes fadeIn{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:translateY(0)}}.step-title{text-align:center;font-size:1.5rem;font-weight:600;margin-bottom:1.5rem}.selection-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:1rem}.selection-card{background-color:var(--bg-card);border:2px solid var(--border-color);border-radius:12px;padding:1.5rem;text-align:center;cursor:pointer;transition:all .3s ease;display:flex;flex-direction:column;justify-content:space-between}.selection-card:hover{transform:translateY(-5px);border-color:var(--gold)}.selection-card.selected{border-color:var(--gold);box-shadow:0 0 15px rgba(255,215,0,.4)}.selection-card i{font-size:2.5rem;color:var(--gold);margin-bottom:1rem}.selection-card h5{font-weight:600;margin-bottom:.5rem}.selection-card p{font-size:.85rem;color:var(--text-muted);line-height:1.4}.selection-card .description{font-size:.8rem;color:var(--text-light);margin-bottom:.75rem;flex-grow:1}.form-group{margin-bottom:1.25rem}.form-group label{display:block;margin-bottom:.5rem;font-weight:500}.form-group input{width:100%;padding:.75rem 1rem;background-color:var(--bg-card);color:var(--text-light);border:1px solid var(--border-color);border-radius:8px;font-family:var(--font-family);font-size:1rem;transition:border-color .3s ease,box-shadow .3s ease}.form-group input:focus{outline:none;border-color:var(--gold);box-shadow:0 0 0 3px rgba(255,215,0,.2)}.input-group{display:flex;align-items:center}.input-group input{text-align:center;border-right:0;border-left:0}.input-group button{background-color:var(--bg-card);border:1px solid var(--border-color);color:var(--gold);padding:.75rem;cursor:pointer;font-size:1.2rem;line-height:1}.input-group button:first-child{border-radius:8px 0 0 8px}.input-group button:last-child{border-radius:0 8px 8px 0}.summary{background-color:var(--bg-card);padding:1.5rem;border-radius:12px;border-left:4px solid var(--gold)}.summary-item{display:flex;justify-content:space-between;margin-bottom:1rem;font-size:.9rem}.summary-item span:first-child{color:var(--text-muted)}.summary-item span:last-child{font-weight:600}.summary-total{border-top:1px solid var(--border-color);padding-top:1rem;margin-top:1rem;font-size:1.2rem;font-weight:700}.summary-total span:last-child{color:var(--gold)}.wizard-footer{display:flex;justify-content:space-between;margin-top:2.5rem}.btn{padding:.75rem 1.5rem;border:none;border-radius:8px;font-family:var(--font-family);font-weight:600;font-size:1rem;cursor:pointer;transition:all .3s ease}.btn-secondary{background-color:var(--bg-card);border:1px solid var(--border-color);color:var(--text-light)}.btn-secondary:hover{background-color:#3a3a3a}.btn-primary{background-color:var(--gold);color:var(--bg-dark)}.btn-primary:hover{background-color:var(--gold-dark)}.btn:disabled{background-color:#555;cursor:not-allowed;color:#888}
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
            <div class="progress-step active" data-step="1"><div class="progress-step-dot"></div><div class="progress-step-label">Layanan</div></div>
            <div class="progress-step" data-step="2"><div class="progress-step-dot"></div><div class="progress-step-label">Detail</div></div>
            <div class="progress-step" data-step="3"><div class="progress-step-dot"></div><div class="progress-step-label">Bayar</div></div>
        </div>

        <form id="payment-form">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token_value); ?>">
            <input type="hidden" id="form_tipe_order" name="tipe_order"><input type="hidden" id="form_renewal_type" name="renewal_type"><input type="hidden" id="form_produk_id" name="produk_id"><input type="hidden" id="form_jumlah_bulan" name="jumlah_bulan" value="1"><input type="hidden" id="form_nama_pembeli" name="nama_pembeli"><input type="hidden" id="form_nomor_whatsapp" name="nomor_whatsapp"><input type="hidden" id="form_license_username" name="license_username"><input type="hidden" id="form_license_password" name="license_password"><input type="hidden" id="form_hwid" name="hwid">

            <div id="step-1" class="wizard-step active">
                <h3 class="step-title">Pilih Jenis Layanan</h3>
                <div class="selection-grid">
                    <div class="selection-card" data-choice="baru"><i class="bi bi-box-seam"></i><h5>Beli Lisensi Baru</h5><p>Daftarkan akun baru untuk lisensi Anda.</p></div>
                    <div class="selection-card" data-choice="perpanjang-hwid"><i class="bi bi-hdd-stack"></i><h5>Perpanjang HWID</h5><p>Perpanjang lisensi berbasis HWID lama.</p></div>
                    <div class="selection-card" data-choice="perpanjang-paket"><i class="bi bi-person-badge"></i><h5>Perpanjang Akun</h5><p>Perpanjang lisensi berbasis Akun/Username.</p></div>
                </div>
            </div>

            <div id="step-2" class="wizard-step"><h3 id="step-2-title" class="step-title"></h3><div id="step-2-content"></div></div>

            <div id="step-3" class="wizard-step">
                <h3 class="step-title">Konfirmasi Pembelian</h3>
                <div class="summary">
                    <div class="summary-item"><span>Layanan</span><span id="summary-layanan"></span></div>
                    <div class="summary-item"><span>Detail</span><span id="summary-detail"></span></div>
                    <div class="summary-item"><span>Durasi</span><span id="summary-durasi"></span></div>
                    <hr style="border-color: var(--border-color); margin: 1rem 0;">
                    <div class="summary-item summary-total"><span>Total Pembayaran</span><span id="summary-total"></span></div>
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
                <?php foreach ($products as $p): ?>
                    <div class='selection-card' data-product-id='<?php echo $p['id']; ?>' data-harga='<?php echo $p['harga']; ?>' data-durasi='<?php echo $p['durasi_hari']; ?> Hari'>
                        <div><i class='bi bi-patch-check'></i>
                        <h5><?php echo htmlspecialchars($p['nama_produk']); ?></h5>
                        <p class='description'><?php echo nl2br(htmlspecialchars($p['deskripsi'] ?? 'Deskripsi tidak tersedia.')); ?></p></div>
                        <div><p>Rp <?php echo number_format($p['harga']); ?></p></div>
                    </div>
                <?php endforeach; ?>
            </div>
        </div>
        <div class="form-group"><label for="input_nama_pembeli_baru">Nama Lengkap</label><input type="text" id="input_nama_pembeli_baru" placeholder="Masukkan nama lengkap Anda" required autocomplete="name"></div>
        <div class="form-group"><label for="input_nomor_whatsapp_baru">Nomor WhatsApp</label><input type="tel" id="input_nomor_whatsapp_baru" placeholder="Contoh: 628123456789" required autocomplete="tel"></div>
        <div class="form-group"><label for="input_license_username_baru">Username untuk Login</label><input type="text" id="input_license_username_baru" placeholder="Buat username untuk lisensi Anda" required autocomplete="username"></div>
        <div class="form-group"><label for="input_license_password_baru">Password untuk Login</label><input type="password" id="input_license_password_baru" placeholder="Buat password yang kuat" required autocomplete="new-password"></div>
    </template>
    <template id="template-perpanjang-hwid">
        <div class="form-group"><label for="input_hwid_perpanjang">HWID yang Terdaftar</label><input type="text" id="input_hwid_perpanjang" placeholder="Masukkan HWID yang akan diperpanjang" required></div>
        <div class="form-group"><label>Jumlah Bulan Perpanjangan</label><div class="input-group"><button type="button" class="quantity-btn" data-action="minus">-</button><input type="number" id="input_jumlah_bulan_hwid" value="1" min="1" max="12" class="form-control" readonly><button type="button" class="quantity-btn" data-action="plus">+</button></div></div>
    </template>
    <template id="template-perpanjang-paket">
        <div class="form-group"><label for="input_license_username_perpanjang">Username Akun Anda</label><input type="text" id="input_license_username_perpanjang" placeholder="Masukkan username akun yang akan diperpanjang" required></div>
        <div class="form-group"><label>Jumlah Bulan Perpanjangan</label><div class="input-group"><button type="button" class="quantity-btn" data-action="minus">-</button><input type="number" id="input_jumlah_bulan_paket" value="1" min="1" max="12" class="form-control" readonly><button type="button" class="quantity-btn" data-action="plus">+</button></div></div>
    </template>
    
    <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
    <script>
    document.addEventListener('DOMContentLoaded', function() {
        const wizard={currentStep:1,totalSteps:3,steps:document.querySelectorAll('.wizard-step'),progressSteps:document.querySelectorAll('.progress-step'),progressBar:document.querySelector('.progress-bar-line'),prevBtn:document.getElementById('prev-btn'),nextBtn:document.getElementById('next-btn'),payBtn:document.getElementById('pay-btn'),form:document.getElementById('payment-form'),formTipeOrder:document.getElementById('form_tipe_order'),formRenewalType:document.getElementById('form_renewal_type'),formProdukId:document.getElementById('form_produk_id'),formJumlahBulan:document.getElementById('form_jumlah_bulan'),formNamaPembeli:document.getElementById('form_nama_pembeli'),formNomorWhatsapp:document.getElementById('form_nomor_whatsapp'),formLicenseUsername:document.getElementById('form_license_username'),formLicensePassword:document.getElementById('form_license_password'),formHwid:document.getElementById('form_hwid'),hargaBulanan:<?php echo $harga_bulanan;?>,produkBulananId:<?php echo $produk_bulanan_id;?>,pilihan:{}};function init(){document.querySelectorAll('#step-1 .selection-card').forEach(e=>{e.addEventListener('click',()=>selectChoice(e))});wizard.nextBtn.addEventListener('click',nextStep);wizard.prevBtn.addEventListener('click',prevStep);wizard.form.addEventListener('submit',handleFormSubmit);updateButtons()}function selectChoice(e){document.querySelectorAll('#step-1 .selection-card').forEach(e=>e.classList.remove('selected'));e.classList.add('selected');wizard.pilihan.layanan=e.dataset.choice;updateButtons()}async function nextStep(){if(wizard.currentStep<wizard.totalSteps){if(wizard.currentStep===1){buildStep2()}else if(wizard.currentStep===2){if(!validateStep2()){Swal.fire('Data Belum Lengkap','Silakan isi semua data yang diperlukan.','warning');return}const e=await validateStep2Server();if(!e)return;buildStep3()}wizard.currentStep++;updateWizard()}}function prevStep(){if(wizard.currentStep>1){wizard.currentStep--;updateWizard()}}function updateWizard(){wizard.steps.forEach(e=>e.classList.remove('active'));document.getElementById(`step-${wizard.currentStep}`).classList.add('active');wizard.progressSteps.forEach((e,t)=>{e.classList.toggle('active',t<wizard.currentStep)});const e=(wizard.currentStep-1)/(wizard.totalSteps-1)*100;wizard.progressBar.style.width=`${e}%`;updateButtons()}function updateButtons(){wizard.prevBtn.style.display=wizard.currentStep>1?'inline-block':'none';wizard.nextBtn.style.display=wizard.currentStep<wizard.totalSteps?'inline-block':'none';wizard.payBtn.style.display=wizard.currentStep===wizard.totalSteps?'inline-block':'none';wizard.nextBtn.disabled=wizard.currentStep===1&&!wizard.pilihan.layanan}function buildStep2(){const e=document.getElementById('step-2-title'),t=document.getElementById('step-2-content');let n='';switch(wizard.pilihan.layanan){case'baru':e.textContent='Lengkapi Data Akun Baru';n='template-beli-baru';break;case'perpanjang-hwid':e.textContent='Detail Perpanjangan HWID';n='template-perpanjang-hwid';break;case'perpanjang-paket':e.textContent='Detail Perpanjangan Akun';n='template-perpanjang-paket';break}const a=document.getElementById(n);t.innerHTML=a.innerHTML;attachStep2Listeners();updateButtons()}function attachStep2Listeners(){document.querySelectorAll('#step-2 input').forEach(e=>{e.addEventListener('input',()=>{wizard.nextBtn.disabled=!validateStep2()})});document.querySelectorAll('#step-2 .selection-card').forEach(e=>{e.addEventListener('click',()=>{document.querySelectorAll('#step-2 .selection-card').forEach(e=>e.classList.remove('selected'));e.classList.add('selected');wizard.nextBtn.disabled=!validateStep2()})});document.querySelectorAll('#step-2 .quantity-btn').forEach(e=>{e.addEventListener('click',e=>{const t=e.target.dataset.action,n=e.target.parentElement.querySelector('input[type="number"]');let a=parseInt(n.value,10);if(t==='plus'&&a<12)a++;if(t==='minus'&&a>1)a--;n.value=a;wizard.nextBtn.disabled=!validateStep2()})})}function validateStep2(){let e=!0;const t=document.querySelectorAll('#step-2 input[required]');t.forEach(t=>{if(!t.value.trim())e=!1});if(document.querySelector('#step-2 .product-grid')){if(!document.querySelector('#step-2 .selection-card.selected'))e=!1}return e}
    async function validateStep2Server(){const e=wizard.pilihan.layanan;let t=new FormData;wizard.pilihan.hargaPerpanjanganAkun=null;if(e==='perpanjang-hwid'){const e=document.getElementById('input_hwid_perpanjang').value;t.append('tipe_order','perpanjang-hwid');t.append('hwid',e)}else if(e==='perpanjang-paket'){const e=document.getElementById('input_license_username_perpanjang').value;t.append('tipe_order','perpanjang-paket');t.append('username',e)}else{return!0}wizard.nextBtn.disabled=!0;wizard.nextBtn.textContent='Memvalidasi...';try{const e=wizard.form.querySelector('input[name="csrf_token"]').value,n=await fetch('check_renewal.php',{method:'POST',body:t,headers:{'X-CSRF-TOKEN':e}}),a=await n.json();if(a.success){Swal.fire('Validasi Berhasil',a.message,'success');if(a.harga){wizard.pilihan.hargaPerpanjanganAkun=parseFloat(a.harga)}return!0}else{Swal.fire('Validasi Gagal',a.message,'error');return!1}}catch(e){console.error('Error Validasi:',e);Swal.fire('Kesalahan Jaringan','Tidak dapat terhubung ke server validasi.','error');return!1}finally{wizard.nextBtn.disabled=!1;wizard.nextBtn.textContent='Lanjutkan'}}
    function buildStep3(){const e=wizard.pilihan.layanan;let t="",n="",a="",i=0,s=wizard.produkBulananId;if(e==="baru"){const e=document.querySelector('#step-2 .selection-card.selected');if(e){i=parseInt(e.dataset.harga,10);a=e.dataset.durasi;s=e.dataset.productId}t="Beli Lisensi Baru";const l=document.getElementById('input_nama_pembeli_baru').value,r=document.getElementById('input_nomor_whatsapp_baru').value,o=document.getElementById('input_license_username_baru').value,d=document.getElementById('input_license_password_baru').value;n=o;wizard.formTipeOrder.value="baru";wizard.formProdukId.value=s;wizard.formNamaPembeli.value=l;wizard.formNomorWhatsapp.value=r;wizard.formLicenseUsername.value=o;wizard.formLicensePassword.value=d}else if(e==="perpanjang-hwid"){const e=document.getElementById('input_jumlah_bulan_hwid'),l=parseInt(e.value,10);i=wizard.hargaBulanan*l;a=`${l} Bulan`;t="Perpanjang HWID";const r=document.getElementById('input_hwid_perpanjang').value;n=`HWID: ...${r.slice(-6)}`;wizard.formTipeOrder.value="perpanjang";wizard.formProdukId.value=wizard.produkBulananId;wizard.formJumlahBulan.value=l;wizard.formRenewalType.value="hwid";wizard.formHwid.value=r}else if(e==="perpanjang-paket"){const e=document.getElementById('input_jumlah_bulan_paket'),l=parseInt(e.value,10),r=wizard.pilihan.hargaPerpanjanganAkun||wizard.hargaBulanan;i=r*l;t="Perpanjang Akun";const o=document.getElementById('input_license_username_perpanjang').value;n=`Username: ${o}`;a=`${l} Bulan`;wizard.formTipeOrder.value="perpanjang";wizard.formRenewalType.value="session";wizard.formProdukId.value=wizard.produkBulananId;wizard.formJumlahBulan.value=l;wizard.formLicenseUsername.value=o}document.getElementById('summary-layanan').textContent=t;document.getElementById('summary-detail').textContent=n;document.getElementById('summary-durasi').textContent=a;document.getElementById('summary-total').textContent='Rp '+new Intl.NumberFormat('id-ID').format(i)}
    async function handleFormSubmit(e){e.preventDefault();const t=document.getElementById('pay-btn'),n=t.textContent;t.textContent='Memproses...';t.disabled=!0;const a=new FormData(wizard.form);try{const e=wizard.form.querySelector('input[name="csrf_token"]').value,i=await fetch('proses_pembayaran.php',{method:'POST',body:a,headers:{'X-CSRF-TOKEN':e}}),s=await i.json();if(!i.ok||!s.success){Swal.fire({icon:'error',title:'Oops... Terjadi Kesalahan',text:s.message||'Gagal memproses permintaan.'});t.textContent=n;t.disabled=!1;return}if(s.success&&s.snap_token){snap.pay(s.snap_token,{onSuccess:function(e){window.location.href='/halaman-sukses.html'},onPending:function(e){Swal.fire('Pembayaran Tertunda','Silakan selesaikan pembayaran Anda.','info')},onError:function(e){Swal.fire('Pembayaran Gagal','Terjadi kesalahan saat pemrosesan.','error')},onClose:function(){Swal.fire('Pembayaran Dibatalkan','Anda menutup jendela pembayaran.','warning');t.textContent=n;t.disabled=!1}})}}catch(e){console.error('Fetch Error:',e);Swal.fire({icon:'error',title:'Kesalahan Jaringan',text:'Tidak dapat terhubung ke server. Periksa konsol browser (F12) untuk detail.'});t.textContent=n;t.disabled=!1}}
    init()});
    </script>
</body>
</html>
<?php $conn->close(); ?>