using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using ICSharpCode.SharpZipLib.Zip;
using Newtonsoft.Json.Linq;
using HWID___Joshhh.Module;
using Tulpep.NotificationWindow; 
using System.Drawing;
using System.Diagnostics;
using System.Reflection;

namespace HWID___Joshhh
{
    public partial class Form1 : Form
    {
        private readonly HttpClient httpClient;

        // --- KONFIGURASI API ---
        private const string BaseUrl = "https://jcetools.my.id/api/";
        private const string SessionKeyUrl = BaseUrl + "auth/get-session-key.php";
        private const string HwidCheckUrl = BaseUrl + "1.php";
        private const string FreeStatusUrl = "https://webtechsolution.my.id/Free/status";
        private const string FreeDownloadUrl = "https://webtechsolution.my.id/Free/Gratis.zip";
        private const string NewsFileUrl = "https://jcetools.my.id/api/UpdaterNews.txt";

        // --- DRAG WINDOW LOGIC ---
        [DllImport("user32.dll")] public static extern int SendMessage(IntPtr hWnd, int Msg, int wParam, int lParam);
        [DllImport("user32.dll")] public static extern bool ReleaseCapture();
        public const int WM_NCLBUTTONDOWN = 0xA1;
        public const int HT_CAPTION = 0x2;

        private string NamaUser { get; set; }
        private string ClientKey { get; set; }
        private string SecretKey { get; set; }
        private string MaintenanceStatus { get; set; }
        private string ButtonCustom1 { get; set; }
        private string ExpiryDate { get; set; }

        public Form1()
        {
            InitializeComponent();
            InitializeModernUI();

            // 1. SET TLS KEAMANAN
            try
            {
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            }
            catch (Exception ex)
            {
                MessageBox.Show("Gagal set TLS: " + ex.Message);
            }

            // 2. SETUP HTTP CLIENT
            httpClient = new HttpClient();
            httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36");

            // 3. TAMPILKAN VERSI DI JUDUL APLIKASI (Opsional tapi Pro)
            this.Text = $"JCE Updater v{AutoUpdater.CurrentVersion}";

            // 4. SAMBUNGKAN EVENT LOAD SECARA MANUAL
            // (Karena tidak ada Form1_Load di designer, kita pasang lewat kodingan ini)
            this.Load += Form1_Load;

            HWIDHelper.DisplayVolumeSerialNumber();
        }

        // --- INI FUNGSI BARU YANG KITA BUAT ---
        private void Form1_Load(object sender, EventArgs e)
        {
            // A. Cek Update Otomatis di Background
            // Kita pakai Task.Run supaya aplikasi tidak macet saat cek update
            _ = Task.Run(async () => await AutoUpdater.CheckForUpdateAsync());

            // B. Jalankan Proses Login/Startup
            HandleStartupAsync();
        }

        // --- UI EVENTS ---
        private void pnlHeader_MouseDown(object sender, MouseEventArgs e) { if (e.Button == MouseButtons.Left) { ReleaseCapture(); SendMessage(Handle, WM_NCLBUTTONDOWN, HT_CAPTION, 0); } }
        private void btnClose_Click(object sender, EventArgs e) { Application.Exit(); }
        private void btnMinimize_Click(object sender, EventArgs e) { this.WindowState = FormWindowState.Minimized; }

        private void InitializeModernUI()
        {
            this.btnDownloadUser.Click += async (s, e) => await ButtonDownloadUser_Click();
            this.btnBuyAccess.Click += (s, e) => OpenWhatsapp();
            this.btnDownloadFree.Click += async (s, e) => await ButtonDownloadFree_Click();
            progressBar.Visible = false;
        }

        private async void HandleStartupAsync()
        {
            // Tes Koneksi Internet dulu
            if (!await InternetHelper.CheckInternetConnectionAsync())
            {
                MessageBox.Show("DEBUG: Tidak ada koneksi internet.", "Gagal Step 0", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetInvalidHwidUI();
            }
            else
            {
                StartHwidCheckLoop();
            }
        }

        // =========================================================================
        // LOGIKA UTAMA DENGAN POP-UP DEBUG DI SETIAP BARIS
        // =========================================================================

        private async Task InitializeUserSessionAsync()
        {
            try
            {
                // STEP 1: Cek HWID Lokal
                uint hwid = HWIDHelper.GetVolumeSerialNumberFromCurrentDrive();
                if (hwid == 0)
                {
                    // Error fatal tetap pakai MessageBox biar user sadar
                    MessageBox.Show("Error: Gagal membaca HWID Komputer.", "Error Hardware", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    SetInvalidHwidUI(); return;
                }

                // Ganti status label saja, jangan popup
                Invoke((MethodInvoker)delegate { lblStatus.Text = "Menghubungkan ke server..."; });

                // STEP 2: Minta Token ke Server
                string sessionToken = await GetSessionTokenAsync();
                if (string.IsNullOrEmpty(sessionToken))
                {
                    // GANTI MESSAGEBOX DENGAN TOAST ERROR
                    ToastHelper.ShowError("Koneksi Gagal", "Gagal terhubung ke server.");
                    SetInvalidHwidUI(); return;
                }

                // STEP 3: Parse Token JWT
                var sessionData = ParseJwtToken(sessionToken);
                if (!sessionData.IsValid)
                {
                    SetInvalidHwidUI(); return;
                }

                // STEP 4: Enkripsi HWID
                string encryptedHwid = EncryptHwidWithSession(hwid.ToString(), sessionData.KeyHex, sessionData.IvHex);

                // STEP 5: Kirim ke 1.php
                string response = await CheckHWIDWithToken(encryptedHwid, sessionToken);
                if (string.IsNullOrEmpty(response))
                {
                    ToastHelper.ShowError("Server Error", "Server tidak merespon.");
                    SetInvalidHwidUI(); return;
                }

                // STEP 6: Baca JSON
                JObject jsonResponse = JObject.Parse(response);
                string status = (string)jsonResponse["status"];

                if (status == "success")
                {
                    // --- INI BAGIAN PALING KEREN ---
                    // Saat sukses, muncul notifikasi halus di pojok kanan bawah
                    string userName = (string)jsonResponse["user"];
                    ToastHelper.ShowSuccess("Login Berhasil", $"Selamat datang, {userName}!");

                    SetValidHwidUI(jsonResponse);

                    // Suara 'Tring' Windows (Opsional)
                    System.Media.SystemSounds.Asterisk.Play();
                }
                else
                {
                    string msg = (string)jsonResponse["message"] ?? "Akses Ditolak.";
                    // Muncul notifikasi error merah
                    ToastHelper.ShowError("Akses Ditolak", msg);
                    SetInvalidHwidUI();
                }
            }
            catch (Exception ex)
            {
                // Error coding/crash
                ToastHelper.ShowError("System Crash", ex.Message);
                SetInvalidHwidUI();
            }
        }

        private async Task<string> GetSessionTokenAsync()
        {
            try
            {
                var response = await httpClient.GetStringAsync(SessionKeyUrl);
                // Cek apakah responnya HTML error atau JSON valid
                if (response.Trim().StartsWith("<"))
                {
                    MessageBox.Show("DEBUG TOKEN ERROR: Server mengembalikan HTML (bukan JSON).\nKemungkinan Error 404/500 atau Salah URL.", "API Error");
                    return null;
                }

                var json = JObject.Parse(response);
                if ((string)json["status"] == "success") return (string)json["session_token"];
            }
            catch (Exception ex) { MessageBox.Show("DEBUG EX TOKEN: " + ex.Message); }
            return null;
        }

        private class SessionData { public string KeyHex; public string IvHex; public bool IsValid; }

        private SessionData ParseJwtToken(string token)
        {
            var data = new SessionData { IsValid = false };
            try
            {
                var parts = token.Split('.');
                if (parts.Length < 2) return data;

                string payload = parts[1];
                switch (payload.Length % 4) { case 2: payload += "=="; break; case 3: payload += "="; break; }

                var jsonBytes = Convert.FromBase64String(payload.Replace('-', '+').Replace('_', '/'));
                var json = JObject.Parse(Encoding.UTF8.GetString(jsonBytes));

                data.KeyHex = (string)json["key"];
                data.IvHex = (string)json["iv"];
                if (!string.IsNullOrEmpty(data.KeyHex)) data.IsValid = true;
            }
            catch (Exception ex) { MessageBox.Show("DEBUG EX PARSE: " + ex.Message); }
            return data;
        }

        private string EncryptHwidWithSession(string plainText, string keyHex, string ivHex)
        {
            try
            {
                byte[] key = HexStringToByteArray(keyHex);
                byte[] iv = HexStringToByteArray(ivHex);
                byte[] inputBytes = Encoding.UTF8.GetBytes(plainText); // Penting: UTF8 GetBytes
                byte[] encrypted;

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;

                    using (var encryptor = aes.CreateEncryptor())
                    using (var ms = new MemoryStream())
                    {
                        using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                        {
                            cs.Write(inputBytes, 0, inputBytes.Length);
                            cs.FlushFinalBlock();
                            encrypted = ms.ToArray();
                        }
                    }
                }
                return BitConverter.ToString(encrypted).Replace("-", "").ToLower();
            }
            catch (Exception ex)
            {
                MessageBox.Show("DEBUG EX ENCRYPT: " + ex.Message);
                return "";
            }
        }

        private async Task<string> CheckHWIDWithToken(string encryptedHwid, string token)
        {
            try
            {
                string jsonData = $"{{\"hwid\":\"{encryptedHwid}\"}}";
                var content = new StringContent(jsonData, Encoding.UTF8, "application/json");

                if (httpClient.DefaultRequestHeaders.Contains("Authorization"))
                    httpClient.DefaultRequestHeaders.Remove("Authorization");
                httpClient.DefaultRequestHeaders.TryAddWithoutValidation("Authorization", "Bearer " + token);

                var response = await httpClient.PostAsync(HwidCheckUrl, content);

                if (!response.IsSuccessStatusCode)
                {
                    MessageBox.Show($"DEBUG HTTP ERROR: {(int)response.StatusCode} {response.ReasonPhrase}\nURL: {HwidCheckUrl}");
                    return null;
                }
                return await response.Content.ReadAsStringAsync();
            }
            catch (Exception ex)
            {
                MessageBox.Show("DEBUG EX POST: " + ex.Message);
                return null;
            }
        }

        public static byte[] HexStringToByteArray(string hex)
        {
            try
            {
                int NumberChars = hex.Length;
                byte[] bytes = new byte[NumberChars / 2];
                for (int i = 0; i < NumberChars; i += 2)
                    bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
                return bytes;
            }
            catch { return new byte[0]; }
        }

        // --- UI HELPERS ---
        private void SetValidHwidUI(JObject json)
        {
            Invoke((MethodInvoker)delegate {
                // 1. Parsing Data
                this.NamaUser = (string)json["user"] ?? "User";
                this.ClientKey = (string)json["sk"];
                this.SecretKey = (string)json["sck"];
                this.MaintenanceStatus = (string)json["maintenance"];
                this.ButtonCustom1 = (string)json["status1_text"];
                this.ExpiryDate = (string)json["expiry_date"];

                // 2. Hitung License
                string expiryText = "Active";
                Color licenseColor = Color.FromArgb(100, 255, 100);

                if (DateTime.TryParse(this.ExpiryDate, out DateTime dt))
                {
                    int daysLeft = (int)(dt.Date - DateTime.Today).TotalDays;
                    if (dt.Year > 2035)
                    {
                        expiryText = "Lifetime (Permanent)";
                        licenseColor = Color.Gold;
                    }
                    else
                    {
                        expiryText = $"{daysLeft} Hari Tersisa";
                        if (daysLeft < 3) licenseColor = Color.Red;
                    }
                }

                // 3. Update UI Dasar
                lblExpiryDate.Text = $"License: {expiryText}";
                lblExpiryDate.ForeColor = licenseColor;
                lblWelcomeUser.Text = $"Hi, {NamaUser}!";
                lblVersion.Text = $"v{AutoUpdater.CurrentVersion} | Online";
                btnDownloadCustom.Text = string.IsNullOrEmpty(ButtonCustom1) ? "Extra Files" : ButtonCustom1;
                lblStatus.Text = "Connected. Ready to launch.";

                // 4. Siapkan Header Berita (Bagian Atas Tetap)
                string headerInfo = $"[SYSTEM INFO]\n" +
                                    $"User Logged : {NamaUser}\n" +
                                    $"License Type: {expiryText}\n" +
                                    $"Server Time : {DateTime.Now.ToString("HH:mm")}\n\n";

                // Tampilkan loading dulu biar user tau sistem sedang bekerja
                rtbNews.Text = headerInfo + "[CHANGELOG]\nLoading server news...";

                // 5. Download Berita dari Server (Async / Background)
                // Kita gunakan Task.Run agar UI tidak macet saat download teks
                Task.Run(async () =>
                {
                    string serverNewsContent = "";
                    try
                    {
                        // Ambil text dari UpdaterNews.txt
                        serverNewsContent = await httpClient.GetStringAsync(NewsFileUrl);
                    }
                    catch
                    {
                        serverNewsContent = "- Gagal memuat berita dari server.\n- Cek koneksi internet Anda.";
                    }

                    // Update UI RichTextBox lagi setelah download selesai
                    Invoke((MethodInvoker)delegate {
                        rtbNews.Text = headerInfo + "[CHANGELOG]\n" + serverNewsContent.Trim();
                    });
                });

                // 6. Tampilkan Panel
                pnlInvalidUser.Visible = false;
                pnlValidUser.Visible = true;
                pnlValidUser.BringToFront();
            });
        }

        private void SetInvalidHwidUI()
        {
            Invoke((MethodInvoker)delegate {
                Text = "JCE Updater - Akses Ditolak";
                if (lblTitle != null) lblTitle.Text = "JCE Updater - Akses Ditolak";
                pnlValidUser.Visible = false;
                pnlInvalidUser.Visible = true;
                pnlInvalidUser.BringToFront();
                lblStatus.Text = "HWID tidak terdaftar atau sesi habis.";
            });
        }

        // --- FITUR UTAMA LAINNYA ---
        private async Task ButtonDownloadUser_Click()
        {
            if (MaintenanceStatus == "yes") { MessageBox.Show("Sedang Maintenance."); return; }
            await DownloadFromS3();
        }

        private async Task DownloadFromS3()
        {
            // --- PERUBAHAN KEAMANAN DI SINI ---
            // Kita panggil KeyGuardian, bukan menulis byte manual
            byte[] sKey = KeyGuardian.GetMainKey();
            byte[] sIv = KeyGuardian.GetIV();
            // ----------------------------------

            try
            {
                if (string.IsNullOrEmpty(ClientKey))
                {
                    MessageBox.Show("Akun aktif tapi kunci S3 kosong.", "Info");
                    return;
                }

                // Dekripsi kunci yang didapat dari JSON server
                string dClient = EncryptionHelper.DecryptString(ClientKey, sKey, sIv) ?? ClientKey;
                string dSecret = EncryptionHelper.DecryptString(SecretKey, sKey, sIv) ?? SecretKey;

                // Proses Download
                var s3 = new S3Helper(dClient, dSecret, "https://s3.nevaobjects.id/");
                string path = $"jce-tools-bucket/{NamaUser}.zip";

                SetProgress(0, "Mengunduh file Custom User...");

                // Mulai Download
                await s3.DownloadAndExtractZipAsync(
                    path.Split('/')[0],
                    path.Substring(path.IndexOf('/') + 1),
                    AppDomain.CurrentDomain.BaseDirectory,
                    p => Invoke((MethodInvoker)(() => SetProgress(p, null)))
                );

                SetComplete("Update Selesai!");
            }
            catch (Exception ex)
            {
                MessageBox.Show("S3 Error: " + ex.Message);
                SetError("Gagal mengunduh file.");
            }
        }

        private async Task ButtonDownloadFree_Click()
        {
            try
            {
                if ((await httpClient.GetStringAsync(FreeStatusUrl)).Trim().ToLower() != "true") { MessageBox.Show("Fitur Gratis Nonaktif."); return; }
                await DownloadAndExtractZipFromUrl(FreeDownloadUrl, "Update Gratis Selesai!");
            }
            catch { SetError("Gagal Cek Gratis."); }
        }

        private async Task DownloadAndExtractZipFromUrl(string url, string msg)
        {
            try
            {
                SetProgress(0, "Mengunduh...");
                using (var resp = await httpClient.GetAsync(url))
                {
                    using (var fs = await resp.Content.ReadAsStreamAsync())
                    using (var ms = new MemoryStream())
                    {
                        await fs.CopyToAsync(ms);
                        ms.Seek(0, SeekOrigin.Begin);
                        using (var zip = new ZipInputStream(ms))
                        {
                            ZipEntry e; while ((e = zip.GetNextEntry()) != null)
                            {
                                string p = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, e.Name);
                                if (e.IsDirectory || !Path.GetFullPath(p).StartsWith(AppDomain.CurrentDomain.BaseDirectory)) continue;
                                Directory.CreateDirectory(Path.GetDirectoryName(p));
                                using (var f = File.Create(p)) zip.CopyTo(f);
                            }
                        }
                    }
                }
                SetComplete(msg);
            }
            catch { SetError("Gagal Download URL."); }
        }

        private void OpenWhatsapp()
        {
            uint hwid = HWIDHelper.GetVolumeSerialNumberFromCurrentDrive();
            string link = $"https://api.whatsapp.com/send?phone=6287775216846&text=Hallo%20Saya%20Mau%20daftar%20cheat%2C%20ini%20hwid%20saya%20%5B{hwid}%5D";
            try { System.Diagnostics.Process.Start(link); } catch { }
        }

        private void StartAntiDebuggingCheck() => Task.Run(async () => { while (true) { AntiDebug.CheckForDebuggers(); await Task.Delay(5000); } });
        private async void StartHwidCheckLoop() { await InitializeUserSessionAsync(); _ = Task.Run(async () => { while (true) { await Task.Delay(TimeSpan.FromMinutes(2)); await InitializeUserSessionAsync(); } }); }
        private void SetProgress(int v, string m) { progressBar.Visible = true; progressBar.Value = v; if (m != null) lblStatus.Text = m; }
        private void SetComplete(string m) { progressBar.Visible = false; MessageBox.Show(m, "Sukses", MessageBoxButtons.OK, MessageBoxIcon.Information); lblStatus.Text = "Siap."; }
        private void SetError(string m) { progressBar.Visible = false; MessageBox.Show(m, "Gagal", MessageBoxButtons.OK, MessageBoxIcon.Error); }
    }

    public static class KeyGuardian
    {
        public static byte[] GetMainKey()
        {
            // Kunci Asli: "JCETOOLS-1830"
            // Kita pecah biar tidak terbaca sebagai teks utuh di dalam file EXE
            string part1 = "JCE";
            string part2 = "TOOLS";
            string dash = "-";
            // Hitungan matematika sederhana untuk angka 1830
            int num = (900 * 2) + 30;

            string fullKey = part1 + part2 + dash + num.ToString();
            return System.Text.Encoding.ASCII.GetBytes(fullKey);
        }

        public static byte[] GetIV()
        {
            // IV Asli: { 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78 }
            // Kita buat loop untuk generate ini, jadi hacker bingung melihat kodenya
            byte[] hiddenIV = new byte[12];

            // Pola 1: 0x12, 0x34, 0x56, 0x78
            hiddenIV[0] = 0x12; hiddenIV[1] = 0x34; hiddenIV[2] = 0x56; hiddenIV[3] = 0x78;

            // Pola 2: 0x90, 0xAB, 0xCD, 0xEF
            hiddenIV[4] = 0x90; hiddenIV[5] = 0xAB; hiddenIV[6] = 0xCD; hiddenIV[7] = 0xEF;

            // Ulangi Pola 1 untuk sisanya
            hiddenIV[8] = 0x12; hiddenIV[9] = 0x34; hiddenIV[10] = 0x56; hiddenIV[11] = 0x78;

            return hiddenIV;
        }
    }

    public static class ToastHelper
    {
        public static void ShowSuccess(string title, string message)
        {
            PopupNotifier popup = new PopupNotifier();

            // 1. FONT MODERN
            popup.TitleFont = new Font("Segoe UI", 11, FontStyle.Bold);
            popup.ContentFont = new Font("Segoe UI", 10);

            // 2. WARNA (Dark Modern)
            Color darkBackground = Color.FromArgb(32, 32, 32);
            Color successGreen = Color.FromArgb(76, 175, 80);

            popup.BodyColor = darkBackground;
            popup.ContentColor = Color.White;
            popup.TitleColor = successGreen;
            popup.BorderColor = successGreen;

            // --- PERBAIKAN BUG CRASH DI SINI ---
            // Jangan set HeaderHeight = 0. Set ke 1, tapi warnanya samakan dengan body.
            popup.HeaderHeight = 1;
            popup.HeaderColor = darkBackground; // Kamuflase header biar ga kelihatan
                                                // ------------------------------------

            // 3. ICON & TEXT
            popup.Image = null; // Ganti dengan Properties.Resources.icon_success jika sudah ada gambar
            popup.TitleText = title;
            popup.ContentText = message;

            // 4. UKURAN & POSISI
            popup.Size = new Size(350, 90);
            popup.ContentPadding = new Padding(10);
            popup.TitlePadding = new Padding(10);

            popup.AnimationDuration = 500;
            popup.ShowOptionsButton = false;
            popup.ShowGrip = false;

            popup.Popup();
        }

        public static void ShowError(string title, string message)
        {
            PopupNotifier popup = new PopupNotifier();

            // Font
            popup.TitleFont = new Font("Segoe UI", 11, FontStyle.Bold);
            popup.ContentFont = new Font("Segoe UI", 10);

            // Warna
            Color darkBackground = Color.FromArgb(32, 32, 32);
            Color errorRed = Color.FromArgb(244, 67, 54);

            popup.BodyColor = darkBackground;
            popup.ContentColor = Color.White;
            popup.TitleColor = errorRed;
            popup.BorderColor = errorRed;

            // --- PERBAIKAN BUG CRASH DI SINI ---
            popup.HeaderHeight = 1;
            popup.HeaderColor = darkBackground;
            // ------------------------------------

            popup.Image = null; // Ganti dengan Properties.Resources.icon_error jika sudah ada gambar
            popup.TitleText = title;
            popup.ContentText = message;

            popup.Size = new Size(350, 90);
            popup.ContentPadding = new Padding(10);
            popup.TitlePadding = new Padding(10);

            popup.AnimationDuration = 500;
            popup.ShowOptionsButton = false;
            popup.ShowGrip = false;

            popup.Popup();
        }
    }

    public static class AutoUpdater
    {
        // --- KONFIGURASI UPDATE ---
        // Ganti URL ini dengan lokasi file hackupdater.txt kamu
        private const string VersionFileUrl = "https://jcetools.my.id/api/hackupdater.txt";

        // Ganti URL ini dengan lokasi file .exe terbaru yang akan didownload
        private const string ExeDownloadUrl = "https://jcetools.my.id/api/JCE_Updater_Latest.exe";

        // Versi Aplikasi Saat Ini (Harus diganti manual setiap kamu compile update baru)
        public const string CurrentVersion = "1.5";

        public static async Task CheckForUpdateAsync()
        {
            try
            {
                using (HttpClient client = new HttpClient())
                {
                    // 1. Ambil teks versi dari server
                    string serverVersionText = await client.GetStringAsync(VersionFileUrl);
                    serverVersionText = serverVersionText.Trim(); // Hilangkan spasi/enter

                    // 2. Bandingkan Versi
                    Version serverVer = new Version(serverVersionText);
                    Version localVer = new Version(CurrentVersion);

                    if (serverVer > localVer)
                    {
                        // ADA UPDATE BARU!
                        DialogResult ask = MessageBox.Show(
                            $"Update Tersedia!\n\nVersi Lama: {localVer}\nVersi Baru: {serverVer}\n\nApakah Anda ingin update sekarang?",
                            "System Update",
                            MessageBoxButtons.YesNo,
                            MessageBoxIcon.Question
                        );

                        if (ask == DialogResult.Yes)
                        {
                            await PerformUpdate(client);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                // Silent fail (jangan ganggu user kalau gagal cek update)
                // Atau bisa log ke console: Console.WriteLine("Update Check Failed: " + ex.Message);
            }
        }

        private static async Task PerformUpdate(HttpClient client)
        {
            string tempFileName = "update_temp.exe";
            string currentExe = AppDomain.CurrentDomain.FriendlyName; // Nama file exe saat ini

            try
            {
                // 1. Download File Baru ke nama sementara
                ToastHelper.ShowSuccess("Updating...", "Sedang mendownload versi terbaru...");

                byte[] fileBytes = await client.GetByteArrayAsync(ExeDownloadUrl);
                File.WriteAllBytes(tempFileName, fileBytes);

                // 2. Buat Script .bat untuk proses penggantian file
                // Script ini akan: Tunggu 2 detik -> Hapus EXE lama -> Rename EXE baru -> Jalankan -> Hapus diri sendiri
                string batchScriptName = "updater.bat";
                string batchScript = $@"
@echo off
timeout /t 2 /nobreak > NUL
del ""{currentExe}""
ren ""{tempFileName}"" ""{currentExe}""
start "" "" ""{currentExe}""
del ""%~f0""
";
                File.WriteAllText(batchScriptName, batchScript);

                // 3. Jalankan Script dan Matikan Aplikasi ini
                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = batchScriptName,
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    WindowStyle = ProcessWindowStyle.Hidden
                };

                Process.Start(psi);
                Application.Exit(); // Tutup aplikasi segera
            }
            catch (Exception ex)
            {
                ToastHelper.ShowError("Update Gagal", "Gagal melakukan update otomatis.\n" + ex.Message);
                if (File.Exists(tempFileName)) File.Delete(tempFileName);
            }
        }
    }
}
