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
            catch
            {
                // Silent catch: Jika gagal set TLS, biarkan default sistem berjalan
            }

            // 2. SETUP HTTP CLIENT
            httpClient = new HttpClient();
            httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36");

            // 3. TAMPILKAN VERSI
            this.Text = $"JCE Updater v{AutoUpdater.CurrentVersion}";

            // 4. LOAD EVENT
            this.Load += Form1_Load;

            HWIDHelper.DisplayVolumeSerialNumber();
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            // A. Cek Update Otomatis di Background
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
            // Tes Koneksi Internet
            if (!await InternetHelper.CheckInternetConnectionAsync())
            {
                ToastHelper.ShowError("Koneksi Error", "Tidak ada koneksi internet. Periksa jaringan Anda.");
                SetInvalidHwidUI();
            }
            else
            {
                StartHwidCheckLoop();
            }
        }

        // =========================================================================
        // LOGIKA UTAMA
        // =========================================================================

        private async Task InitializeUserSessionAsync()
        {
            try
            {
                // STEP 1: Cek HWID Lokal
                uint hwid = HWIDHelper.GetVolumeSerialNumberFromCurrentDrive();
                if (hwid == 0)
                {
                    ToastHelper.ShowError("System Error", "Gagal membaca ID Perangkat.");
                    SetInvalidHwidUI(); return;
                }

                Invoke((MethodInvoker)delegate { lblStatus.Text = "Menghubungkan ke server..."; });

                // STEP 2: Minta Token
                string sessionToken = await GetSessionTokenAsync();
                if (string.IsNullOrEmpty(sessionToken))
                {
                    lblStatus.Text = "Gagal terhubung ke server auth.";
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
                    lblStatus.Text = "Server tidak merespon.";
                    SetInvalidHwidUI(); return;
                }

                // STEP 6: Baca JSON
                JObject jsonResponse;
                try
                {
                    jsonResponse = JObject.Parse(response);
                }
                catch
                {
                    SetInvalidHwidUI(); return;
                }

                string status = (string)jsonResponse["status"];

                if (status == "success")
                {
                    string userName = (string)jsonResponse["user"];
                    ToastHelper.ShowSuccess("Login Berhasil", $"Selamat datang, {userName}!");

                    SetValidHwidUI(jsonResponse);

                    System.Media.SystemSounds.Asterisk.Play();
                }
                else
                {
                    string msg = (string)jsonResponse["message"] ?? "Akses Ditolak.";
                    ToastHelper.ShowError("Akses Ditolak", msg);
                    SetInvalidHwidUI();
                }
            }
            catch (Exception)
            {
                ToastHelper.ShowError("Aplikasi Error", "Terjadi kesalahan sistem. Silakan restart aplikasi.");
                SetInvalidHwidUI();
            }
        }

        private async Task<string> GetSessionTokenAsync()
        {
            try
            {
                var response = await httpClient.GetStringAsync(SessionKeyUrl);
                if (response.Trim().StartsWith("<")) return null;

                var json = JObject.Parse(response);
                if ((string)json["status"] == "success") return (string)json["session_token"];
            }
            catch { /* Silent Fail */ }
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
            catch { /* Silent Fail */ }
            return data;
        }

        private string EncryptHwidWithSession(string plainText, string keyHex, string ivHex)
        {
            try
            {
                byte[] key = HexStringToByteArray(keyHex);
                byte[] iv = HexStringToByteArray(ivHex);
                byte[] inputBytes = Encoding.UTF8.GetBytes(plainText);
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
            catch
            {
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

                if (!response.IsSuccessStatusCode) return null;

                return await response.Content.ReadAsStringAsync();
            }
            catch
            {
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
                this.NamaUser = (string)json["user"] ?? "User";
                this.ClientKey = (string)json["sk"];
                this.SecretKey = (string)json["sck"];
                this.MaintenanceStatus = (string)json["maintenance"];
                this.ButtonCustom1 = (string)json["status1_text"];
                this.ExpiryDate = (string)json["expiry_date"];

                string expiryText = "Active";
                Color licenseColor = Color.FromArgb(100, 255, 100);

                if (DateTime.TryParse(this.ExpiryDate, out DateTime dt))
                {
                    int daysLeft = (int)(dt.Date - DateTime.Today).TotalDays;
                    if (dt.Year > 2035)
                    {
                        expiryText = "Lifetime";
                        licenseColor = Color.Gold;
                    }
                    else
                    {
                        expiryText = $"{daysLeft} Hari Tersisa";
                        if (daysLeft < 3) licenseColor = Color.Red;
                    }
                }

                lblExpiryDate.Text = $"License: {expiryText}";
                lblExpiryDate.ForeColor = licenseColor;
                lblWelcomeUser.Text = $"Hi, {NamaUser}!";
                lblVersion.Text = $"v{AutoUpdater.CurrentVersion} | Online";
                btnDownloadCustom.Text = string.IsNullOrEmpty(ButtonCustom1) ? "Extra Files" : ButtonCustom1;
                lblStatus.Text = "Connected.";

                string headerInfo = $"[SYSTEM INFO]\n" +
                                    $"User Logged : {NamaUser}\n" +
                                    $"License Type: {expiryText}\n" +
                                    $"Server Time : {DateTime.Now.ToString("HH:mm")}\n\n";

                rtbNews.Text = headerInfo + "[CHANGELOG]\nLoading info...";

                Task.Run(async () =>
                {
                    string serverNewsContent = "";
                    try
                    {
                        serverNewsContent = await httpClient.GetStringAsync(NewsFileUrl);
                    }
                    catch
                    {
                        serverNewsContent = "- Gagal memuat berita server.";
                    }

                    Invoke((MethodInvoker)delegate {
                        rtbNews.Text = headerInfo + "[CHANGELOG]\n" + serverNewsContent.Trim();
                    });
                });

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

        // =========================================================
        // FUNGSI UNTUK MEMATIKAN PROCESS YANG SEDANG BERJALAN
        // =========================================================
        private void KillRunningInjector(string processNameWithoutExtension)
        {
            try
            {
                Process[] processes = Process.GetProcessesByName(processNameWithoutExtension);
                foreach (Process proc in processes)
                {
                    proc.Kill();
                    proc.WaitForExit(1000);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Gagal mematikan proses: " + ex.Message);
            }
        }

        // --- FITUR UTAMA LAINNYA ---
        private async Task ButtonDownloadUser_Click()
        {
            if (MaintenanceStatus == "yes") { MessageBox.Show("Server sedang Maintenance, coba lagi nanti.", "Info"); return; }
            await DownloadFromS3();
        }

        private async Task DownloadFromS3()
        {
            // 1. Matikan Injector jika masih berjalan
            KillRunningInjector("JCE Launcher v1.5");

            // 2. [FIX PENTING] Hapus atribut 'System' & 'Hidden' dari cacert.pem agar bisa ditimpa.
            //    Injector C++ Anda membuat file ini menjadi hidden/system, yang menyebabkan error 'Access Denied'.
            string certPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "cacert.pem");
            if (File.Exists(certPath))
            {
                try
                {
                    // Reset atribut ke Normal agar bisa ditimpa
                    File.SetAttributes(certPath, FileAttributes.Normal);
                }
                catch
                {
                    // Abaikan jika gagal (misal file sedang digunakan, meski sudah di-kill)
                }
            }

            await Task.Delay(500);

            // --- KEAMANAN S3: Ambil Key dari Guardian ---
            byte[] sKey = KeyGuardian.GetMainKey();
            byte[] sIv = KeyGuardian.GetIV();

            try
            {
                if (string.IsNullOrEmpty(ClientKey))
                {
                    MessageBox.Show("Terjadi kesalahan konfigurasi akun (Key Missing). Hubungi Admin.", "Gagal");
                    return;
                }

                string dClient = EncryptionHelper.DecryptString(ClientKey, sKey, sIv) ?? ClientKey;
                string dSecret = EncryptionHelper.DecryptString(SecretKey, sKey, sIv) ?? SecretKey;

                var s3 = new S3Helper(dClient, dSecret, "https://s3.nevaobjects.id/");
                string bucketName = "jce-tools-bucket";
                string objectName = $"{NamaUser}.zip";

                SetProgress(0, "Mempersiapkan download...");

                await s3.DownloadAndExtractZipAsync(
                    bucketName,
                    objectName,
                    AppDomain.CurrentDomain.BaseDirectory,
                    p => Invoke((MethodInvoker)(() => SetProgress(p, null)))
                );

                SetComplete("File berhasil diperbarui!");
            }
            catch (Exception)
            {
                // CLEAN: Sembunyikan pesan error ASLI S3 dari user
                SetError("Gagal mengunduh file aset.\nPeriksa koneksi internet atau hubungi Admin.");
            }
        }

        private async Task ButtonDownloadFree_Click()
        {
            try
            {
                if ((await httpClient.GetStringAsync(FreeStatusUrl)).Trim().ToLower() != "true") { MessageBox.Show("Fitur Gratis saat ini tidak tersedia.", "Info"); return; }
                await DownloadAndExtractZipFromUrl(FreeDownloadUrl, "Update Gratis Selesai!");
            }
            catch { SetError("Gagal mengunduh file gratis."); }
        }

        private async Task DownloadAndExtractZipFromUrl(string url, string msg)
        {
            try
            {
                SetProgress(0, "Mengunduh...");

                using (var resp = await httpClient.GetAsync(url))
                {
                    if (!resp.IsSuccessStatusCode) throw new Exception("HTTP Error");

                    using (var fs = await resp.Content.ReadAsStreamAsync())
                    using (var ms = new MemoryStream())
                    {
                        await fs.CopyToAsync(ms);
                        ms.Seek(0, SeekOrigin.Begin);

                        if (ms.Length == 0) throw new Exception("File kosong.");

                        SetProgress(50, "Mengekstrak...");

                        try
                        {
                            using (var zip = new ZipInputStream(ms))
                            {
                                ZipEntry e;
                                while ((e = zip.GetNextEntry()) != null)
                                {
                                    string p = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, e.Name);

                                    // Validasi Path Traversal
                                    if (e.IsDirectory || !Path.GetFullPath(p).StartsWith(AppDomain.CurrentDomain.BaseDirectory))
                                        continue;

                                    string dir = Path.GetDirectoryName(p);
                                    if (!Directory.Exists(dir)) Directory.CreateDirectory(dir);

                                    if (File.Exists(p)) File.Delete(p);

                                    using (var f = File.Create(p))
                                    {
                                        zip.CopyTo(f);
                                    }
                                }
                            }
                        }
                        catch
                        {
                            throw new Exception("File ZIP rusak.");
                        }
                    }
                }

                SetComplete(msg);
            }
            catch
            {
                SetError("Gagal memproses file update.");
            }
        }

        private void OpenWhatsapp()
        {
            uint hwid = HWIDHelper.GetVolumeSerialNumberFromCurrentDrive();
            string link = $"https://wa.me/6287775216846?text=Halo%20Admin%2C%20saya%20ingin%20daftar.%20HWID%3A%20{hwid}";
            try { Process.Start(new ProcessStartInfo { FileName = link, UseShellExecute = true }); } catch { }
        }

        private void StartAntiDebuggingCheck() => Task.Run(async () => { while (true) { AntiDebug.CheckForDebuggers(); await Task.Delay(5000); } });
        private async void StartHwidCheckLoop() { await InitializeUserSessionAsync(); _ = Task.Run(async () => { while (true) { await Task.Delay(TimeSpan.FromMinutes(2)); await InitializeUserSessionAsync(); } }); }

        private void SetProgress(int v, string m)
        {
            progressBar.Visible = true;
            progressBar.Value = v;
            if (m != null) lblStatus.Text = m;
        }

        private void SetComplete(string m)
        {
            progressBar.Visible = false;
            ToastHelper.ShowSuccess("Sukses", m);
            lblStatus.Text = "Siap digunakan.";
        }

        private void SetError(string m)
        {
            progressBar.Visible = false;
            MessageBox.Show(m, "Gagal", MessageBoxButtons.OK, MessageBoxIcon.Error);
            lblStatus.Text = "Error.";
        }
    }

    // --- CLASS PENDUKUNG ---

    public static class KeyGuardian
    {
        public static byte[] GetMainKey()
        {
            string part1 = "JCE"; string part2 = "TOOLS"; string dash = "-"; int num = (900 * 2) + 30;
            string fullKey = part1 + part2 + dash + num.ToString();
            return Encoding.ASCII.GetBytes(fullKey);
        }
        public static byte[] GetIV()
        {
            byte[] hiddenIV = new byte[12];
            hiddenIV[0] = 0x12; hiddenIV[1] = 0x34; hiddenIV[2] = 0x56; hiddenIV[3] = 0x78;
            hiddenIV[4] = 0x90; hiddenIV[5] = 0xAB; hiddenIV[6] = 0xCD; hiddenIV[7] = 0xEF;
            hiddenIV[8] = 0x12; hiddenIV[9] = 0x34; hiddenIV[10] = 0x56; hiddenIV[11] = 0x78;
            return hiddenIV;
        }
    }

    public static class ToastHelper
    {
        public static void ShowSuccess(string title, string message)
        {
            ShowPopup(title, message, Color.FromArgb(76, 175, 80));
        }

        public static void ShowError(string title, string message)
        {
            ShowPopup(title, message, Color.FromArgb(244, 67, 54));
        }

        private static void ShowPopup(string title, string message, Color color)
        {
            PopupNotifier popup = new PopupNotifier();
            popup.TitleFont = new Font("Segoe UI", 11, FontStyle.Bold);
            popup.ContentFont = new Font("Segoe UI", 10);
            popup.BodyColor = Color.FromArgb(32, 32, 32);
            popup.ContentColor = Color.White;
            popup.TitleColor = color;
            popup.BorderColor = color;
            popup.HeaderHeight = 1;
            popup.HeaderColor = Color.FromArgb(32, 32, 32);
            popup.TitleText = title;
            popup.ContentText = message;
            popup.Size = new Size(350, 90);
            popup.AnimationDuration = 500;
            popup.ShowOptionsButton = false;
            popup.ShowGrip = false;
            popup.Popup();
        }
    }

    public static class AutoUpdater
    {
        private const string VersionFileUrl = "https://jcetools.my.id/api/hackupdater.txt";
        private const string ExeDownloadUrl = "https://jcetools.my.id/api/JCE_Updater_Latest.exe";
        public const string CurrentVersion = "1.5";

        public static async Task CheckForUpdateAsync()
        {
            try
            {
                using (HttpClient client = new HttpClient())
                {
                    string serverVersionText = await client.GetStringAsync(VersionFileUrl);
                    Version serverVer = new Version(serverVersionText.Trim());
                    Version localVer = new Version(CurrentVersion);

                    if (serverVer > localVer)
                    {
                        DialogResult ask = MessageBox.Show($"Versi Baru Tersedia: {serverVer}\nUpdate sekarang?", "Update", MessageBoxButtons.YesNo, MessageBoxIcon.Question);
                        if (ask == DialogResult.Yes) await PerformUpdate(client);
                    }
                }
            }
            catch { }
        }

        private static async Task PerformUpdate(HttpClient client)
        {
            string tempFileName = "update_temp.exe";
            string currentExe = AppDomain.CurrentDomain.FriendlyName;
            try
            {
                ToastHelper.ShowSuccess("Updating", "Mengunduh versi baru...");
                byte[] fileBytes = await client.GetByteArrayAsync(ExeDownloadUrl);
                File.WriteAllBytes(tempFileName, fileBytes);

                string batchScriptName = "updater.bat";
                string batchScript = $@"@echo off
timeout /t 2 /nobreak > NUL
del ""{currentExe}""
ren ""{tempFileName}"" ""{currentExe}""
start "" "" ""{currentExe}""
del ""%~f0""";
                File.WriteAllText(batchScriptName, batchScript);

                Process.Start(new ProcessStartInfo { FileName = batchScriptName, CreateNoWindow = true, WindowStyle = ProcessWindowStyle.Hidden });
                Application.Exit();
            }
            catch (Exception)
            {
                ToastHelper.ShowError("Update Gagal", "Gagal auto-update.");
                if (File.Exists(tempFileName)) File.Delete(tempFileName);
            }
        }
    }
}