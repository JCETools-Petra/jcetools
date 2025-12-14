using System;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using ICSharpCode.SharpZipLib.Zip;
using Newtonsoft.Json.Linq;
using HWID___Joshhh.Module;

namespace HWID___Joshhh
{
    public partial class Form1 : Form
    {
        private readonly HttpClient httpClient;

        private static readonly byte[] originalKey = { 0x4A, 0x43, 0x45, 0x54, 0x4F, 0x4F, 0x4C, 0x53, 0x2D, 0x31, 0x38, 0x33, 0x30 };
        private static readonly byte[] originalIv = { 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78 };
        private const string ApiKey = "JCE-TOOLS-8274827490142820785613720428042187";

        private string NamaUser { get; set; }
        private string ClientKey { get; set; }
        private string SecretKey { get; set; }
        private string MaintenanceStatus { get; set; }
        private string ButtonCustom1 { get; set; }
        private string ExpiredDate { get; set; }

        public Form1()
        {
            InitializeComponent();
            InitializeModernUI();

            httpClient = new HttpClient();

            // Startup async
            HandleStartupAsync();

            HWIDHelper.DisplayVolumeSerialNumber();
        }

        // Startup flow: anti-debug + cek internet + loop HWID
        private async void HandleStartupAsync()
        {
            StartAntiDebuggingCheck();

            bool hasConnection = await InternetHelper.CheckInternetConnectionAsync();
            if (!hasConnection)
            {
                MessageBox.Show("Aplikasi membutuhkan koneksi internet untuk berfungsi.", "Koneksi Diperlukan", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetInvalidHwidUI();
            }
            else
            {
                StartHwidCheckLoop();
            }
        }

        private void InitializeModernUI()
        {
            try { }
            catch { /* ignore jika resource logo tidak ada */ }

            this.btnDownloadUser.Click += new System.EventHandler(this.button2_Click);
            this.btnBuyAccess.Click += new System.EventHandler(this.button1_Click);
            this.btnDownloadFree.Click += new System.EventHandler(this.button3_Click);
        }

        private async Task InitializeUserSessionAsync()
        {
            uint hwid = HWIDHelper.GetVolumeSerialNumberFromCurrentDrive();
            if (hwid == 0)
            {
                SetInvalidHwidUI();
                return;
            }

            string hwidString = hwid.ToString();
            string encryptedHwid = EncryptionHelper.EncryptString(hwidString, originalKey, originalIv);
            string response = await CheckHWID(encryptedHwid);

            if (response == null) { SetInvalidHwidUI(); return; }
            try
            {
                JObject jsonResponse = JObject.Parse(response);
                if ((string)jsonResponse["status"] == "error") { SetInvalidHwidUI(); }
                else { SetValidHwidUI(jsonResponse); }
            }
            catch (Exception)
            {
                FileLogger.Log("Gagal memproses respons server.");
                MessageBox.Show("Gagal memproses data dari server. Silakan coba lagi.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetInvalidHwidUI();
            }
        }

        private void SetValidHwidUI(JObject jsonResponse)
        {
            this.Invoke((MethodInvoker)delegate {
                this.NamaUser = (string)jsonResponse["nama"];
                this.ClientKey = (string)jsonResponse["sk"];
                this.SecretKey = (string)jsonResponse["sck"];
                this.MaintenanceStatus = (string)jsonResponse["maintenance"];
                this.ButtonCustom1 = (string)jsonResponse["status1_text"];
                this.ExpiredDate = (string)jsonResponse["expiry_date"];

                string expiryStatusText;
                if (DateTime.TryParse(this.ExpiredDate, out DateTime expiryDateTime))
                {
                    if (expiryDateTime.Year > 2035)
                    {
                        expiryStatusText = "Permanent";
                    }
                    else
                    {
                        TimeSpan timeRemaining = expiryDateTime.Date - DateTime.Today;
                        int daysRemaining = (int)timeRemaining.TotalDays;
                        if (daysRemaining < 0) { daysRemaining = 0; }
                        expiryStatusText = $"Sisa: {daysRemaining} Hari";
                    }
                }
                else
                {
                    expiryStatusText = this.ExpiredDate;
                }

                this.Text = $"JCE Updater - {expiryStatusText}";

                pnlInvalidUser.Visible = false;
                pnlValidUser.Visible = true;

                lblWelcomeUser.Text = $"Selamat Datang, {this.NamaUser}!";
                btnDownloadUser.Text = $"Download File - {this.NamaUser}";
                btnDownloadCustom.Text = $"Download File - {this.ButtonCustom1}";
                lblStatus.Text = "Terautentikasi. Siap untuk mengunduh.";
            });
        }

        #region Updated Methods (lebih detail logging)
        private async Task DownloadFromS3()
        {
            try
            {
                string decryptedClientKey = EncryptionHelper.DecryptString(this.ClientKey, originalKey, originalIv);
                string decryptedSecretKey = EncryptionHelper.DecryptString(this.SecretKey, originalKey, originalIv);

                FileLogger.Log($"S3 KEY LEN: CK={(decryptedClientKey?.Length ?? -1)}, SCK={(decryptedSecretKey?.Length ?? -1)}");

                if (string.IsNullOrEmpty(decryptedClientKey) || string.IsNullOrEmpty(decryptedSecretKey))
                {
                    MessageBox.Show("Terjadi masalah dengan akun Anda. Silakan hubungi dukungan teknis.", "Error Akun", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    FileLogger.Log("Gagal decrypt kredensial S3 (null/empty).");
                    return;
                }

                string s3Path = $"jce-tools-bucket/{this.NamaUser}.zip";
                string bucketName = s3Path.Split('/')[0];
                string keyName = s3Path.Substring(bucketName.Length + 1);
                FileLogger.Log($"S3 PATH: bucket={bucketName}, key={keyName}");

                var s3Helper = new S3Helper(decryptedClientKey, decryptedSecretKey, "https://s3.nevaobjects.id/");

                SetDownloadProgress(0, "Mengunduh file pengguna...");
                await s3Helper.DownloadAndExtractZipAsync(
                    bucketName, keyName, AppDomain.CurrentDomain.BaseDirectory,
                    progress => this.Invoke((MethodInvoker)(() => SetDownloadProgress(progress, null)))
                );

                SetDownloadComplete("Update Selesai! Silakan jalankan launcher.");
            }
            catch (Exception ex)
            {
                FileLogger.Log("Gagal download dari S3 DETAIL: " + ex.ToString());
                SetDownloadError("Gagal mengunduh pembaruan. Silakan coba lagi.");
            }
        }

        private async Task<string> CheckHWID(string encryptedHwid)
        {
            try
            {
                string url = "https://jcetools.my.id/api/cektest.php";
                string jsonData = $"{{\"hwid\":\"{encryptedHwid}\"}}";
                var content = new StringContent(jsonData, Encoding.UTF8, "application/json");
                content.Headers.Add("X-API-Key", ApiKey);

                var response = await httpClient.PostAsync(url, content);

                if (!response.IsSuccessStatusCode)
                {
                    var respBody = await response.Content.ReadAsStringAsync();
                    FileLogger.Log($"HWID {response.StatusCode} BODY: {respBody}");
                    return null;
                }

                return await response.Content.ReadAsStringAsync();
            }
            catch (Exception ex)
            {
                FileLogger.Log($"Terjadi masalah saat verifikasi HWID: {ex.Message}");
                return null;
            }
        }

        private async Task DownloadAndExtractZipFromUrl(string url, string successMessage)
        {
            try
            {
                SetDownloadProgress(0, "Mengunduh file gratis...");
                using (var response = await httpClient.GetAsync(url, HttpCompletionOption.ResponseHeadersRead))
                {
                    if (!response.IsSuccessStatusCode)
                    {
                        FileLogger.Log($"FREE-DL HTTP {(int)response.StatusCode} {response.ReasonPhrase}");
                        response.EnsureSuccessStatusCode();
                    }

                    var totalBytes = response.Content.Headers.ContentLength ?? -1L;

                    using (var zipStream = await response.Content.ReadAsStreamAsync())
                    using (var memoryStream = new MemoryStream())
                    {
                        var buffer = new byte[8192];
                        long totalRead = 0;
                        int bytesRead;

                        while ((bytesRead = await zipStream.ReadAsync(buffer, 0, buffer.Length)) > 0)
                        {
                            await memoryStream.WriteAsync(buffer, 0, bytesRead);
                            totalRead += bytesRead;
                            if (totalBytes > 0)
                            {
                                var progress = (int)((totalRead * 100) / totalBytes);
                                this.Invoke((MethodInvoker)(() => SetDownloadProgress(progress, null)));
                            }
                        }

                        memoryStream.Seek(0, SeekOrigin.Begin);
                        using (var zipInputStream = new ZipInputStream(memoryStream))
                        {
                            ZipEntry entry;
                            while ((entry = zipInputStream.GetNextEntry()) != null)
                            {
                                string destinationPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, entry.Name);

                                // zip-slip guard
                                string fullPath = Path.GetFullPath(destinationPath);
                                string basePath = Path.GetFullPath(AppDomain.CurrentDomain.BaseDirectory);
                                if (!fullPath.StartsWith(basePath, StringComparison.OrdinalIgnoreCase))
                                {
                                    FileLogger.Log($"ZIP-SKIP (zip slip attempt): {entry.Name}");
                                    continue;
                                }

                                string destinationDir = Path.GetDirectoryName(destinationPath);
                                if (!string.IsNullOrEmpty(destinationDir)) Directory.CreateDirectory(destinationDir);

                                if (!entry.IsDirectory)
                                {
                                    using (var fileStream = File.Create(destinationPath))
                                    {
                                        zipInputStream.CopyTo(fileStream);
                                    }
                                }
                            }
                        }
                    }

                    SetDownloadComplete(successMessage);
                }
            }
            catch (Exception ex)
            {
                FileLogger.Log("Gagal download dari URL DETAIL: " + ex.ToString());
                SetDownloadError("Gagal mengunduh pembaruan. Periksa koneksi internet Anda.");
            }
        }
        #endregion

        #region Unchanged Methods (UI/helper)
        private void StartAntiDebuggingCheck()
        {
            Task.Run(async () =>
            {
                while (true)
                {
                    AntiDebug.CheckForDebuggers();
                    await Task.Delay(TimeSpan.FromSeconds(5));
                }
            });
        }

        private async Task StartHwidCheckLoop()
        {
            await InitializeUserSessionAsync();
            _ = Task.Run(async () =>
            {
                while (true)
                {
                    await Task.Delay(TimeSpan.FromMinutes(2));
                    await InitializeUserSessionAsync();
                }
            });
        }

        private void SetInvalidHwidUI()
        {
            this.Invoke((MethodInvoker)delegate {
                this.Text = "JCE Updater - Akses Ditolak";
                pnlValidUser.Visible = false;
                pnlInvalidUser.Visible = true;
                lblStatus.Text = "HWID tidak terdaftar. Silakan beli akses atau gunakan versi gratis.";
            });
        }

        private void button1_Click(object sender, EventArgs e)
        {
            uint hwid = HWIDHelper.GetVolumeSerialNumberFromCurrentDrive();
            if (hwid == 0) return;
            string hwidString = hwid.ToString();
            string whatsappLink = "https://api.whatsapp.com/send?phone=6281299430992&text=Hallo%20Saya%20Mau%20daftar%20cheat%2C%20ini%20hwid%20saya%20%5B%20%5D";
            string finalLink = whatsappLink.Replace("%5B%20%5D", $"%5B{hwidString}%5D");
            try
            {
                System.Diagnostics.Process.Start(finalLink);
            }
            catch (Exception)
            {
                FileLogger.Log("Gagal membuka browser untuk WhatsApp.");
                MessageBox.Show($"Gagal membuka browser. Silakan salin HWID Anda secara manual: {hwidString}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private async void button2_Click(object sender, EventArgs e)
        {
            if (this.MaintenanceStatus == "yes")
            {
                string url = "https://www.facebook.com/joseph.green11";
                string message = $"Layanan sedang dalam pemeliharaan. Silakan periksa halaman Facebook untuk informasi terbaru.";
                if (MessageBox.Show(message, "Maintenance", MessageBoxButtons.OKCancel, MessageBoxIcon.Warning) == DialogResult.OK)
                {
                    try { System.Diagnostics.Process.Start(url); }
                    catch (Exception) { MessageBox.Show("Gagal membuka URL.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error); }
                }
                return;
            }
            await DownloadFromS3();
        }

        private async void button3_Click(object sender, EventArgs e)
        {
            string statusUrl = "https://webtechsolution.my.id/Free/status";
            string downloadUrl = "https://webtechsolution.my.id/Free/Gratis.zip";
            try
            {
                string statusResponse = await httpClient.GetStringAsync(statusUrl);
                if (!bool.TryParse(statusResponse.Trim(), out bool canDownload) || !canDownload)
                {
                    MessageBox.Show("Penggunaan versi gratis saat ini dibatasi. Silakan coba lagi nanti.", "Informasi", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }
                await DownloadAndExtractZipFromUrl(downloadUrl, "Update Selesai! Silakan jalankan launcher.");
            }
            catch (Exception)
            {
                FileLogger.Log("Gagal memeriksa status versi gratis.");
                MessageBox.Show("Gagal memeriksa status. Silakan coba lagi.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void SetDownloadProgress(int percentage, string message)
        {
            progressBar.Visible = true;
            progressBar.Value = Math.Max(0, Math.Min(100, percentage));
            if (message != null)
            {
                lblStatus.Text = message;
            }
        }

        private void SetDownloadComplete(string message)
        {
            lblStatus.Text = "Unduhan selesai.";
            progressBar.Visible = false;
            MessageBox.Show(message, "Sukses", MessageBoxButtons.OK, MessageBoxIcon.Information);
            lblStatus.Text = "Siap untuk mengunduh.";
        }

        private void SetDownloadError(string errorMessage)
        {
            lblStatus.Text = "Unduhan gagal.";
            progressBar.Visible = false;
            MessageBox.Show(errorMessage, "Gagal", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
        #endregion
    }
}
