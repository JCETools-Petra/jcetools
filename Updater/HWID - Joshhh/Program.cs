using System;
using System.Net;
using System.Windows.Forms;

namespace HWID___Joshhh
{
    internal static class Program
    {
        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        [STAThread]
        static void Main()
        {
            // Pastikan TLS 1.2 aktif (penting untuk koneksi HTTPS modern / S3)
            try
            {
                ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12;
            }
            catch { /* abaikan jika lingkungan sudah pakai TLS modern */ }

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new Form1());
        }
    }
}
