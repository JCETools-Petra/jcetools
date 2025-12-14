using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows.Forms;

namespace HWID___Joshhh
{
    public static class HWIDHelper
    {
        public static uint GetVolumeSerialNumberFromCurrentDrive()
        {
            // LOGIKA 1: Ambil Path EXE (Sama seperti GetModuleFileNameA di C++)
            string exePath = Application.ExecutablePath;
            string driveLetter = Path.GetPathRoot(exePath);

            // Pastikan formatnya "C:\" (C++ mengambil char pertama + ":\\")
            if (string.IsNullOrEmpty(driveLetter)) return 0;
            if (!driveLetter.EndsWith("\\")) driveLetter += "\\";

            uint serialNumber = 0;
            uint maxComponentLength;
            uint fileSystemFlags;
            StringBuilder volumeName = new StringBuilder(261);
            StringBuilder fileSystemName = new StringBuilder(261);

            // LOGIKA 2: Panggil API Windows Mode ANSI
            // Ini kunci agar hasilnya sama dengan Injector
            if (GetVolumeInformation(
                driveLetter,
                volumeName,
                (uint)volumeName.Capacity,
                ref serialNumber,
                out maxComponentLength,
                out fileSystemFlags,
                fileSystemName,
                (uint)fileSystemName.Capacity))
            {
                return serialNumber;
            }

            return 0;
        }

        public static void DisplayVolumeSerialNumber()
        {
            uint serialNumber = GetVolumeSerialNumberFromCurrentDrive();
            if (serialNumber == 0) return;

            // Simpan log untuk debugging
            try
            {
                string filePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "hwid-log.txt");
                File.WriteAllText(filePath, "HWID: " + serialNumber.ToString());
            }
            catch { }
        }

        // PENTING: CharSet.Ansi (Ini yang menyamakan dengan C++)
        [DllImport("kernel32.dll", EntryPoint = "GetVolumeInformationA", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Ansi)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetVolumeInformation(
           string lpRootPathName,
           StringBuilder lpVolumeNameBuffer,
           uint nVolumeNameSize,
           ref uint lpVolumeSerialNumber,
           out uint lpMaximumComponentLength,
           out uint lpFileSystemFlags,
           StringBuilder lpFileSystemNameBuffer,
           uint nFileSystemNameSize);
    }
}