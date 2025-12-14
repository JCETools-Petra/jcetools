using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows.Forms;

public static class HWIDHelper
{
    public static uint GetVolumeSerialNumberFromCurrentDrive()
    {
        string driveLetter = Path.GetPathRoot(AppDomain.CurrentDomain.BaseDirectory);
        if (string.IsNullOrEmpty(driveLetter))
        {
            FileLogger.Log("Gagal mendapatkan path drive root.");
            MessageBox.Show("Gagal mengidentifikasi drive aplikasi.", "Error Kritis", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 0;
        }

        uint serialNumber = 0;
        if (GetVolumeInformation(driveLetter, null, 0, ref serialNumber, out _, out _, null, 0))
        {
            return serialNumber;
        }
        else
        {
            FileLogger.Log("Gagal mendapatkan informasi volume drive.");
            MessageBox.Show("Gagal mendapatkan HWID dari sistem.", "Error Kritis", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 0;
        }
    }

    public static void DisplayVolumeSerialNumber()
    {
        uint serialNumber = GetVolumeSerialNumberFromCurrentDrive();
        if (serialNumber == 0) return;

        string hwidString = serialNumber.ToString();
        string filePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "hwid-log.txt");

        try
        {
            File.WriteAllText(filePath, "HWID: " + hwidString);
        }
        catch (Exception)
        {
            FileLogger.Log("Gagal menulis file hwid-log.txt.");
            MessageBox.Show("Gagal menyimpan file HWID. Pastikan aplikasi memiliki izin tulis.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
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