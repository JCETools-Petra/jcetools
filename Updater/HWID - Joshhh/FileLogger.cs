using System;
using System.IO;
using System.Text; // Untuk Encoding

public static class FileLogger
{
    private static readonly string LogFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "debug_log.txt");
    private static readonly object _lock = new object();

    public static void Log(string message)
    {
        try
        {
            lock (_lock) // Pastikan thread-safe saat menulis ke file
            {
                string logEntry = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} - {message}{Environment.NewLine}";
                File.AppendAllText(LogFilePath, logEntry, Encoding.UTF8);
            }
        }
        catch (Exception ex)
        {
            // Jika logging gagal, kita bisa coba output ke Debug console sebagai fallback
            // atau abaikan jika tidak ingin ada output jika file gagal ditulis.
            System.Diagnostics.Debug.WriteLine($"Error writing to log file: {ex.Message}");
            System.Diagnostics.Debug.WriteLine($"Original log message: {message}");
        }
    }

    public static void ClearLog()
    {
        try
        {
            lock (_lock)
            {
                if (File.Exists(LogFilePath))
                {
                    File.Delete(LogFilePath);
                }
                Log("Log file cleared.");
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"Error clearing log file: {ex.Message}");
        }
    }
}