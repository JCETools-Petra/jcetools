using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

public static class InternetHelper
{
    private static readonly HttpClient httpClient = new HttpClient();

    public static async Task<bool> CheckInternetConnectionAsync(string urlToCheck = "https://www.google.com", TimeSpan? timeout = null)
    {
        // --- INI BAGIAN YANG DIPERBAIKI ---
        // Menggunakan blok if standar yang kompatibel dengan C# 7.3
        if (timeout == null)
        {
            timeout = TimeSpan.FromSeconds(5);
        }

        using (var cts = new CancellationTokenSource((TimeSpan)timeout))
        {
            try
            {
                var request = new HttpRequestMessage(HttpMethod.Head, urlToCheck);
                var response = await httpClient.SendAsync(request, cts.Token);
                return response.IsSuccessStatusCode;
            }
            catch (TaskCanceledException)
            {
                FileLogger.Log("Internet check timed out.");
                return false;
            }
            catch (HttpRequestException)
            {
                FileLogger.Log("Internet check failed (HttpRequestException).");
                return false;
            }
            catch (Exception ex)
            {
                FileLogger.Log($"An unexpected error occurred during internet check: {ex.Message}");
                return false;
            }
        }
    }
}