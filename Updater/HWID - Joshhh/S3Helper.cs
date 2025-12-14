using Amazon.S3;
using Amazon.S3.Model;
using Amazon.S3.Util;
using System;
using System.IO;
using System.Threading.Tasks;
using ICSharpCode.SharpZipLib.Zip;

public class S3Helper
{
    private readonly AmazonS3Client s3Client;

    public S3Helper(string clientKey, string secretKey, string serviceUrl)
    {
        var config = new AmazonS3Config
        {
            ServiceURL = serviceUrl,
            ForcePathStyle = true,
            SignatureVersion = "4"
        };
        s3Client = new AmazonS3Client(clientKey, secretKey, config);
    }

    public async Task DownloadAndExtractZipAsync(string bucketName, string keyName, string destinationPath, Action<int> reportProgress)
    {
        var request = new GetObjectRequest
        {
            BucketName = bucketName,
            Key = keyName
        };

        try
        {
            FileLogger.Log($"S3 REQ: bucket={bucketName}, key={keyName}");

            using (var response = await s3Client.GetObjectAsync(request))
            using (var memoryStream = new MemoryStream())
            {
                long totalBytes = response.ContentLength;
                long totalRead = 0;
                var buffer = new byte[8192];
                int bytesRead;

                // stream → memory (dengan progress)
                while ((bytesRead = await response.ResponseStream.ReadAsync(buffer, 0, buffer.Length)) > 0)
                {
                    totalRead += bytesRead;
                    memoryStream.Write(buffer, 0, bytesRead);

                    if (totalBytes > 0)
                    {
                        var progress = (int)((totalRead * 100) / totalBytes);
                        reportProgress?.Invoke(progress);
                    }
                }

                memoryStream.Seek(0, SeekOrigin.Begin);

                // ekstrak zip
                using (var zipInputStream = new ZipInputStream(memoryStream))
                {
                    ZipEntry entry;
                    while ((entry = zipInputStream.GetNextEntry()) != null)
                    {
                        string entryDestinationPath = Path.Combine(destinationPath, entry.Name);

                        // rudimentary zip-slip guard
                        string fullPath = Path.GetFullPath(entryDestinationPath);
                        if (!fullPath.StartsWith(Path.GetFullPath(destinationPath), StringComparison.OrdinalIgnoreCase))
                        {
                            FileLogger.Log($"ZIP-SKIP (zip slip attempt): {entry.Name}");
                            continue;
                        }

                        string entryDestinationDir = Path.GetDirectoryName(entryDestinationPath);
                        if (!string.IsNullOrEmpty(entryDestinationDir))
                        {
                            Directory.CreateDirectory(entryDestinationDir);
                        }

                        if (!entry.IsDirectory)
                        {
                            using (var fileStream = File.Create(entryDestinationPath))
                            {
                                zipInputStream.CopyTo(fileStream);
                            }
                        }
                    }
                }

                reportProgress?.Invoke(100);
            }
        }
        catch (AmazonS3Exception s3ex)
        {
            FileLogger.Log($"S3 ERROR: HttpStatus={s3ex.StatusCode}, ErrorCode={s3ex.ErrorCode}, Msg={s3ex.Message}");
            if (s3ex.InnerException != null)
            {
                FileLogger.Log($"S3 INNER: {s3ex.InnerException.GetType().Name}: {s3ex.InnerException.Message}");
            }
            throw; // biar caller bisa bedakan S3 vs general exception
        }
        catch (Exception ex)
        {
            FileLogger.Log($"S3 GENERAL EX: {ex.GetType().Name}: {ex.Message}");
            throw new Exception("Gagal mengunduh file dari server.");
        }
    }
}
