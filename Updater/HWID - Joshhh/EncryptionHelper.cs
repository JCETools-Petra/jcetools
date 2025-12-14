using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

public static class EncryptionHelper
{
    public static string EncryptString(string plainText, byte[] key, byte[] iv)
    {
        if (string.IsNullOrEmpty(plainText))
            throw new ArgumentNullException(nameof(plainText));
        if (key == null || key.Length <= 0)
            throw new ArgumentNullException(nameof(key));
        if (iv == null || iv.Length <= 0)
            throw new ArgumentNullException(nameof(iv));

        byte[] paddedKey = new byte[32];
        byte[] paddedIV = new byte[16];

        Array.Copy(key, paddedKey, Math.Min(key.Length, paddedKey.Length));
        Array.Copy(iv, paddedIV, Math.Min(iv.Length, paddedIV.Length));

        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = paddedKey;
            aesAlg.IV = paddedIV;
            aesAlg.Mode = CipherMode.CBC;
            aesAlg.Padding = PaddingMode.PKCS7;

            ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                    {
                        swEncrypt.Write(plainText);
                    }
                }
                return BitConverter.ToString(msEncrypt.ToArray()).Replace("-", "").ToLower();
            }
        }
    }

    public static string DecryptString(string cipherTextHex, byte[] key, byte[] iv)
    {
        if (string.IsNullOrEmpty(cipherTextHex))
            throw new ArgumentNullException(nameof(cipherTextHex));
        if (key == null || key.Length <= 0)
            throw new ArgumentNullException(nameof(key));
        if (iv == null || iv.Length <= 0)
            throw new ArgumentNullException(nameof(iv));

        byte[] paddedKey = new byte[32];
        byte[] paddedIV = new byte[16];

        Array.Copy(key, paddedKey, Math.Min(key.Length, paddedKey.Length));
        Array.Copy(iv, paddedIV, Math.Min(iv.Length, paddedIV.Length));

        try
        {
            byte[] cipherTextBytes = Enumerable.Range(0, cipherTextHex.Length)
                                     .Where(x => x % 2 == 0)
                                     .Select(x => Convert.ToByte(cipherTextHex.Substring(x, 2), 16))
                                     .ToArray();

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = paddedKey;
                aesAlg.IV = paddedIV;
                aesAlg.Mode = CipherMode.CBC;
                aesAlg.Padding = PaddingMode.PKCS7;

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msDecrypt = new MemoryStream(cipherTextBytes))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            return srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Decryption Error: {ex.Message}");
            return null;
        }
    }
}