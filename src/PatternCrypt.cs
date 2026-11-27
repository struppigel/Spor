using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Spor
{
    /// <summary>
    /// The known-malware database (resources/autodetect.txt) is embedded AES-256-CBC encrypted with an HMAC-SHA256 (encrypt-then-MAC):
    /// IV (16 bytes) | ciphertext | MAC over IV and ciphertext (32 bytes). The build encrypts it (Spor.csproj, target
    /// EncryptPatterns); Spor decrypts it on first use.
    ///
    /// Why: plain patterns in Spor.exe (malware paths, command lines) make antivirus engines flag Spor and show up in a strings dump.
    /// The key is in the exe, so this hides the patterns, it does not keep them secret: the plain file is in the source repo.
    /// The IV is derived from the content (SHA256), so the same file always gives the same bytes (deterministic builds).
    /// </summary>
    static class PatternCrypt
    {
        // Spor.csproj's EncryptPatterns task reads the key from this line: keep the form KeyHex = "<64 hex digits>".
        internal const string KeyHex = "4efec9ba121784dcf6828248f828c557863b1e0a9eb26f700114016168596e15";

        const int IvLength = 16, MacLength = 32;

        static byte[] Key => Hex(KeyHex);

        static byte[] MacKey
        {
            get { using (var sha = SHA256.Create()) return sha.ComputeHash(Key.Concat(Encoding.ASCII.GetBytes("mac")).ToArray()); }
        }

        /// <summary>The bytes of a file, encrypted (the same as the build's EncryptPatterns task).</summary>
        public static byte[] Encrypt(byte[] plain)
        {
            byte[] iv;
            using (var sha = SHA256.Create()) iv = sha.ComputeHash(plain).Take(IvLength).ToArray();
            byte[] ct;
            using (var aes = Aes.Create())
            {
                aes.Mode = CipherMode.CBC; aes.Padding = PaddingMode.PKCS7; aes.Key = Key; aes.IV = iv;
                using (var e = aes.CreateEncryptor()) ct = e.TransformFinalBlock(plain, 0, plain.Length);
            }
            var body = iv.Concat(ct).ToArray();
            using (var h = new HMACSHA256(MacKey)) return body.Concat(h.ComputeHash(body)).ToArray();
        }

        /// <summary>The text of an encrypted file (a BOM is dropped, as File.ReadAllText does). InvalidDataException: damaged or another key.</summary>
        public static string Decrypt(byte[] data)
        {
            if (data == null || data.Length < IvLength + 16 + MacLength || (data.Length - IvLength - MacLength) % 16 != 0)
                throw new InvalidDataException("not an encrypted pattern file (wrong length)");
            var body = data.Take(data.Length - MacLength).ToArray();
            byte[] mac;
            using (var h = new HMACSHA256(MacKey)) mac = h.ComputeHash(body);
            int diff = 0;
            for (int i = 0; i < MacLength; i++) diff |= mac[i] ^ data[body.Length + i];
            if (diff != 0) throw new InvalidDataException("damaged or not encrypted with this Spor's key (MAC check failed)");
            byte[] plain;
            using (var aes = Aes.Create())
            {
                aes.Mode = CipherMode.CBC; aes.Padding = PaddingMode.PKCS7; aes.Key = Key; aes.IV = body.Take(IvLength).ToArray();
                using (var d = aes.CreateDecryptor()) plain = d.TransformFinalBlock(body, IvLength, body.Length - IvLength);
            }
            using (var r = new StreamReader(new MemoryStream(plain), Encoding.UTF8, true)) return r.ReadToEnd();
        }

        static byte[] Hex(string s) => Enumerable.Range(0, s.Length / 2).Select(i => Convert.ToByte(s.Substring(2 * i, 2), 16)).ToArray();
    }
}
