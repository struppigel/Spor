using System;
using System.IO;
using System.Text.RegularExpressions;

namespace Spor
{
    /// <summary>
    /// Inflated files: hundreds of MB of one repeated byte, against the size limits of scanners and sandbox uploads (loaders, stealers,
    /// game-lure archives). 16 samples of 64 KB spread over the range, about 1 MB read per file; no hashing.
    /// </summary>
    static class Padded
    {
        public const string Flag = "!padded";
        public const long MinFile = 100L << 20, MinExe = 50L << 20;
        const int Samples = 16, SampleSize = 64 * 1024;

        /// <summary>Partial downloads, VM disks and Windows' own big files: never checked.</summary>
        public static readonly Regex Skip = new Regex(
            @"(\.(crdownload|part|partial|!qb|!ut|download|opdownload|vdi|vmdk|vhd|vhdx|qcow2|avhdx)$|^(pagefile|hiberfil|swapfile)\.sys$)", Util.RX);

        /// <summary>
        /// (pure) The repeated byte of a range when every sample is that one byte; null otherwise. read(offset, count) returns the bytes
        /// at an offset of the file (fewer at its end).
        /// </summary>
        public static byte? Check(long start, long length, Func<long, int, byte[]> read)
        {
            if (length < SampleSize * 2L || read == null) return null;
            byte? value = null;
            for (int i = 0; i < Samples; i++)
            {
                long off = start + (length - SampleSize) * i / (Samples - 1);
                var b = read(off, SampleSize);
                if (b == null || b.Length == 0) return null;
                if (value == null) value = b[0];
                for (int k = 0; k < b.Length; k++) if (b[k] != value.Value) return null;
            }
            return value;
        }

        /// <summary>
        /// "padded: N MB of byte 0xXX" for a padded file, else null. Executables over 50 MB: only the overlay (data after the last section,
        /// before the signature), and only when it is more than 90 % of the file. Other files over 100 MB: the whole file.
        /// </summary>
        public static string OfFile(FileInfo f)
        {
            try
            {
                if (Skip.IsMatch(f.Name) || (f.Attributes & FileAttributes.SparseFile) != 0) return null;
                long start = 0, length = f.Length;
                // a PE file: only its overlay; other "program" types (.msi, .jar, .msix, Office macros) are checked whole
                var pe = Modules.Files.Exec.IsMatch(f.Name) && f.Length > MinExe ? Pe.Read(f.FullName) : PeInfo.Empty;
                if (pe.Valid)
                {
                    if (pe.OverlayOffset <= 0 || pe.OverlayOffset >= f.Length) return null;
                    start = pe.OverlayOffset;
                    long end = pe.CertOffset >= start && pe.CertOffset < f.Length ? pe.CertOffset : f.Length;
                    length = end - start;
                    if (length <= f.Length * 0.9) return null;
                }
                else if (f.Length <= MinFile) return null;
                using (var fs = new FileStream(f.FullName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 4096))
                {
                    var v = Check(start, length, (off, n) =>
                    {
                        fs.Position = off;
                        var b = new byte[n];
                        int r = 0, k;
                        while (r < n && (k = fs.Read(b, r, n - r)) > 0) r += k;
                        if (r < n) Array.Resize(ref b, r);
                        return b;
                    });
                    return v == null ? null : $"padded: {length >> 20} MB of byte 0x{v.Value:X2}";
                }
            }
            catch { return null; }
        }
    }
}
