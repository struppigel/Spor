using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace Spor
{
    static class Util
    {
        public const RegexOptions RX = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant;
        public static readonly StringComparer IC = StringComparer.OrdinalIgnoreCase;

        public static DateTime? FtTime(long ft)
        {
            if (ft <= 0) return null;
            try { return DateTime.FromFileTimeUtc(ft); } catch { return null; }
        }

        public static DateTime? FtTime(object o)
        {
            if (o is long l) return FtTime(l);
            if (o is int i) return FtTime((long)i);
            if (o is byte[] b && b.Length >= 8) return FtTime(BitConverter.ToInt64(b, 0));
            return null;
        }

        public static string Utc(DateTime? t) => t.HasValue ? t.Value.ToString(Log.TimeFmt, CultureInfo.InvariantCulture) + " UTC" : "(no time)";

        /// <summary>
        /// A file time as FRST shows it: UTC plus the PC's offset when the scan ran (FileTimeToLocalFileTime),
        /// not the daylight saving rule of the file's own date, which ToLocalTime() would apply.
        /// </summary>
        public static DateTime FrstLocal(DateTime utc, TimeSpan offset) => DateTime.SpecifyKind(utc, DateTimeKind.Unspecified) + offset;

        static readonly Regex DevicePrefix = new Regex(@"^(?:\\\\\?\\|\\\?\?\\)", RegexOptions.CultureInvariant);

        /// <summary>The path without a "\\?\" or "\??\" prefix; "\\?\UNC\server\x" becomes "\\server\x".</summary>
        public static string StripDevicePrefix(string p)
        {
            p = (p ?? "").Trim();
            if (p.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase)) return @"\\" + p.Substring(8);
            return DevicePrefix.Replace(p, "");
        }

        static readonly Regex LineBreaks = new Regex(@"[\r\n]+", RegexOptions.CultureInvariant);
        // C0 control characters other than tab and line breaks (a NUL after a Zone.Identifier URL, ...).
        static readonly Regex Controls = new Regex(@"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]", RegexOptions.CultureInvariant);

        /// <summary>One line: line breaks become spaces, other control characters are removed. Never shortened (n is ignored; the log keeps full text).</summary>
        public static string Clip(object o, int n = 0) => LineBreaks.Replace(Controls.Replace(Convert.ToString(o) ?? "", ""), " ").Trim();

        /// <summary>Shannon entropy of bytes in bits per byte: 8 = random or encrypted, below 5 = text, 0 = one repeated value.</summary>
        public static double Entropy(byte[] b, int count = -1)
        {
            if (b == null) return 0;
            if (count < 0 || count > b.Length) count = b.Length;
            if (count == 0) return 0;
            var n = new long[256];
            for (int i = 0; i < count; i++) n[b[i]]++;
            double e = 0;
            foreach (var x in n)
                if (x > 0) { double p = (double)x / count; e -= p * Math.Log(p, 2); }
            return e;
        }

        /// <summary>Folder part of a path ("" if none).</summary>
        public static string Folder(string p) => p.Substring(0, Math.Max(0, p.LastIndexOf('\\')));

        public static string Leaf(string p) => p.Substring(p.LastIndexOf('\\') + 1);

        /// <summary>
        /// Reads a text file opened shared (services keep their logs open). Files over cap: the end is read.
        /// UTF-16 with or without BOM (AnyDesk writes it without), else UTF-8/ANSI.
        /// </summary>
        public static string ReadText(string f, int cap = 20 * 1024 * 1024)
        {
            byte[] b;
            using (var fs = new FileStream(f, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            {
                int n = (int)Math.Min(fs.Length, cap);
                if (fs.Length > cap) fs.Seek(-n, SeekOrigin.End);
                b = new byte[n];
                int r = 0;
                while (r < n) { int k = fs.Read(b, r, n - r); if (k <= 0) break; r += k; }
                if (r < n) Array.Resize(ref b, r);
            }
            bool utf16 = b.Length >= 2 && ((b[0] == 0xFF && b[1] == 0xFE) || (b.Length >= 4 && b[1] == 0 && b[3] == 0));
            return (utf16 ? Encoding.Unicode.GetString(b) : Encoding.UTF8.GetString(b)).TrimStart('﻿');
        }

        /// <summary>All lines, as Get-Content returns them (no trailing empty line).</summary>
        public static List<string> AllLines(string f)
        {
            var l = Regex.Split(ReadText(f), "\r?\n").ToList();
            if (l.Count > 0 && l[l.Count - 1].Length == 0) l.RemoveAt(l.Count - 1);
            return l;
        }

        /// <summary>Non-empty lines.</summary>
        public static List<string> Lines(string f) => Regex.Split(ReadText(f), "\r?\n").Where(x => x.Trim().Length > 0).ToList();

        const FileAttributes SkipFile = (FileAttributes)(0x1000 | 0x40000 | 0x400000);   // offline / cloud placeholders: reading starts a download or blocks

        /// <summary>
        /// Files matching the patterns (filtered by Windows, fast), up to depth folder levels below dir.
        /// Does not follow junctions/symlinks, skips cloud placeholders and Store app "Packages" folders.
        /// </summary>
        public static IEnumerable<FileInfo> Walk(string dir, int depth, params string[] patterns)
        {
            var seen = new HashSet<string>(IC);
            var st = new Stack<KeyValuePair<string, int>>();
            st.Push(new KeyValuePair<string, int>(dir, 0));
            while (st.Count > 0)
            {
                var e = st.Pop();
                var di = new DirectoryInfo(e.Key);
                foreach (var p in patterns)
                {
                    FileInfo[] fs;
                    try { fs = di.GetFiles(p); } catch { continue; }
                    foreach (var fi in fs)
                        if ((fi.Attributes & SkipFile) == 0 && seen.Add(fi.FullName)) yield return fi;
                }
                if (e.Value >= depth) continue;
                DirectoryInfo[] ds;
                try { ds = di.GetDirectories(); } catch { continue; }
                foreach (var sd in ds)
                    if ((sd.Attributes & FileAttributes.ReparsePoint) == 0 && !sd.Name.Equals("Packages", StringComparison.OrdinalIgnoreCase))
                        st.Push(new KeyValuePair<string, int>(sd.FullName, e.Value + 1));
            }
        }

        public static string Plural(int n, string one, string many) => n == 1 ? "1 " + one : n + " " + many;
    }
}
