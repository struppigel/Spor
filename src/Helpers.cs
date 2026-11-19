using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;

namespace Spor
{
    static class Ads
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern SafeFileHandle CreateFile(string name, uint access, FileShare share, IntPtr sa, FileMode mode, uint flags, IntPtr template);

        /// <summary>Text of an alternate data stream (e.g. Zone.Identifier), or null. .NET Framework rejects ':' in paths, so CreateFile directly.</summary>
        public static string Read(string path, string stream)
        {
            using (var h = CreateFile((path.Length >= 250 ? @"\\?\" + path : path) + ":" + stream, 0x80000000, FileShare.ReadWrite | FileShare.Delete, IntPtr.Zero, FileMode.Open, 0, IntPtr.Zero))
            {
                if (h.IsInvalid) return null;
                using (var fs = new FileStream(h, FileAccess.Read))
                {
                    var b = new byte[Math.Min(fs.Length, 64 * 1024)];
                    int n = fs.Read(b, 0, b.Length);
                    return Encoding.UTF8.GetString(b, 0, n);
                }
            }
        }

        /// <summary>Download origin from Zone.Identifier: "from <HostUrl>, referrer <ReferrerUrl>" (or zone only), null if none.</summary>
        public static string Origin(string path)
        {
            string z;
            try { z = Read(path, "Zone.Identifier"); } catch { return null; }
            if (z == null) return null;
            string V(string k) { var m = Regex.Match(z, @"^\s*" + k + @"\s*=\s*(.+?)\s*$", RegexOptions.Multiline | RegexOptions.IgnoreCase); return m.Success ? m.Groups[1].Value : null; }
            var host = V("HostUrl"); var refr = V("ReferrerUrl"); var zone = V("ZoneId");
            var parts = new List<string>();
            if (host != null) parts.Add("from " + Util.Clip(host, 120));
            if (refr != null && refr != host) parts.Add("referrer " + Util.Clip(refr, 80));
            if (parts.Count == 0 && zone != null) parts.Add(zone == "3" ? "downloaded from the internet (no URL saved)" : "zone " + zone);
            return parts.Count > 0 ? string.Join(", ", parts) : null;
        }
    }

    /// <summary>Windows shortcut (.lnk): target, where the target was (local drive type / network), target times.</summary>
    class Lnk
    {
        public string Target, Args, Net;
        public int DriveType = -1;   // 2 removable, 3 fixed, 4 network, 5 CD-ROM (also a mounted ISO)
        public DateTime? TargetCreated, TargetWritten;
        public long Size;

        public string Where => DriveType == 5 ? "on a CD/DVD or mounted ISO" : DriveType == 2 ? "on a removable drive" : DriveType == 4 || Net != null ? "on a network share" : null;

        public static Lnk Parse(byte[] b)
        {
            if (b.Length < 76 || BitConverter.ToUInt32(b, 0) != 0x4C) return null;
            var l = new Lnk();
            uint flags = BitConverter.ToUInt32(b, 20);
            l.TargetCreated = Util.FtTime(BitConverter.ToInt64(b, 28));
            l.TargetWritten = Util.FtTime(BitConverter.ToInt64(b, 44));
            l.Size = BitConverter.ToUInt32(b, 52);
            bool uni = (flags & 0x80) != 0;
            int o = 76;
            if ((flags & 1) != 0) o += 2 + BitConverter.ToUInt16(b, o);
            if ((flags & 2) != 0 && o + 28 <= b.Length)
            {
                int li = o; int size = BitConverter.ToInt32(b, li), hs = BitConverter.ToInt32(b, li + 4), lf = BitConverter.ToInt32(b, li + 8);
                string suffix = Cstr(b, li + BitConverter.ToInt32(b, li + 24), false);
                if (hs >= 0x24) { var su = Cstr(b, li + BitConverter.ToInt32(b, li + 32), true); if (!string.IsNullOrEmpty(su)) suffix = su; }
                if ((lf & 1) != 0)
                {
                    int vol = li + BitConverter.ToInt32(b, li + 12);
                    if (vol + 8 <= b.Length) l.DriveType = BitConverter.ToInt32(b, vol + 4);
                    var bp = hs >= 0x24 ? Cstr(b, li + BitConverter.ToInt32(b, li + 28), true) : null;
                    if (string.IsNullOrEmpty(bp)) bp = Cstr(b, li + BitConverter.ToInt32(b, li + 16), false);
                    l.Target = Join(bp, suffix);
                }
                if ((lf & 2) != 0)
                {
                    int cnr = li + BitConverter.ToInt32(b, li + 20);
                    if (cnr + 12 <= b.Length) l.Net = Cstr(b, cnr + BitConverter.ToInt32(b, cnr + 8), false);
                    if (l.Target == null) l.Target = Join(l.Net, suffix);
                }
                o = li + size;
            }
            // string data: name, relative path, working dir, arguments, icon
            var sd = new string[5];
            for (int i = 0, bit = 4; i < 5; i++, bit <<= 1)
            {
                if ((flags & bit) == 0 || o + 2 > b.Length) continue;
                int n = BitConverter.ToUInt16(b, o); o += 2;
                int bytes = uni ? n * 2 : n;
                if (o + bytes > b.Length) break;
                sd[i] = uni ? Encoding.Unicode.GetString(b, o, bytes) : Encoding.Default.GetString(b, o, bytes);
                o += bytes;
            }
            l.Args = sd[3];
            if (l.Target == null && sd[1] != null) l.Target = sd[1];
            return l;
        }

        static string Join(string a, string b) => string.IsNullOrEmpty(b) ? a : string.IsNullOrEmpty(a) ? b : a.TrimEnd('\\') + "\\" + b;

        static string Cstr(byte[] b, int o, bool uni)
        {
            if (o <= 0 || o >= b.Length) return null;
            int e = o;
            if (uni) { while (e + 1 < b.Length && (b[e] != 0 || b[e + 1] != 0)) e += 2; return Encoding.Unicode.GetString(b, o, e - o); }
            while (e < b.Length && b[e] != 0) e++;
            return Encoding.Default.GetString(b, o, e - o);
        }
    }

    static class Ev
    {
        /// <summary>Events of a log since a time, newest first, at most max. Empty if the log doesn't exist or can't be read.</summary>
        public static List<EventRecord> Query(string log, string cond, DateTime since, int max, List<string> err = null)
        {
            var res = new List<EventRecord>();
            var x = $"*[System[{(string.IsNullOrEmpty(cond) ? "" : "(" + cond + ") and ")}TimeCreated[@SystemTime>='{since:yyyy-MM-ddTHH:mm:ss.fffZ}']]]";
            try
            {
                using (var rd = new EventLogReader(new EventLogQuery(log, PathType.LogName, x) { ReverseDirection = true }))
                {
                    for (EventRecord e; res.Count < max && (e = rd.ReadEvent()) != null;) res.Add(e);
                    if (res.Count == max && rd.ReadEvent() is EventRecord more)
                    { more.Dispose(); err?.Add($"{log}: more than {max} matching events in the time window; only the newest {max} were read (use a shorter time window)"); }
                }
            }
            catch (EventLogNotFoundException) { }
            catch (Exception e) { err?.Add(log + ": " + e.Message); }
            return res;
        }

        public static string Ids(params int[] ids) => string.Join(" or ", ids.Select(i => "EventID=" + i));

        public static string Msg(EventRecord e)
        {
            string m = null;
            try { m = e.FormatDescription(); } catch { }
            if (string.IsNullOrEmpty(m)) m = string.Join(" | ", e.Properties.Select(p => Convert.ToString(p.Value)));
            return m;
        }

        /// <summary>Value of a "Name: value" line in an event message (Defender style).</summary>
        public static string Field(string msg, string name)
        {
            var m = Regex.Match(msg ?? "", @"^\s*" + Regex.Escape(name) + @"\s*:\s*(.*?)\s*$", RegexOptions.Multiline | RegexOptions.IgnoreCase);
            return m.Success ? m.Groups[1].Value : null;
        }

        public static string P(EventRecord e, int i) => e.Properties.Count > i ? Convert.ToString(e.Properties[i].Value) : "";
    }

    static class Cmd
    {
        static readonly Regex Exe = new Regex(@"^(.*?\.(exe|com|scr|bat|cmd|ps1|vbs|vbe|js|jse|wsf|hta|dll|sys|cpl|msi|lnk|jar))(\s|,|$)", Util.RX);

        /// <summary>The program a command line starts: quoted path, else everything up to the first .exe/.dll/..., else the first word.</summary>
        public static string Program(string cmd, string winDir)
        {
            var s = Environment.ExpandEnvironmentVariables((cmd ?? "").Trim());
            if (s.Length == 0) return "";
            string p;
            if (s[0] == '"') { int e = s.IndexOf('"', 1); p = e > 0 ? s.Substring(1, e - 1) : s.Trim('"'); }
            else { var m = Exe.Match(s); p = m.Success ? m.Groups[1].Value : s.Split(' ')[0]; }
            p = Regex.Replace(p, @"^\\\?\?\\", "");
            if (p.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase)) p = winDir + p.Substring(11);
            else if (p.StartsWith(@"System32\", StringComparison.OrdinalIgnoreCase) || p.StartsWith(@"SysWOW64\", StringComparison.OrdinalIgnoreCase)) p = Path.Combine(winDir, p);
            else if (!p.Contains("\\") && Regex.IsMatch(p, @"\.(exe|com)$", Util.RX) && File.Exists(Path.Combine(winDir, "System32", p))) p = Path.Combine(winDir, "System32", p);
            return p;
        }

        /// <summary>The arguments after the program in a command line.</summary>
        public static string Args(string cmd)
        {
            var s = Environment.ExpandEnvironmentVariables((cmd ?? "").Trim());
            if (s.StartsWith("\"")) { int e = s.IndexOf('"', 1); return e > 0 ? s.Substring(e + 1).Trim() : ""; }
            var m = Exe.Match(s);
            if (m.Success) return s.Substring(m.Groups[1].Length).Trim();
            int sp = s.IndexOf(' ');
            return sp > 0 ? s.Substring(sp + 1).Trim() : "";
        }

        /// <summary>Exact size in bytes, not rounded, so logs can be compared.</summary>
        public static string Bytes(long n) => n + " bytes";
    }
}
