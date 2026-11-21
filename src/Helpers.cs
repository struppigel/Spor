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

        /// <summary>The Zone.Identifier stream of a file, parsed; null if it has none (or it cannot be read).</summary>
        public static Zone Origin(string path)
        {
            string z;
            try { z = Read(path, "Zone.Identifier"); } catch { return null; }
            return z == null ? null : ParseZone(z);
        }

        /// <summary>The text of a Zone.Identifier stream ("[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=..."), parsed. Never null.</summary>
        public static Zone ParseZone(string text)
        {
            text = text ?? "";
            string V(string k)
            {
                // to the line break, not "$": in Multiline mode .NET's "$" does not match before "\r"
                var m = Regex.Match(text, @"^[ \t]*" + k + @"[ \t]*=([^\r\n]*)", RegexOptions.Multiline | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
                var v = m.Success ? Util.Clip(m.Groups[1].Value) : "";
                return v.Length > 0 ? v : null;
            }
            var id = V("ZoneId");
            return new Zone
            {
                Id = int.TryParse(id, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var n) ? n : (int?)null,
                HostUrl = V("HostUrl"),
                ReferrerUrl = V("ReferrerUrl"),
            };
        }
    }

    /// <summary>
    /// A Zone.Identifier stream: the zone (0 this computer, 1 intranet, 2 trusted, 3 internet, 4 restricted) and the URLs a browser saved.
    /// </summary>
    sealed class Zone
    {
        public int? Id;
        public string HostUrl, ReferrerUrl;

        /// <summary>A URL that says where the file came from. "about:internet" / "about:blank" (written by some tools and Office) are none.</summary>
        public static bool RealUrl(string u) => !string.IsNullOrWhiteSpace(u) && !u.TrimStart().StartsWith("about:", StringComparison.OrdinalIgnoreCase);

        public bool HasUrl => RealUrl(HostUrl) || RealUrl(ReferrerUrl);

        /// <summary>For the log: the URLs as "from:" / "referrer:" sub-lines (a line would get too long with them).</summary>
        public List<(string Key, string Value)> Urls
        {
            get
            {
                var l = new List<(string Key, string Value)>();
                if (HostUrl != null) l.Add(("from", HostUrl));
                if (ReferrerUrl != null && ReferrerUrl != HostUrl) l.Add(("referrer", ReferrerUrl));
                return l;
            }
        }

        /// <summary>For the log line, when the stream has no URL: the zone ("downloaded from the internet (no URL saved)", "zone 0"); else null.</summary>
        public string Text => HostUrl == null && ReferrerUrl == null && Id.HasValue ? (Id == 3 ? "downloaded from the internet (no URL saved)" : "zone " + Id) : null;
    }

    /// <summary>
    /// Windows shortcut (.lnk, MS-SHLLINK): target, where the target was (local drive type / network), target times, arguments, icon,
    /// working folder, window state, the volume of the target and the machine that made the shortcut. Malformed parts are skipped.
    /// </summary>
    class Lnk
    {
        public string Target, Args, Net;
        public int DriveType = -1;   // 2 removable, 3 fixed, 4 network, 5 CD-ROM (also a mounted ISO)
        public DateTime? TargetCreated, TargetWritten;
        public long Size;
        public string Description, RelPath, WorkDir, IconLocation;
        public int IconIndex;
        public int ShowCmd = 1;      // 1 normal, 3 maximized, 7 minimized (not activated)
        public string VolumeSerial;  // 8 hex digits, of the target's volume (LinkInfo)
        public string VolumeLabel;
        public string EnvTarget;     // EnvironmentVariableDataBlock: target with %variables%
        public string EnvIcon;       // IconEnvironmentDataBlock: icon with %variables%
        public string Machine;       // TrackerDataBlock: NetBIOS name of the PC the shortcut was made on
        public string IdListTarget;  // the target from the shell item list (LinkTargetIDList)
        /// <summary>Where the target came from: "link info", "relative path", "environment block" or "item list".</summary>
        public string TargetFrom;

        public string Where => DriveType == 5 ? "on a CD/DVD or mounted ISO" : DriveType == 2 ? "on a removable drive" : DriveType == 4 || Net != null ? "on a network share" : null;

        /// <summary>The icon as Windows uses it: the expanded-variables block if there is one, else the icon location; with ",index".</summary>
        public string Icon
        {
            get
            {
                var i = !string.IsNullOrEmpty(EnvIcon) ? EnvIcon : IconLocation;
                return string.IsNullOrEmpty(i) ? null : i + "," + IconIndex;
            }
        }

        static ushort U16(byte[] b, int o) => o >= 0 && o + 2 <= b.Length ? BitConverter.ToUInt16(b, o) : (ushort)0;
        static int I32(byte[] b, int o) => o >= 0 && o + 4 <= b.Length ? BitConverter.ToInt32(b, o) : 0;
        static uint U32(byte[] b, int o) => o >= 0 && o + 4 <= b.Length ? BitConverter.ToUInt32(b, o) : 0;

        public static Lnk Parse(byte[] b)
        {
            if (b == null || b.Length < 76 || BitConverter.ToUInt32(b, 0) != 0x4C) return null;
            var l = new Lnk();
            uint flags = BitConverter.ToUInt32(b, 20);
            l.TargetCreated = Util.FtTime(BitConverter.ToInt64(b, 28));
            l.TargetWritten = Util.FtTime(BitConverter.ToInt64(b, 44));
            l.Size = BitConverter.ToUInt32(b, 52);
            l.IconIndex = BitConverter.ToInt32(b, 56);
            l.ShowCmd = BitConverter.ToInt32(b, 60);
            bool uni = (flags & 0x80) != 0;
            int o = 76;
            if ((flags & 1) != 0)
            {
                int n = U16(b, o);
                try { l.IdListTarget = IdList(b, o + 2, Math.Min(b.Length, o + 2 + n)); } catch { }
                o += 2 + n;
            }
            if ((flags & 2) != 0 && o + 28 <= b.Length)
            {
                int li = o; int size = I32(b, li), hs = I32(b, li + 4), lf = I32(b, li + 8);
                string suffix = Cstr(b, li + I32(b, li + 24), false);
                if (hs >= 0x24) { var su = Cstr(b, li + I32(b, li + 32), true); if (!string.IsNullOrEmpty(su)) suffix = su; }
                if ((lf & 1) != 0)
                {
                    int vol = li + I32(b, li + 12);
                    if (vol + 16 <= b.Length)
                    {
                        l.DriveType = I32(b, vol + 4);
                        l.VolumeSerial = U32(b, vol + 8).ToString("X8");
                        int lo = I32(b, vol + 12);
                        var label = lo == 0x14 ? Cstr(b, vol + I32(b, vol + 16), true) : Cstr(b, vol + lo, false);
                        if (!string.IsNullOrEmpty(label)) l.VolumeLabel = label;
                    }
                    var bp = hs >= 0x24 ? Cstr(b, li + I32(b, li + 28), true) : null;
                    if (string.IsNullOrEmpty(bp)) bp = Cstr(b, li + I32(b, li + 16), false);
                    l.Target = Join(bp, suffix);
                }
                if ((lf & 2) != 0)
                {
                    int cnr = li + I32(b, li + 20);
                    if (cnr + 12 <= b.Length) l.Net = Cstr(b, cnr + I32(b, cnr + 8), false);
                    if (l.Target == null) l.Target = Join(l.Net, suffix);
                }
                if (!string.IsNullOrEmpty(l.Target)) l.TargetFrom = "link info";
                o = li + Math.Max(size, 0);
            }
            // string data: name (description), relative path, working dir, arguments, icon
            var sd = new string[5];
            for (int i = 0, bit = 4; i < 5; i++, bit <<= 1)
            {
                if ((flags & bit) == 0 || o + 2 > b.Length) continue;
                int n = U16(b, o); o += 2;
                int bytes = uni ? n * 2 : n;
                if (o + bytes > b.Length) { o = b.Length; break; }
                sd[i] = uni ? Encoding.Unicode.GetString(b, o, bytes) : Encoding.Default.GetString(b, o, bytes);
                o += bytes;
            }
            l.Description = sd[0]; l.RelPath = sd[1]; l.WorkDir = sd[2]; l.Args = sd[3]; l.IconLocation = sd[4];
            // extra data blocks: size, signature, data; a size below 4 ends the list
            for (int guard = 0; guard < 64 && o + 8 <= b.Length; guard++)
            {
                int size = I32(b, o); uint sig = U32(b, o + 4);
                if (size < 8 || o + size > b.Length) break;
                switch (sig)
                {
                    case 0xA0000001:   // EnvironmentVariableDataBlock: ANSI (260 bytes), then Unicode (520 bytes)
                    case 0xA0000007:   // IconEnvironmentDataBlock: same layout
                        if (size >= 0x314)
                        {
                            var s = Fixed(b, o + 268, 520, true);
                            if (string.IsNullOrEmpty(s)) s = Fixed(b, o + 8, 260, false);
                            if (!string.IsNullOrEmpty(s)) { if (sig == 0xA0000001) l.EnvTarget = s; else l.EnvIcon = s; }
                        }
                        break;
                    case 0xA0000003:   // TrackerDataBlock: length, version, MachineID (16 bytes ANSI), droids
                        if (size >= 0x20)
                        {
                            var m = Fixed(b, o + 16, 16, false);
                            if (!string.IsNullOrEmpty(m)) l.Machine = m;
                        }
                        break;
                }
                o += size;
            }
            // an empty link info path ("") is no target either: the other places still count
            if (string.IsNullOrEmpty(l.Target) && !string.IsNullOrEmpty(l.EnvTarget)) { l.Target = l.EnvTarget; l.TargetFrom = "environment block"; }
            if (string.IsNullOrEmpty(l.Target) && !string.IsNullOrEmpty(l.IdListTarget)) { l.Target = l.IdListTarget; l.TargetFrom = "item list"; }
            if (string.IsNullOrEmpty(l.Target) && !string.IsNullOrEmpty(sd[1])) { l.Target = sd[1]; l.TargetFrom = "relative path"; }
            return l;
        }

        static readonly Guid MyComputer = new Guid("20D04FE0-3AEA-1069-A2D8-08002B30309D");

        /// <summary>
        /// (pure) The path in a shell item list: My Computer, a drive ("E:\"), then file entries (their long name from the 0xBEEF0004
        /// extension block, else the short name). Null when the list does not start like that (a control panel item, a URI, ...).
        /// </summary>
        internal static string IdList(byte[] b, int o, int end)
        {
            string path = null;
            bool root = false;
            for (int guard = 0; guard < 64 && o + 2 <= end; guard++)
            {
                int size = U16(b, o);
                if (size == 0) break;
                if (size < 3 || o + size > end) return null;
                int type = b[o + 2];
                if (!root && path == null)
                {
                    if (type == 0x1F && size >= 20 && new Guid(Sub(b, o + 4, 16)) == MyComputer) { root = true; o += size; continue; }
                    if ((type & 0x70) == 0x20) { root = true; }   // a list that starts at the drive
                    else return null;
                }
                if ((type & 0x70) == 0x20 && path == null)
                {
                    var drive = Cstr(b, o + 3, false, o + size);
                    if (string.IsNullOrEmpty(drive) || !Regex.IsMatch(drive, @"^[A-Za-z]:\\?$")) return null;
                    path = drive.Substring(0, 2);
                }
                else if ((type & 0x70) == 0x30 && path != null)
                {
                    var name = FileEntryName(b, o, size);
                    if (string.IsNullOrEmpty(name)) return null;
                    path += "\\" + name;
                }
                else if (path != null) return path;   // something else after the path: what we have
                o += size;
            }
            return path;
        }

        /// <summary>A file entry shell item's name: the long name of its 0xBEEF0004 block, else the primary (8.3 or full) name.</summary>
        static string FileEntryName(byte[] b, int o, int size)
        {
            int type = b[o + 2], end = o + size;
            bool uniName = (type & 0x04) != 0;
            int p = o + 14;   // size 2, type 1, unknown 1, file size 4, modified 4, attributes 2
            var primary = Cstr(b, p, uniName, end);
            if (primary == null) return null;
            int afterName = p + (uniName ? (primary.Length + 1) * 2 : primary.Length + 1);
            if ((afterName - o) % 2 == 1) afterName++;   // the extension block is 2-byte aligned
            // extension block: size 2, version 2, signature 4 (0xBEEF0004), ...
            if (afterName + 8 <= end && U32(b, afterName + 4) == 0xBEEF0004)
            {
                int ext = afterName, ver = U16(b, ext + 2);
                int n = 18;                // size, version, signature, created, accessed, identifier
                if (ver >= 7) n += 18;     // unknown, file reference, unknown
                if (ver >= 3) n += 2;      // long string size
                if (ver >= 9) n += 4;
                if (ver >= 8) n += 4;
                var lng = Cstr(b, ext + n, true, Math.Min(end, ext + U16(b, ext)));
                if (!string.IsNullOrEmpty(lng) && lng.IndexOf('\0') < 0) return lng;
            }
            return primary;
        }

        static byte[] Sub(byte[] b, int o, int n) { var r = new byte[n]; Buffer.BlockCopy(b, o, r, 0, n); return r; }

        /// <summary>A NUL-terminated string in a fixed-size field.</summary>
        static string Fixed(byte[] b, int o, int bytes, bool uni) => o + bytes <= b.Length ? Cstr(b, o, uni, o + bytes) : null;

        static string Join(string a, string b) => string.IsNullOrEmpty(b) ? a : string.IsNullOrEmpty(a) ? b : a.TrimEnd('\\') + "\\" + b;

        static string Cstr(byte[] b, int o, bool uni, int end = -1)
        {
            if (end < 0 || end > b.Length) end = b.Length;
            if (o <= 0 || o >= end) return null;
            int e = o;
            if (uni) { while (e + 1 < end && (b[e] != 0 || b[e + 1] != 0)) e += 2; return Encoding.Unicode.GetString(b, o, Math.Min(e, end) - o & ~1); }
            while (e < end && b[e] != 0) e++;
            return Encoding.Default.GetString(b, o, e - o);
        }
    }

    /// <summary>An Internet shortcut (.url): the URL and the icon it shows.</summary>
    sealed class UrlFile
    {
        public string Url, IconFile;
        public int IconIndex;

        /// <summary>(pure) The [InternetShortcut] values URL, IconFile, IconIndex.</summary>
        public static UrlFile Parse(string text)
        {
            var u = new UrlFile();
            foreach (var line in Regex.Split(text ?? "", "\r?\n"))
            {
                int i = line.IndexOf('=');
                if (i <= 0) continue;
                var k = line.Substring(0, i).Trim(); var v = Util.Clip(line.Substring(i + 1));
                if (k.Equals("URL", StringComparison.OrdinalIgnoreCase)) u.Url = v;
                else if (k.Equals("IconFile", StringComparison.OrdinalIgnoreCase)) u.IconFile = v;
                else if (k.Equals("IconIndex", StringComparison.OrdinalIgnoreCase) && int.TryParse(v, out var n)) u.IconIndex = n;
            }
            return u;
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

        /// <summary>A selector of named EventData fields ("NewProcessName", "Image", ...): stable across event versions, unlike indexes.</summary>
        public static EventLogPropertySelector Fields(params string[] names) =>
            new EventLogPropertySelector(names.Select(n => $"Event/EventData/Data[@Name='{n}']"));

        /// <summary>The selected fields of an event, in the selector's order (null for a missing one); all null if it cannot be read.</summary>
        public static string[] Values(EventRecord e, EventLogPropertySelector fields, int count)
        {
            var res = new string[count];
            try
            {
                var v = ((EventLogRecord)e).GetPropertyValues(fields);
                for (int i = 0; i < count && i < v.Count; i++) res[i] = v[i] == null ? null : Convert.ToString(v[i]);
            }
            catch { }
            return res;
        }
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
