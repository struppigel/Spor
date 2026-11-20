using System;
using System.Text.RegularExpressions;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Spor.Modules
{
    /// <summary>
    /// Timestomping: files whose timestamps were set back to hide when they arrived. Reads the NTFS change journal (USN) of every
    /// fixed NTFS drive: files with a "basic info change" (timestamps or attributes set) in the time window are scored:
    ///   creation time before the journal's "file create" event by more than a day   +4
    ///   creation / modification time on an exact hour +3, exact minute +2, zero sub-seconds +2, only milliseconds +1
    ///   (SetFileTime-style values; real NTFS times have 100 ns precision)
    ///   both times more than 7 days before the change, without a create event in the journal   +1
    /// Files with a score of MinScore or more are listed. Archive extraction sets round modification times (zip stores 2-second
    /// times), so one round time alone is not enough.
    /// </summary>
    class Timestomp : IModule
    {
        public string Id => "timestomp";
        public string Name => "TIMESTOMPING";
        public string Description => "files with faked timestamps (NTFS change journal)";

        const int MinScore = 3;
        /// <summary>With the whitelist: only file types malware runs or hides in. Sync clients (Nextcloud, Dropbox, OneDrive), driver
        /// installs and media tools set round times on documents, pictures and .inf/.cat files all the time.</summary>
        static readonly Regex Types = new Regex(@"\.(exe|dll|sys|scr|com|pif|cpl|ocx|drv|efi|msi|msp|jar|ps1|psm1|bat|cmd|vbs|vbe|js|jse|wsf|wsh|wsc|sct|hta|py|pyw|au3|a3x|ahk|lnk|url|zip|rar|7z|cab|iso|img|vhdx?)$", Util.RX);
        Ctx c;

        // ---- NTFS change journal ----
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern SafeFileHandle CreateFile(string name, uint access, FileShare share, IntPtr sa, FileMode mode, uint flags, IntPtr template);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool DeviceIoControl(SafeFileHandle h, uint code, byte[] inBuf, int inSize, byte[] outBuf, int outSize, out int returned, IntPtr ov);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern SafeFileHandle OpenFileById(SafeFileHandle volume, ref FILE_ID_DESCRIPTOR id, uint access, FileShare share, IntPtr sa, uint flags);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern uint GetFinalPathNameByHandle(SafeFileHandle h, StringBuilder path, int size, uint flags);

        [StructLayout(LayoutKind.Sequential)]
        struct FILE_ID_DESCRIPTOR { public int Size; public int Type; public long FileId; public long Pad; }   // Type 0 = 64-bit file ID (union with 128-bit)

        const uint FSCTL_QUERY_USN_JOURNAL = 0x000900f4, FSCTL_READ_USN_JOURNAL = 0x000900bb;
        const uint USN_REASON_FILE_CREATE = 0x100, USN_REASON_FILE_DELETE = 0x200, USN_REASON_RENAME_OLD = 0x1000, USN_REASON_RENAME_NEW = 0x2000,
                   USN_REASON_BASIC_INFO_CHANGE = 0x8000;

        public void Execute(Ctx ctx)
        {
            c = ctx;
            c.Out.Comment($"Files whose timestamps were set in the last {c.Opt.Days} days (NTFS change journal), listed from score {MinScore}: +4 creation time before the real creation,");
            c.Out.Comment("+3 round creation time, +1 millisecond-only creation time, +1 round modification time, +1 both times over 7 days old" +
                          (Rules.Whitelist ? "; only programs, scripts, shortcuts, archives and disk images." : "."));
            var t = new Table("@info changed", "score", "!status", "created", "modified", "*file");
            var found = new List<(DateTime Changed, int Score, string Path, string Status, DateTime Created, DateTime Modified, List<string> Signals)>();
            foreach (var d in DriveInfo.GetDrives())
            {
                try { if (d.DriveType != DriveType.Fixed || d.DriveFormat != "NTFS") continue; } catch { continue; }
                var drive = d.Name.TrimEnd('\\');
                try { Scan(drive, found); }
                catch (Exception e) { c.Err.Add(drive + ": " + e.Message); }
            }
            foreach (var x in found.OrderByDescending(x => x.Score).ThenByDescending(x => x.Changed))
            {
                t.Add(Log.T(x.Changed), x.Score.ToString(), x.Status, x.Created.ToString("yyyy-MM-dd HH:mm:ss.fffffff"), x.Modified.ToString("yyyy-MM-dd HH:mm:ss.fffffff"), x.Path);
                foreach (var s in x.Signals) t.More("signal", s);
                if (x.Score < MinScore) continue;
                var fl = new List<string> { "!timestomped" };
                c.Event(x.Changed, "STP", x.Path, $"timestamps set (score {x.Score}): created {x.Created:yyyy-MM-dd HH:mm:ss.fffffff}, modified {x.Modified:yyyy-MM-dd HH:mm:ss.fffffff}", fl);
            }
            t.WriteTo(c.Out);
        }

        void Scan(string drive, List<(DateTime, int, string, string, DateTime, DateTime, List<string>)> found)
        {
            var sw = Stopwatch.StartNew();
            using (var vol = CreateFile(@"\\.\" + drive, 0x80000000, FileShare.ReadWrite | FileShare.Delete, IntPtr.Zero, FileMode.Open, 0, IntPtr.Zero))
            {
                if (vol.IsInvalid) throw new Exception("cannot open the volume (error " + Marshal.GetLastWin32Error() + ")");
                var jd = new byte[80];
                if (!DeviceIoControl(vol, FSCTL_QUERY_USN_JOURNAL, null, 0, jd, jd.Length, out _, IntPtr.Zero))
                    throw new Exception("no change journal (error " + Marshal.GetLastWin32Error() + ")");
                ulong journalId = BitConverter.ToUInt64(jd, 0);
                long firstUsn = BitConverter.ToInt64(jd, 8), nextUsn = BitConverter.ToInt64(jd, 16);

                var infoChange = new Dictionary<long, DateTime>();   // file ID -> newest basic info change
                var created = new Dictionary<long, DateTime>();      // file ID -> first create
                // NTFS tunneling: when a name disappears from a folder (delete, rename away) and a file gets that name again within 15 s,
                // NTFS gives it the old creation time. Safe-save (write temp, rename over the original) does this all the time.
                var vacated = new Dictionary<string, List<DateTime>>(StringComparer.OrdinalIgnoreCase);   // "parent|name" -> times
                var named = new Dictionary<long, List<(DateTime T, string Key)>>();                       // file ID -> (create / rename-to time, "parent|name")
                DateTime? earliest = null; long records = 0;
                var req = new byte[40];   // READ_USN_JOURNAL_DATA_V0
                var buf = new byte[1 << 20];
                long usn = firstUsn;
                while (usn < nextUsn)
                {
                    Array.Clear(req, 0, req.Length);
                    BitConverter.GetBytes(usn).CopyTo(req, 0);
                    BitConverter.GetBytes(USN_REASON_FILE_CREATE | USN_REASON_BASIC_INFO_CHANGE | USN_REASON_FILE_DELETE | USN_REASON_RENAME_OLD | USN_REASON_RENAME_NEW).CopyTo(req, 8);
                    BitConverter.GetBytes(journalId).CopyTo(req, 32);
                    if (!DeviceIoControl(vol, FSCTL_READ_USN_JOURNAL, req, req.Length, buf, buf.Length, out int n, IntPtr.Zero) || n <= 8) break;
                    long next = BitConverter.ToInt64(buf, 0);
                    for (int o = 8; o + 60 <= n;)
                    {
                        int len = BitConverter.ToInt32(buf, o);
                        if (len <= 0) break;
                        if (BitConverter.ToUInt16(buf, o + 4) == 2)   // USN_RECORD_V2
                        {
                            long id = BitConverter.ToInt64(buf, o + 8), parent = BitConverter.ToInt64(buf, o + 16);
                            var ts = DateTime.FromFileTimeUtc(BitConverter.ToInt64(buf, o + 32));
                            uint reason = BitConverter.ToUInt32(buf, o + 40), attr = BitConverter.ToUInt32(buf, o + 52);
                            int nl = BitConverter.ToUInt16(buf, o + 56), no = BitConverter.ToUInt16(buf, o + 58);
                            var key = parent + "|" + (o + no + nl <= n ? Encoding.Unicode.GetString(buf, o + no, nl) : "");
                            records++;
                            if (earliest == null || ts < earliest) earliest = ts;
                            if ((attr & 0x10) == 0 && ts >= c.Since.AddMinutes(-1))   // not a directory
                            {
                                if ((reason & USN_REASON_BASIC_INFO_CHANGE) != 0 && (!infoChange.TryGetValue(id, out var x) || ts > x)) infoChange[id] = ts;
                                if ((reason & USN_REASON_FILE_CREATE) != 0 && (!created.TryGetValue(id, out var y) || ts < y)) created[id] = ts;
                                if ((reason & (USN_REASON_FILE_DELETE | USN_REASON_RENAME_OLD)) != 0)
                                { if (!vacated.TryGetValue(key, out var l)) vacated[key] = l = new List<DateTime>(); l.Add(ts); }
                                if ((reason & (USN_REASON_FILE_CREATE | USN_REASON_RENAME_NEW)) != 0)
                                { if (!named.TryGetValue(id, out var l)) named[id] = l = new List<(DateTime, string)>(); l.Add((ts, key)); }
                            }
                        }
                        o += len;
                    }
                    if (next <= usn) break;
                    usn = next;
                }
                var journal = $"{drive} change journal: {records} records{(earliest.HasValue ? " back to " + Log.T(earliest) : "")}, {infoChange.Count} files with changed timestamps";
                if (earliest.HasValue && earliest > c.Since.AddDays(2))
                    journal += $"; ATTENTION: it only covers {(DateTime.UtcNow - earliest.Value).TotalHours:N1} hours (ring buffer), older timestomping is not visible";
                bool Tunneled(long id) => named.TryGetValue(id, out var l) && l.Any(x => vacated.TryGetValue(x.Key, out var v) && v.Any(t => t <= x.T.AddSeconds(1) && t >= x.T.AddSeconds(-16)));
                int tunneled = 0, skippedType = 0;

                int gone = 0, frst = 0;
                foreach (var kv in infoChange)
                {
                    var path = PathOf(vol, kv.Key);
                    if (path == null || !File.Exists(path)) { gone++; continue; }
                    var m = Rules.DrivePath.Match(path);
                    if (Rules.Whitelist && (!Types.IsMatch(path) || (c.TrustedFile(path) && Signature.Applies(path)))) { skippedType++; continue; }   // signed executables in Windows / Program Files
                    DateTime ct, mt;
                    try { ct = File.GetCreationTimeUtc(path); mt = File.GetLastWriteTimeUtc(path); } catch { continue; }
                    int score = 0; var sig = new List<string>();
                    Round(ct, "creation time", true, ref score, sig);
                    Round(mt, "modification time", false, ref score, sig);
                    if (created.TryGetValue(kv.Key, out var cr))
                    {
                        if (ct < cr.AddDays(-1))
                        {
                            if (Tunneled(kv.Key)) tunneled++;   // safe-save: the name was replaced within 15 s, NTFS kept the old creation time
                            else { score += 4; sig.Add($"creation time {ct:yyyy-MM-dd HH:mm:ss} is before the file was actually created ({cr:yyyy-MM-dd HH:mm:ss}, change journal)"); }
                        }
                    }
                    else if (score > 0 && ct < kv.Value.AddDays(-7) && mt < kv.Value.AddDays(-7))
                    {
                        score += 1; sig.Add("both times are more than 7 days before the timestamp change");
                    }
                    if (score < (Rules.Whitelist ? MinScore : 1)) continue;
                    if (Rules.Whitelist && FrstSqlite(path, kv.Value)) { frst++; continue; }
                    found.Add((kv.Value, score, c.F(path).Path, c.F(path).Status, ct, mt, sig));
                }
                // one line per drive: what was read and what was left out
                var left = new List<string>();
                if (gone > 0) left.Add($"{gone} deleted since");
                if (skippedType > 0 && Rules.Whitelist) left.Add($"{skippedType} data files or signed programs in Windows / Program Files");
                if (frst > 0) left.Add($"{frst} FRST SQLite DLLs (C:\\FRST\\bin)");
                if (tunneled > 0) left.Add($"{tunneled} NTFS tunneling (safe-save, normal)");
                c.Out.Comment(journal + (left.Count > 0 ? "; not scored: " + string.Join(", ", left) : "") + $" ({sw.Elapsed.TotalSeconds:N1} s)");
            }
        }

        /// <summary>
        /// Round values are what SetFileTime-based tools write; real NTFS times have 100 ns precision. Creation times count more:
        /// archive extraction and installers set round MODIFICATION times all the time (zip stores 2-second times), creation times rarely.
        /// </summary>
        static readonly Regex FrstExe = new Regex(@"\\FRST(64)?( ?\(\d+\))?\.exe$", RegexOptions.IgnoreCase);

        /// <summary>
        /// FRST unpacks its SQLite DLL to C:\FRST\bin with the file's original (old, whole-second) times every time it runs.
        /// Not counted only if it is exactly that file on the system drive and an FRST program ran within 15 minutes of the timestamp change.
        /// </summary>
        bool FrstSqlite(string path, DateTime changed)
        {
            if (!Regex.IsMatch(path, @"^[A-Z]:\\FRST\\bin\\sqlite3(_x64)?\.dll$", RegexOptions.IgnoreCase)
                || !path.Substring(0, 2).Equals(c.SystemDrive, StringComparison.OrdinalIgnoreCase)) return false;
            return c.Events.Any(e => e.Path != null && FrstExe.IsMatch(e.Path) && Math.Abs((e.T - changed).TotalMinutes) <= 15);
        }

        static void Round(DateTime t, string what, bool creation, ref int score, List<string> sig)
        {
            if (t.Ticks % 10000000 == 0)
            {
                var how = t.Minute == 0 && t.Second == 0 ? "on an exact hour" : t.Second == 0 ? "on an exact minute" : "with zero sub-seconds";
                score += creation ? 3 : 1;
                sig.Add($"{what} {how} ({t:yyyy-MM-dd HH:mm:ss.fffffff})");
            }
            else if (creation && t.Ticks % 10000 == 0) { score += 1; sig.Add($"{what} is only millisecond-precise ({t:yyyy-MM-dd HH:mm:ss.fffffff})"); }
        }

        static string PathOf(SafeFileHandle vol, long id)
        {
            var d = new FILE_ID_DESCRIPTOR { Size = Marshal.SizeOf(typeof(FILE_ID_DESCRIPTOR)), Type = 0, FileId = id };
            using (var h = OpenFileById(vol, ref d, 0x80 /* FILE_READ_ATTRIBUTES */, FileShare.ReadWrite | FileShare.Delete, IntPtr.Zero, 0x02000000 /* backup semantics */))
            {
                if (h.IsInvalid) return null;
                var sb = new StringBuilder(32768);
                uint n = GetFinalPathNameByHandle(h, sb, sb.Capacity, 0);
                if (n == 0 || n >= sb.Capacity) return null;
                var p = sb.ToString();
                return p.StartsWith(@"\\?\UNC\") ? @"\\" + p.Substring(8) : p.StartsWith(@"\\?\") ? p.Substring(4) : p;
            }
        }
    }
}
