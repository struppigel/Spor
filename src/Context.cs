using System;
using System.Diagnostics;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace Spor
{
    class Options
    {
        public int Days = 30;
        public bool Whitelist = true;
        public bool Aggressive;           // command line -aggressive only (trial, see Aggr): never set by the window
        public string ExtraNoise = "";
        public string Algo = "SHA256";
        public int MaxMB = 500;
        public bool NoHash;
        public bool NoOpen;
        public string Out;
        public string Profile = "default";   // Scanner.Profiles: which modules run when Modules is null
        public HashSet<string> Modules;   // null = the profile's modules
        public int UsbMax = 2000;         // USB DRIVES: items listed per drive
        public int UsbDepth = 8;          // USB DRIVES: folder levels below a removable drive's root
        public int PerDir = 4;            // entries per folder before "+N more"
        public int Max = 20;              // remote access: entries per log; webcam: programs
        public int HistoryMax = 40;       // ClickFix: suspicious PowerShell history lines
        public int HistoryTail = 15;      // ClickFix: last unfiltered history lines
        public int Batch = 20;            // Amcache: entries written within 5 s that count as an inventory scan
        public int Burst = 5;             // Amcache: shown entries within 5 s that count as an install/update burst
    }

    class Profile
    {
        public string Sid, Path, User;
    }

    class Hive
    {
        public Profile P;
        public RegistryKey Root;
        public string User => P.User;
    }

    /// <summary>
    /// One timeline event. File events (Path set) of the same file within 2 minutes are merged into one line;
    /// text events (Path null) are shown as they are.
    /// </summary>
    class TEvent
    {
        public DateTime T;
        public string Src;      // source tag, see Timeline.Tags
        public string Path;     // file, or null
        public string Text;     // for text events, or shown instead of the path
        public string Extra;    // e.g. "UA 5x", PCA exit code
        public List<string> Flags;
        public bool NoHash;
        public List<(string Key, string Value)> More;   // indented "key: value" lines under a text event (e.g. Uninstall keys of a grouped install)
        public string Known;    // Autodetect: "known malware <family>: <note>", first in the line's details
        public int? Pid;        // process events (PROC, 4688, SYSMON): different processes of one program stay apart when flagged
        public string Aggr;     // text events: why the aggressive whitelist hides the timeline line (Aggr), else null
    }

    /// <summary>Shared state: options, users and hives, timeline, findings, file display and hashes.</summary>
    class Ctx : IDisposable
    {
        public readonly Options Opt;
        public Log Out = new Log();   // the running module's detail section
        public readonly DateTime Since;
        /// <summary>The PC's UTC offset when the scan started. FRST shows file times with it, so FILES does too.</summary>
        public readonly TimeSpan LocalOffset;
        public readonly string SystemDrive = (Environment.GetEnvironmentVariable("SystemDrive") ?? "C:").TrimEnd('\\');
        public readonly string WinDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        public readonly List<string> Err = new List<string>();   // errors of the running module
        public readonly List<Profile> Profiles = new List<Profile>();
        public readonly List<TEvent> Events = new List<TEvent>();
        public readonly List<(DateTime? T, string Module, string Text)> Findings = new List<(DateTime?, string, string)>();
        /// <summary>Values for Autodetect (see Observe).</summary>
        public readonly List<(string Kind, string Value, DateTime? T, string Item)> Observed = new List<(string, string, DateTime?, string)>();
        public readonly Dictionary<string, string> Sha256 = new Dictionary<string, string>(Util.IC);   // display path -> hash
        public readonly Dictionary<string, string> AmSha1 = new Dictionary<string, string>(Util.IC);   // display path or name -> Amcache SHA1
        public readonly Dictionary<string, string> Signer = new Dictionary<string, string>(Util.IC);    // display path -> signature status, signer, thumbprint
        public readonly Dictionary<string, string> Version = new Dictionary<string, string>(Util.IC);   // display path -> version information
        public readonly Dictionary<string, string> Md5 = new Dictionary<string, string>(Util.IC);       // display path -> MD5 (FRST Search logs give only MD5)
        public readonly Dictionary<string, (long Size, DateTime Created, DateTime Modified)> Meta =
            new Dictionary<string, (long, DateTime, DateTime)>(Util.IC);                                 // display path -> size, created, modified (UTC)
        /// <summary>Display path -> real path of the files to hash (F with hash on); FILES hashes the ones it lists (HashFile).</summary>
        public readonly Dictionary<string, string> ToHash = new Dictionary<string, string>(Util.IC);

        /// <summary>
        /// Hashes a file F queued (ToHash) into Sha256 and Md5: the chosen algorithm and MD5 in one read (MD5 to meet FRST Search
        /// lines). A file that cannot be read any more stays without a hash ("not hashed").
        /// </summary>
        public void HashFile(string disp)
        {
            if (!ToHash.TryGetValue(disp, out var real) || Sha256.ContainsKey(disp)) return;
            var sw = Stopwatch.StartNew();
            try
            {
                using (var fs = new FileStream(real, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1 << 20, FileOptions.SequentialScan))
                using (var a = HashAlgorithm.Create(Opt.Algo))
                using (var m = MD5.Create())
                {
                    bool both = !Opt.Algo.Equals("MD5", StringComparison.OrdinalIgnoreCase);
                    var buf = new byte[1 << 20]; int n;
                    while ((n = fs.Read(buf, 0, buf.Length)) > 0) { a.TransformBlock(buf, 0, n, null, 0); if (both) m.TransformBlock(buf, 0, n, null, 0); HashBytes += n; }
                    a.TransformFinalBlock(buf, 0, 0);
                    Sha256[disp] = BitConverter.ToString(a.Hash).Replace("-", "");
                    if (both) { m.TransformFinalBlock(buf, 0, 0); Md5[disp] = BitConverter.ToString(m.Hash).Replace("-", ""); }
                }
            }
            catch { }
            HashFiles++; HashTime += sw.Elapsed;
        }

        /// <summary>What hashing cost this scan (for the end line: where the scan's time goes).</summary>
        public int HashFiles;
        public long HashBytes;
        public TimeSpan HashTime;

        /// <summary>Side-loading results per host program (Sideload.For), so each program is checked once per scan.</summary>
        public readonly Dictionary<string, List<SideloadHit>> Sideloads = new Dictionary<string, List<SideloadHit>>(Util.IC);
        /// <summary>Side-loading details already on a timeline line (Sideload.Claim), so no line gets them twice.</summary>
        public readonly HashSet<string> SideloadLines = new HashSet<string>(Util.IC);

        /// <summary>
        /// Program starts seen by modules (RUNNING PROCESSES, process creation events): a parent program started a child program
        /// (its direct parent) with this command line.
        /// </summary>
        public readonly List<(string Parent, string Child, string CommandLine, DateTime? T)> Launches = new List<(string, string, string, DateTime?)>();
        /// <summary>Process starts recorded by Security 4688 and Sysmon 1 (PID, start, image), to name exited parents in RUNNING PROCESSES.</summary>
        public readonly List<(int Pid, DateTime T, string Image)> ProcessStarts = new List<(int, DateTime, string)>();

        /// <summary>
        /// Removable and USB volumes (USB DRIVES): volume serial (8 hex digits, as in Prefetch's \VOLUME{...-XXXXXXXX}) -> label, and drive
        /// letters ("E:") -> (label, when the device that has the letter now was last connected; null when unknown). Correlate names the USB
        /// drive on timeline lines of files on them: by serial always, by letter only after that connect (the letter may have been another
        /// stick or a DVD before).
        /// </summary>
        public readonly Dictionary<string, string> UsbVolumes = new Dictionary<string, string>(Util.IC);
        public readonly Dictionary<string, (string Label, DateTime? Since)> UsbLetters = new Dictionary<string, (string, DateTime?)>(Util.IC);

        /// <summary>Script-runtime launchers (Correlate): never hidden by the signer whitelist, like interpreters.</summary>
        public readonly HashSet<string> RuntimeLaunchers = new HashSet<string>(Util.IC);

        /// <summary>Names.RenamedDetail per program: "original name X", or null when not renamed.</summary>
        public readonly Dictionary<string, string> Renamed = new Dictionary<string, string>(Util.IC);

        /// <summary>A file line from c.File() whose signature is missing or not valid.</summary>
        public static bool BadSig(string status) => status != null && (status.Contains("unsigned") || status.Contains(" signature"));
        public string Module = "";

        List<Hive> hives;
        string tmp;
        readonly Dictionary<string, string> status = new Dictionary<string, string>(Util.IC);
        readonly Dictionary<string, string> shortNames = new Dictionary<string, string>(Util.IC);
        readonly Dictionary<string, string> caseCache = new Dictionary<string, string>(Util.IC);

        public Ctx(Options opt)
        {
            Opt = opt;
            Since = DateTime.UtcNow.AddDays(-opt.Days);
            LocalOffset = TimeZoneInfo.Local.GetUtcOffset(DateTime.UtcNow);
            try
            {
                using (var pl = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"))
                    foreach (var sid in pl.GetSubKeyNames())
                    {
                        if (!Regex.IsMatch(sid, @"^S-1-5-21-[\d-]+$")) continue;
                        using (var k = pl.OpenSubKey(sid))
                        {
                            var pp = Environment.ExpandEnvironmentVariables(Convert.ToString(k?.GetValue("ProfileImagePath")) ?? "").TrimEnd('\\');
                            if (pp.Length > 0) Profiles.Add(new Profile { Sid = sid, Path = pp, User = Util.Leaf(pp) });
                        }
                    }
            }
            catch (Exception e) { Err.Add("ProfileList: " + e.Message); }

            // 8.3 short folder names -> long names (ShimCache and others keep both, e.g. C:\Users\KELVIN~1)
            foreach (var d in Profiles.Select(p => p.Path).Concat(new[] { Env("ProgramFiles"), Env("ProgramFiles(x86)"), Env("ProgramData"), WinDir }))
            {
                if (string.IsNullOrEmpty(d) || !Directory.Exists(d)) continue;
                var sp = Native.ShortPath(d);
                if (sp != null && !sp.Equals(d, StringComparison.OrdinalIgnoreCase)) shortNames[sp.TrimEnd('\\')] = d;
            }
        }

        public static string Env(string n) => Environment.GetEnvironmentVariable(n);

        /// <summary>More than one user profile: show user names in the log.</summary>
        public bool MultiUser => Profiles.Count > 1;

        public string UserOf(string sid) => Profiles.FirstOrDefault(p => p.Sid.Equals(sid, StringComparison.OrdinalIgnoreCase))?.User ?? sid;

        /// <summary>"[user] " if there is more than one user, else "".</summary>
        public string U(string user) => MultiUser && !string.IsNullOrEmpty(user) ? "[" + user + "] " : "";

        /// <summary>A timeline event; returns it, or null when it is older than the time window (not added).</summary>
        public TEvent Event(DateTime? t, string src, string path, string extra = null, List<string> flags = null, string text = null, bool noHash = false,
                          List<(string Key, string Value)> more = null, int? pid = null)
        {
            if (!t.HasValue || t.Value < Since) return null;
            var e = new TEvent { T = t.Value, Src = src, Path = path, Text = text, Extra = extra, Flags = flags, NoHash = noHash, More = more, Pid = pid };
            Events.Add(e);
            return e;
        }

        /// <summary>
        /// A value for Autodetect (known-malware patterns): kind = path, task, run, service, cmd, software, company or domain; item = how a
        /// hit is shown in the SUMMARY (null: the kind and the value). Costs one list entry; matching runs once after all modules.
        /// Timeline paths and the signer / company of checked files are taken by Autodetect itself.
        /// </summary>
        public void Observe(string kind, string value, DateTime? t = null, string item = null)
        {
            if (!string.IsNullOrWhiteSpace(value)) Observed.Add((kind, value, t, item));
        }

        /// <summary>Paths for Autodetect that only pass a hit on (to their timeline lines and Related), never a SUMMARY line of their own.</summary>
        public readonly List<(string Path, DateTime? T)> ObservedQuiet = new List<(string, DateTime?)>();

        /// <summary>
        /// A path for Autodetect that is no finding by itself: a file a program's prefetch entry loaded (a fake Python's 100 library files
        /// would fill the SUMMARY). A hit marks the file's timeline lines and the files related to it (Relate: the program that loaded it).
        /// </summary>
        public void ObserveQuiet(string path, DateTime? t = null)
        {
            if (!string.IsNullOrWhiteSpace(path)) ObservedQuiet.Add((path, t));
        }

        public void Find(string text) => Findings.Add((null, Module, text));
        public void Find(DateTime? t, string text) => Findings.Add((t, Module, text));
        /// <summary>A finding with indented "key: value" sub-lines under its SUMMARY line (a Defender detection's files, ...).</summary>
        public void Find(DateTime? t, string text, List<(string Key, string Value)> more)
        {
            Findings.Add((t, Module, text));
            if (more == null || more.Count == 0) return;
            // the same text again (Defender logs a detection again when it finds another file): its sub-lines are added, the SUMMARY
            // writes one line for findings that read the same in the same second
            if (FindingMore.TryGetValue(text, out var had)) had.AddRange(more.Where(m => !had.Contains(m)));
            else FindingMore[text] = new List<(string Key, string Value)>(more);
        }
        /// <summary>
        /// A finding with flags, written like every other item line: "item => details &lt;==== !flags" (details left out when null).
        /// Up to Spor 0.7.1 the flags were inside the text ("x.pdf.lnk  !double-extension  (loaded by y.exe)").
        /// </summary>
        public void Find(DateTime? t, string item, string details, List<string> flags) => FindAs(Module, t, item, details, flags);

        /// <summary>A finding with flags and sub-lines (a drop folder and its group: line).</summary>
        public void Find(DateTime? t, string item, string details, List<string> flags, List<(string Key, string Value)> more) =>
            FindAs(Module, t, item, details, flags, more);

        /// <summary>Find with flags for another module than the running one (findings Correlate decides on after all modules).</summary>
        public void FindAs(string module, DateTime? t, string item, string details, List<string> flags, List<(string Key, string Value)> more = null)
        {
            var text = string.IsNullOrEmpty(details) ? item : item + " => " + details;
            Findings.Add((t, module, text));
            if (more != null && more.Count > 0)
            {
                if (FindingMore.TryGetValue(text, out var hadMore)) hadMore.AddRange(more.Where(m => !hadMore.Contains(m)));
                else FindingMore[text] = new List<(string Key, string Value)>(more);
            }
            if (flags == null || flags.Count == 0) return;
            var key = module + "\n" + text;
            FindingFlags[key] = FindingFlags.TryGetValue(key, out var had) ? had.Union(flags).ToList() : flags.Distinct().ToList();
        }

        /// <summary>
        /// ShimCache findings of flagged files modified before the time window (ExecEvidence). Correlate writes them after all modules:
        /// a copied file keeps the original's modification time, so with later evidence of the file its time becomes a detail of that
        /// evidence instead of a SUMMARY line at the old time (Correlate.FoldCopiedShimCache).
        /// </summary>
        public readonly List<(DateTime? T, string Module, string Path, string Item, string Details, List<string> Flags)> PendingShim =
            new List<(DateTime?, string, string, string, string, List<string>)>();

        readonly Dictionary<string, string> lolbinCopies = new Dictionary<string, string>(Util.IC);

        /// <summary>
        /// Rules.LolbinCopy for a file on disk (its original name, signature and Hidden attribute), cached: "copy of MSBuild.exe outside its
        /// usual folders; ...", or null. fallbackOriginal: the original name another source recorded (Amcache), for a file that is gone.
        /// </summary>
        public string LolbinCopy(string p, string fallbackOriginal = null)
        {
            if (string.IsNullOrEmpty(p) || !Rules.DrivePath.IsMatch(p)) return null;
            var real = RealCase(p);
            var key = real + "|" + fallbackOriginal;   // a gone file is decided by the original name it is given
            if (lolbinCopies.TryGetValue(key, out var r)) return r;
            string orig = fallbackOriginal, sig = null;
            bool hidden = false;
            if (System.IO.File.Exists(real))
            {
                if (Regex.IsMatch(real, @"\.exe$", Util.RX)) orig = Signature.Names(real).Original ?? fallbackOriginal;
                if (Rules.CopiedLolbin(orig) || Rules.CopiedLolbin(Util.Leaf(real)))   // only these get the signature check here
                {
                    sig = Signature.Check(real).Status;
                    try { hidden = (System.IO.File.GetAttributes(real) & FileAttributes.Hidden) != 0; } catch { }
                }
            }
            return lolbinCopies[key] = Rules.LolbinCopy(real, orig, sig, hidden);
        }

        /// <summary>Files NEW FILES flagged !timestomped (old times, written in the window): TIMESTOMPING lists them too.</summary>
        public readonly List<(string Path, DateTime Created, DateTime Modified, DateTime Changed)> Backdated = new List<(string, DateTime, DateTime, DateTime)>();

        readonly Dictionary<string, HashSet<string>> pathMarks = new Dictionary<string, HashSet<string>>(Util.IC);
        readonly List<(string Folder, string Flag, bool Unsigned)> folderMarks = new List<(string, string, bool)>();

        /// <summary>
        /// A flag for every timeline event of a file, whichever module saw it (Defender detected it, a persisted interpreter outside
        /// its install folder): ApplyMarks puts it on them before the timeline is built, so the file's lines link up in the SUMMARY.
        /// </summary>
        public void MarkPath(string path, string flag)
        {
            if (string.IsNullOrEmpty(path) || !Rules.DrivePath.IsMatch(path)) return;
            if (!pathMarks.TryGetValue(path, out var set)) pathMarks[path] = set = new HashSet<string>();
            set.Add(flag);
        }

        /// <summary>
        /// A flag for the events of every file inside a folder (a Defender path exclusion): see MarkPath. unsigned: only files without a
        /// valid signature (a game folder a user excluded holds hundreds of signed files; a dropper's payload is unsigned).
        /// </summary>
        public void MarkFolder(string folder, string flag, bool unsigned = false)
        {
            if (string.IsNullOrEmpty(folder) || !Rules.DrivePath.IsMatch(folder)) return;
            folderMarks.Add((folder.TrimEnd('\\') + "\\", flag, unsigned));
        }

        /// <summary>
        /// Files that stand for a value Autodetect may match: a Startup shortcut's target, an installed program's folder (ends with "\").
        /// Key: the matched path, or the item text an observation was made with (Observe). A known-malware hit passes its mark on to them.
        /// </summary>
        public readonly Dictionary<string, List<(string Path, string Via)>> Related = new Dictionary<string, List<(string, string)>>(Util.IC);

        /// <summary>
        /// See Related. via: how the mark reads on the related file's lines ("loaded NODE.EXE"); null: "related to &lt;matched file&gt;".
        /// path: a full path, or a bare program name (a prefetch entry without its path, "CHARMAP.EXE").
        /// </summary>
        public void Relate(string key, string path, string via = null)
        {
            if (string.IsNullOrEmpty(key) || string.IsNullOrEmpty(path)) return;
            if (!Rules.DrivePath.IsMatch(path) && (path.IndexOf('\\') >= 0 || path.IndexOf('.') < 0)) return;
            if (!Related.TryGetValue(key, out var list)) Related[key] = list = new List<(string, string)>();
            if (!list.Any(r => r.Path.Equals(path, StringComparison.OrdinalIgnoreCase) && r.Via == via)) list.Add((path, via));
        }

        /// <summary>The flags MarkPath and MarkFolder give a file (empty when none).</summary>
        public List<string> MarksOf(string path)
        {
            var f = new List<string>();
            if (string.IsNullOrEmpty(path)) return f;
            if (pathMarks.TryGetValue(path, out var set)) f.AddRange(set);
            foreach (var (folder, flag, unsigned) in folderMarks)
                if (path.StartsWith(folder, StringComparison.OrdinalIgnoreCase) && !f.Contains(flag) && (!unsigned || !SignedOk(path))) f.Add(flag);
            return f;
        }

        /// <summary>Puts the marks on the timeline events of the marked files (new flag lists: modules may share theirs between events).</summary>
        public void ApplyMarks()
        {
            if (pathMarks.Count == 0 && folderMarks.Count == 0) return;
            foreach (var e in Events)
            {
                if (e.Path == null) continue;
                var add = MarksOf(e.Path).Where(f => e.Flags == null || !e.Flags.Contains(f)).ToList();
                if (add.Count > 0) e.Flags = (e.Flags ?? new List<string>()).Concat(add).ToList();
            }
        }

        /// <summary>The flags of a file with !lolbin-copy added when LolbinCopy finds one (a new list).</summary>
        public List<string> WithLolbinCopy(string p, IEnumerable<string> flags)
        {
            var f = (flags ?? Enumerable.Empty<string>()).ToList();
            if (LolbinCopy(p) != null && !f.Contains(Rules.LolbinCopyFlag)) f.Add(Rules.LolbinCopyFlag);
            return f;
        }
        /// <summary>Flags of a finding (Find with flags), by module and text.</summary>
        public readonly Dictionary<string, List<string>> FindingFlags = new Dictionary<string, List<string>>();
        /// <summary>Sub-lines of a finding, by its text (Find with sub-lines).</summary>
        public readonly Dictionary<string, List<(string Key, string Value)>> FindingMore = new Dictionary<string, List<(string Key, string Value)>>();
        /// <summary>
        /// A finding whose time is not when something happened: when = what the time is ("file modified", "key changed", ...).
        /// Not written to the line (the summary's tag and text stay as parsers know them); the summary's comment and the LEGEND explain the times.
        /// </summary>
        public void Find(DateTime? t, string text, string when, string from = null) => Findings.Add((t, Module, text));

        /// <summary>A private temp folder, deleted at the end.</summary>
        public string Temp
        {
            get
            {
                if (tmp == null)
                {
                    tmp = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "spor_" + Guid.NewGuid().ToString("N").Substring(0, 8));
                    Directory.CreateDirectory(tmp);
                }
                return tmp;
            }
        }

        /// <summary>Registry hives of all user profiles: loaded ones from HKU, others from a copy of NTUSER.DAT (+ logs).</summary>
        public List<Hive> Hives
        {
            get
            {
                if (hives != null) return hives;
                hives = new List<Hive>();
                foreach (var p in Profiles)
                {
                    RegistryKey k = null;
                    try { k = Registry.Users.OpenSubKey(p.Sid); } catch { }
                    if (k == null)
                    {
                        var nt = System.IO.Path.Combine(p.Path, "NTUSER.DAT");
                        if (!System.IO.File.Exists(nt)) continue;
                        try
                        {
                            var dst = System.IO.Path.Combine(Temp, p.Sid + ".dat");
                            foreach (var s in new[] { "", ".LOG1", ".LOG2" })   // the logs let Windows replay changes not yet in the hive file
                                if (System.IO.File.Exists(nt + s)) System.IO.File.Copy(nt + s, dst + s, true);
                            k = Native.LoadHive(dst);
                        }
                        catch (Exception e) { Err.Add("Hive of " + p.User + ": " + e.Message); continue; }
                    }
                    hives.Add(new Hive { P = p, Root = k });
                }
                return hives;
            }
        }

        /// <summary>Removes \\?\ and \??\ prefixes and expands 8.3 short names.</summary>
        public string Long(string p)
        {
            p = Util.StripDevicePrefix(p);
            if (p.IndexOf('~') < 0) return p;
            foreach (var s in shortNames)
                if (p.StartsWith(s.Key + "\\", StringComparison.OrdinalIgnoreCase)) return s.Value + p.Substring(s.Key.Length);
            return Native.LongPath(p) ?? p;
        }

        /// <summary>
        /// The path with the upper/lower case as it is on disk (Prefetch stores upper case, Amcache lower case).
        /// Parts that don't exist any more keep the case they were given in.
        /// </summary>
        public string RealCase(string p)
        {
            var m = Rules.DrivePath.Match(p ?? "");
            if (!m.Success) return p;
            // the cache also holds the parts looked up on the way, null for a part that is gone: a gone folder asked for
            // later (a "folder: " line, a "more:" line) must not get that null (it printed as "\")
            if (caseCache.TryGetValue(p, out var r) && r != null) return r;
            var parts = m.Groups[2].Value.Split(new[] { '\\' }, StringSplitOptions.RemoveEmptyEntries);
            var cur = m.Groups[1].Value.ToUpperInvariant();
            int i = 0;
            for (; i < parts.Length; i++)
            {
                var key = cur + "\\" + parts[i];
                if (!caseCache.TryGetValue(key, out var hit))
                {
                    hit = null;
                    if (parts[i].IndexOfAny(new[] { '*', '?' }) < 0)
                        try
                        {
                            var found = new DirectoryInfo(cur + "\\").GetFileSystemInfos(parts[i]);
                            var f = found.FirstOrDefault(x => x.Name.Equals(parts[i], StringComparison.OrdinalIgnoreCase)) ?? (found.Length == 1 ? found[0] : null);
                            if (f != null) hit = cur + "\\" + f.Name;
                        }
                        catch { }
                    caseCache[key] = hit;
                }
                if (hit == null) break;
                cur = hit;
            }
            for (; i < parts.Length; i++) cur += "\\" + parts[i];
            return caseCache[p] = cur;
        }

        /// <summary>
        /// A file for the log: (path in real case with bidi characters as &lt;RLO&gt;, status). Status "-" = there and fine;
        /// else e.g. "gone", "no access", "unsigned", "revoked signature", "volume not mounted". Hash, signature and version go to
        /// the FILES section at the end.
        /// </summary>
        /// <summary>
        /// The one rule for "trusted": in Windows or Program Files (not Windows\Temp, Tasks, Debug, a Startup folder), no flags,
        /// not a LOLBin, and - for executables - a valid signature (embedded or Windows catalog). A location alone is not enough:
        /// malware with admin rights drops into System32 and Program Files too.
        /// </summary>
        public bool TrustedFile(string p)
        {
            if (Alias(RealCase(p ?? "")) is string target) p = target;
            if (!Rules.InTrustedLocation(p)) return false;
            if (Rules.Flags(p).Count > 0 || Rules.Lol.IsMatch(p) || Rules.Interpreter.IsMatch(p)) return false;   // they run what their arguments say
            return SignedOk(p);
        }

        /// <summary>
        /// Not an executable type, or an executable with a valid signature. A missing file is OK only when an update replaced it:
        /// the same file exists, validly signed, in a newer version folder next to the old one (see Replacement).
        /// </summary>
        public bool SignedOk(string p)
        {
            var real = RealCase(p ?? "");
            if (Alias(real) is string target) real = target;
            if (!Signature.Applies(real)) return true;
            if (!System.IO.File.Exists(real)) { var nw = Replacement(real); return nw != null && Signature.Check(nw).Valid; }
            return Signature.Check(real).Valid;
        }

        HashSet<string> installFolders;

        /// <summary>
        /// The file is in the folder of an installed program (Uninstall keys, machine and per user: InstallLocation, the folders of
        /// DisplayIcon and of the uninstaller), below it at any depth. For the aggressive whitelist (Aggr): a per-user app's folder,
        /// not one a sideload kit made up. A drive root or a profile folder itself does not count.
        /// </summary>
        public bool InInstalledFolder(string p)
        {
            if (installFolders == null)
            {
                installFolders = new HashSet<string>(Util.IC);
                void Add(string f)
                {
                    f = (f ?? "").Trim().Trim('"').TrimEnd('\\');
                    if (!Rules.DrivePath.IsMatch(f) || Rules.DropLocation(f + "\\x") || Names.RandomFolder(f + "\\x")) return;
                    installFolders.Add(f + "\\");
                }
                var keys = new List<(RegistryKey Root, string Path)>
                {
                    (Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
                    (Registry.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
                };
                foreach (var h in Hives) keys.Add((h.Root, @"Software\Microsoft\Windows\CurrentVersion\Uninstall"));
                foreach (var (root, path) in keys)
                    try
                    {
                        using (var u = root.OpenSubKey(path))
                            if (u != null)
                                foreach (var n in u.GetSubKeyNames())
                                    using (var k = u.OpenSubKey(n))
                                    {
                                        if (k == null) continue;
                                        Add(Convert.ToString(k.GetValue("InstallLocation")));
                                        foreach (var v in new[] { "DisplayIcon", "UninstallString" })
                                        {
                                            var prog = Cmd.Program(Regex.Replace(Convert.ToString(k.GetValue(v)) ?? "", @",-?\d+$", ""), WinDir);
                                            if (Rules.DrivePath.IsMatch(prog ?? "")) Add(Util.Folder(prog));
                                        }
                                    }
                    }
                    catch { }
            }
            return installFolders.Any(f => (p ?? "").StartsWith(f, StringComparison.OrdinalIgnoreCase));
        }

        /// <summary>A file on disk validly signed by a well-known publisher (resources/publishers.txt): Riot's vgk.sys, NordVPN's driver.</summary>
        public bool ByTrustedSigner(string p)
        {
            var real = RealCase(p ?? "");
            if (!System.IO.File.Exists(real) || !Signature.Applies(real)) return false;
            var sg = Signature.Check(real);
            return sg.Valid && Rules.TrustedSigners.Contains((sg.Signer ?? "").Replace(" (catalog)", ""));
        }

        readonly Dictionary<string, string> aliases = new Dictionary<string, string>(Util.IC);
        /// <summary>The program an app execution alias in ...\Microsoft\WindowsApps\ starts, or null.</summary>
        public string Alias(string p)
        {
            if (p == null || p.IndexOf(@"\Microsoft\WindowsApps\", StringComparison.OrdinalIgnoreCase) < 0) return null;
            if (!aliases.TryGetValue(p, out var t)) aliases[p] = t = Native.AppAlias(p);
            return t;
        }

        /// <summary>(alias, program) of the app execution aliases met so far, as FILES writes them (real case, Rules.Fix).</summary>
        public IEnumerable<(string Alias, string Target)> AliasTargets() =>
            aliases.Where(kv => kv.Value != null).Select(kv => (Rules.Fix(RealCase(kv.Key)), Rules.Fix(RealCase(kv.Value)))).ToList();

        static readonly Regex VersionPart =new Regex(@"\d+([._]\d+)+", Util.RX);
        static readonly Regex HashFolder = new Regex(@"^(?=[^\\]*\d)[0-9a-f]{8,40}$", Util.RX);   // VS Code: Microsoft VS Code\2C33B50B16 (commit prefix)

        /// <summary>Folder name with its version replaced by # (app-1.0.9267 -> app-#, 2C33B50B16 -> #), or null if it has none.</summary>
        static string Shape(string seg) => HashFolder.IsMatch(seg) ? "#" : VersionPart.IsMatch(seg) ? VersionPart.Replace(seg, "#") : null;
        readonly Dictionary<string, string> repl = new Dictionary<string, string>(Util.IC);

        /// <summary>
        /// For a deleted file in a version folder (Discord\app-1.0.9267\Discord.exe, ...\claude-code-2.1.310-win32-x64\...\claude.exe,
        /// WindowsApps\Claude_5.1.0.0_x64__id\app\claude.exe, Edge\Application\157.0.1.2\x.exe): the same file in the newest sibling folder
        /// whose name differs only in the version numbers, or null.
        /// </summary>
        public string Replacement(string p)
        {
            if (string.IsNullOrEmpty(p)) return null;
            if (repl.TryGetValue(p, out var r)) return r;
            r = null;
            try
            {
                var parts = p.Split('\\');
                for (int i = parts.Length - 2; i >= 1 && r == null; i--)
                {
                    var shape = Shape(parts[i]);
                    if (shape == null) continue;
                    var parent = string.Join("\\", parts.Take(i));
                    if (!Directory.Exists(parent)) continue;
                    var rest = string.Join("\\", parts.Skip(i + 1));
                    r = Directory.GetDirectories(parent)
                        .Where(d => !Path.GetFileName(d).Equals(parts[i], StringComparison.OrdinalIgnoreCase) && shape.Equals(Shape(Path.GetFileName(d)), StringComparison.OrdinalIgnoreCase))
                        .Select(d => Path.Combine(d, rest)).Where(System.IO.File.Exists)
                        .OrderByDescending(x => System.IO.File.GetLastWriteTimeUtc(x)).FirstOrDefault();
                }
            }
            catch { }
            return repl[p] = r;
        }

        public (string Path, string Status) F(string p, bool hash = true)
        {
            if (string.IsNullOrEmpty(p)) return ("-", "-");
            if (p.StartsWith(@"\VOLUME{", StringComparison.OrdinalIgnoreCase)) return (Rules.Fix(p), "volume not mounted");
            // a path without its drive (PCA) that no drive has now (ExecEvidence.PcaPath checked them all): gone, not "present and signed"
            if (p.StartsWith(@"?:\", StringComparison.Ordinal)) return (Rules.Fix(p), "gone");
            if (!Rules.DrivePath.IsMatch(p)) return (Rules.Fix(p), "-");
            var real = RealCase(p);
            var disp = Rules.Fix(real);
            if (Alias(real) is string target)   // app execution alias: the status of the real program (it gets its own FILES line)
                return (disp, F(target, hash).Status);
            if (!status.TryGetValue(real + "|" + hash, out var st))
            {
                var sts = new List<string>();
                if (!System.IO.File.Exists(real)) sts.Add("gone");
                else
                {
                    try { var fm = new FileInfo(real); Meta[disp] = (fm.Length, fm.CreationTimeUtc, fm.LastWriteTimeUtc); } catch { }
                    // hash only when asked; the signature always (the whitelist decides by it, so the log must show it).
                    // The hash itself waits for FILES (HashFile): only the files it lists are read in full.
                    if (hash && !Opt.NoHash)
                        try
                        {
                            var fi = new FileInfo(real);
                            if (fi.Length > (long)Opt.MaxMB * 1024 * 1024) sts.Add("> " + Opt.MaxMB + " MB, not hashed");
                            else
                            {
                                using (new FileStream(real, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete)) { }   // readable?
                                ToHash[disp] = real;
                            }
                        }
                        catch { sts.Add("no access"); }
                    if (Signature.Applies(real) && !sts.Contains("no access"))
                    {
                        var sg = Signature.Check(real);
                        Signer[disp] = Signature.Describe(sg);
                        if (sg.Status == "no access") sts.Add("no access");   // unreadable: not "unsigned"
                        else if (!sg.Valid) sts.Add(sg.Status == "unsigned" ? "unsigned" : sg.Status + " signature");
                        // "path => invalid signature: file changed after signing (bad digest); signer X <==== !invalid-signature"
                        if (sg.Status == "revoked" || (sg.Status == "invalid" && sg.Reason != null && sg.Reason.StartsWith("file changed")))
                            FindAs("Signature", null, disp, $"{sg.Status} signature: {sg.Reason}" + (sg.Signer != null ? "; signer " + sg.Signer : ""),
                                   new List<string> { Rules.InvalidSignatureFlag });
                    }
                    var ver = Signature.Version(real);
                    if (ver != null) Version[disp] = ver;
                }
                st = sts.Count > 0 ? string.Join(", ", sts) : "-";
                status[real + "|" + hash] = st;
            }
            return (disp, st);
        }

        /// <summary>A file as a continuation value: "path [status] &lt;==== flags".</summary>
        public string FF(string p, bool hash = true, IEnumerable<string> flags = null)
        {
            var f = F(p, hash); var fl = Rules.FlagCol(flags ?? Rules.Flags(p));
            return Log.Item(f.Path, f.Status, null, fl);
        }

        /// <summary>The file as free text: path plus "  [status]" if there is one.</summary>
        public string File(string p, bool hash = true)
        {
            var f = F(p, hash);
            return Log.Item(f.Path, f.Status);
        }

        /// <summary>Signature status for a file that exists: "signed: X", "unsigned", "invalid signature", or "" if not applicable.</summary>
        public string Sig(string p)
        {
            if (string.IsNullOrEmpty(p) || !Signature.Applies(p) || !System.IO.File.Exists(p)) return "";
            return Signature.Describe(Signature.Check(p));
        }

        /// <summary>Copies a file that may be locked: plain copy, else shared read, else esentutl /y /vss (shadow copy; some AVs alert on it).</summary>
        public string CopyLocked(string src, string dst)
        {
            try { System.IO.File.Copy(src, dst, true); return "plain copy"; } catch { }
            try
            {
                using (var i = new FileStream(src, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                using (var o = new FileStream(dst, FileMode.Create, FileAccess.Write)) i.CopyTo(o);
                return "shared read";
            }
            catch { }
            var sp = ShadowPath(src);
            if (sp != null) try { System.IO.File.Copy(sp, dst, true); return "shadow copy"; } catch (Exception e) { Err.Add("shadow copy of " + src + ": " + e.Message); }
            Esentutl($"/y /vss \"{src}\" /d \"{dst}\"");
            if (!System.IO.File.Exists(dst)) throw new IOException("cannot copy " + src + " (locked, and esentutl /vss failed)");
            return "esentutl /vss";
        }

        /// <summary>The bytes of a file that may be locked.</summary>
        public byte[] ReadLocked(string path)
        {
            try
            {
                using (var i = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                using (var m = new MemoryStream()) { i.CopyTo(m); return m.ToArray(); }
            }
            catch
            {
                var d = System.IO.Path.Combine(Temp, Guid.NewGuid().ToString("N").Substring(0, 8) + "_" + System.IO.Path.GetFileName(path));
                CopyLocked(path, d);
                try { return System.IO.File.ReadAllBytes(d); } finally { try { System.IO.File.Delete(d); } catch { } }
            }
        }

        string shadowDev, shadowId; bool shadowTried;
        public string ShadowNote;

        /// <summary>
        /// The path of a file in a shadow copy of the system drive, created once when the first locked file is needed
        /// (SRUM, WebCache, Amcache are locked by Windows) and deleted at the end. Null if not possible.
        /// </summary>
        string ShadowPath(string path)
        {
            if (!path.StartsWith(SystemDrive + "\\", StringComparison.OrdinalIgnoreCase)) return null;
            if (!shadowTried)
            {
                shadowTried = true;
                try
                {
                    using (var cls = new System.Management.ManagementClass(@"\\.\root\cimv2", "Win32_ShadowCopy", null))
                    using (var inp = cls.GetMethodParameters("Create"))
                    {
                        inp["Volume"] = SystemDrive + "\\"; inp["Context"] = "ClientAccessible";
                        using (var outp = cls.InvokeMethod("Create", inp, null))
                        {
                            var rc = Convert.ToUInt32(outp["ReturnValue"]);
                            if (rc != 0) throw new Exception("Win32_ShadowCopy.Create returned " + rc);
                            shadowId = Convert.ToString(outp["ShadowID"]);
                        }
                    }
                    using (var q = new System.Management.ManagementObjectSearcher(@"\\.\root\cimv2", $"SELECT DeviceObject FROM Win32_ShadowCopy WHERE ID='{shadowId}'"))
                        foreach (System.Management.ManagementObject o in q.Get()) shadowDev = Convert.ToString(o["DeviceObject"]);
                    ShadowNote = "A shadow copy of " + SystemDrive + " was created to read locked files (SRUM, WebCache, Amcache) and deleted afterwards.";
                }
                catch (Exception e) { Err.Add("shadow copy: " + e.Message); }
            }
            return shadowDev == null ? null : shadowDev + path.Substring(SystemDrive.Length);
        }

        void DeleteShadow()
        {
            if (shadowId == null) return;
            try
            {
                using (var q = new System.Management.ManagementObjectSearcher(@"\\.\root\cimv2", $"SELECT * FROM Win32_ShadowCopy WHERE ID='{shadowId}'"))
                    foreach (System.Management.ManagementObject o in q.Get()) o.Delete();
            }
            catch { }
            shadowId = null;
        }

        public void Esentutl(string args)
        {
            var psi = new System.Diagnostics.ProcessStartInfo(System.IO.Path.Combine(WinDir, @"System32\esentutl.exe"), args)
            { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true, RedirectStandardInput = true };
            try
            {
                using (var p = System.Diagnostics.Process.Start(psi))
                {
                    p.StandardInput.Close(); p.StandardOutput.ReadToEnd(); p.StandardError.ReadToEnd();
                    if (!p.WaitForExit(120000)) try { p.Kill(); } catch { }
                }
            }
            catch (Exception e) { Err.Add("esentutl: " + e.Message); }
        }

        Dictionary<string, string> devices;
        /// <summary>"\Device\HarddiskVolume3\x" -> "C:\x" (BAM, SRUM, Defender logs).</summary>
        public string DevicePath(string p)
        {
            if (devices == null)
            {
                devices = new Dictionary<string, string>(Util.IC);
                foreach (var d in DriveInfo.GetDrives()) { try { var n = d.Name.TrimEnd('\\'); var t = Native.DosDevice(n); if (t != null) devices[t] = n; } catch { } }
            }
            var m = Regex.Match(p ?? "", @"^(\\Device\\[^\\]+)(\\.*)$", Util.RX);
            return m.Success && devices.TryGetValue(m.Groups[1].Value, out var dl) ? dl + m.Groups[2].Value : p;
        }

        public void Dispose()
        {
            DeleteShadow();
            if (hives != null)
                foreach (var h in hives) try { h.Root.Dispose(); } catch { }
            if (tmp == null) return;
            GC.Collect(); GC.WaitForPendingFinalizers();
            for (int i = 0; i < 10 && Directory.Exists(tmp); i++)
            {
                try { Directory.Delete(tmp, true); } catch { System.Threading.Thread.Sleep(300); }
            }
        }
    }
}
