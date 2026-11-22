using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

namespace Spor.Modules
{
    /// <summary>
    /// DROP FOLDERS: a sweep that needs no evidence. PavinLoader (installed by RenLoader's fake MSI apps) drops "project folders" into
    /// Windows cache and system folders (WebCache, INetCache, Protect, Crypto, ...): a copied MSBuild.exe with a broken signature, a
    /// .wsf a scheduled task starts with wscript, a 20-30 MB Resources.resx (the payload) and dummy developer files (.sln, .csproj,
    /// .targets, .props, README.md, ...). A copy that never ran is named by no evidence source, so the sweep lists these folders on
    /// every scan: down to 2 levels below each cache folder of every profile (the SYSTEM account's too) and ProgramData's Caches, and
    /// the LocalAppData vendor\product folders where RenLoader's MSI apps put their copy. Folders created within 10 seconds of each
    /// other are one group; folders with the same file names, and folders in AppData created within 10 seconds of a match, join it.
    /// Nothing is hidden by the whitelist.
    /// </summary>
    class Drops : IModule
    {
        public string Id => "drops";
        public string Name => "DROP FOLDERS";
        public string Description => "loader project folders in Windows cache and system folders, found without other evidence";

        public const string Family = "PavinLoader";
        const long BigResx = 5L * 1024 * 1024;
        const int Depth = 2;                 // folder levels below a root
        const int MaxItems = 50000;          // files and folders read by the sweep
        const int NearDepth = 4;             // folder levels below AppData\Local, Roaming, LocalLow for the 10-second search
        const int NearMax = 30000;           // folders read by it
        static readonly TimeSpan NearBudget = TimeSpan.FromSeconds(10);
        const double NearSeconds = 10;
        const int NearListed = 10;           // folders of a group found by their time, listed
        const int EntriesListed = 20;        // files of a folder on entry: lines

        /// <summary>The cache folders in a profile, from the PavinLoader cases and rifteyy's FenrisHub snippet "PavinLoader cache drops investigator".</summary>
        internal static readonly string[] CacheRoots =
        {
            @"AppData\Local\Microsoft\Windows\WebCache", @"AppData\Local\Microsoft\Windows\Explorer", @"AppData\Local\Microsoft\Windows\Caches",
            @"AppData\Local\Microsoft\Windows\INetCache", @"AppData\Local\Microsoft\Windows\Notifications",
            @"AppData\Roaming\Microsoft\Protect", @"AppData\Roaming\Microsoft\Crypto", @"AppData\Roaming\Microsoft\Windows\Themes",
            @"AppData\Roaming\Microsoft\Windows\Libraries",
        };

        /// <summary>First-level LocalAppData folders the vendor sweep does not enter: Temp (NEW FILES lists it) and the Store apps' Packages.</summary>
        static readonly Regex SkipVendor = new Regex(@"^(Temp|Packages)$", Util.RX);

        /// <summary>Developer project files (the dummy files of a PavinLoader folder).</summary>
        static readonly Regex ProjectFile = new Regex(@"\.(sln|csproj|csproj\.user|vbproj|targets|props)$", Util.RX);
        static readonly string[] ProjectOrder = { ".sln", ".csproj", ".vbproj", ".csproj.user", ".targets", ".props" };
        static readonly Regex Wsf = new Regex(@"\.(wsf|vbs)$", Util.RX);
        static readonly Regex Batch = new Regex(@"\.(cmd|bat)$", Util.RX);
        /// <summary>Files that get an entry: line (hash, signature and version in FILES); the rest are names on others: lines.</summary>
        static readonly Regex KeyFile = new Regex(@"\.(exe|dll|scr|com|cpl|ocx|sys|wsf|vbs|vbe|js|jse|hta|cmd|bat|ps1|psm1|resx|cs|msi|lnk)$", Util.RX);

        internal sealed class Entry
        {
            public string Name;
            public long Size;
            public FileAttributes Attr;
            public DateTime Created;
        }

        internal sealed class Folder
        {
            public string Path;              // without the trailing backslash
            public DateTime Created;
            public FileAttributes Attr;
            public bool CacheRoot;           // below a Windows cache folder (else a LocalAppData vendor folder, or found by its time)
            public bool ByTime;              // found by the 10-second search
            public string Profile;           // the profile folder it is in, or null (ProgramData)
            public List<Entry> Files = new List<Entry>();
            public string Reason;            // Layout: why it is a loader project folder, or null
            public string Link;              // a group member that is no match itself: why it belongs to the group
            public Folder Head;              // the group's first folder (itself for the first)
        }

        /// <summary>What a sweep read; Clock: the time budget of the 10-second search, one for the whole scan (all profiles).</summary>
        internal sealed class Counter { public int Items, Dirs, Denied; public bool Capped, OutOfTime; public readonly Stopwatch Clock = Stopwatch.StartNew(); }

        Ctx c;

        public void Execute(Ctx ctx)
        {
            c = ctx;
            var sw = Stopwatch.StartNew();
            var profiles = c.Profiles.Select(p => p.Path).Concat(SystemProfiles(c.WinDir)).Distinct(Util.IC).ToList();
            var roots = Roots(profiles, Ctx.Env("ProgramData"));
            var n = new Counter();
            var folders = Sweep(roots, OriginalName, n);
            var matchTimes = folders.Where(f => f.Reason != null && f.Profile != null)
                                    .GroupBy(f => f.Profile, Util.IC).ToDictionary(g => g.Key, g => g.Select(f => f.Created).ToList(), Util.IC);
            var near = new List<Folder>();
            var nn = new Counter();
            foreach (var kv in matchTimes) near.AddRange(Near(kv.Key, kv.Value, nn, NearBudget));
            // a folder found by its time with the whole layout is a match of its own (strict: it is no cache folder)
            foreach (var f in near) f.Reason = Layout(f.Files.Select(x => (x.Name, x.Size)).ToList(), false,
                                                      name => OriginalName(Path.Combine(f.Path, name)));
            var groups = Link(folders, near);

            c.Out.Comment($"Swept {CacheRoots.Length} Windows cache folders in {Util.Plural(profiles.Count, "profile", "profiles")} (the SYSTEM account's too) " +
                          $"and ProgramData, and the LocalAppData vendor folders: {Util.Plural(n.Dirs, "folder", "folders")}, {n.Items} items, {Depth} levels deep; " +
                          $"{groups.Sum(g => g.Count(f => f.Reason != null))} matches.");
            if (n.Capped) c.Out.Comment($"Stopped at {MaxItems} items; the rest is not swept.");
            if (n.Denied > 0) c.Out.Comment($"{n.Denied} of {n.Dirs} folders could not be read (access denied).");
            if (nn.Capped || nn.OutOfTime) c.Out.Comment($"The search for folders created within {NearSeconds} s of a match stopped after {nn.Dirs} folders.");

            c.Out.Sub("Loader project folders",
                "A copied MSBuild.exe with a .wsf, or project files (.sln, .csproj, .targets, .props) with a large .resx, or any of them in a Windows cache folder.\n" +
                "Folders created within 10 s of each other are one group (group: = its first folder), and so are folders with the same file names.\n" +
                "Times UTC; files on entry: lines, hashes, signatures and versions in FILES.");
            var t = new Table("@created", "*folder", "=attributes", "=details", "<flags");
            foreach (var g in groups)
            {
                int byTime = 0;
                foreach (var f in g)
                {
                    var disp = Usb.Shown(f.Path) + "\\";
                    var flags = Flags(f);
                    if (f.ByTime && f.Reason == null && ++byTime > NearListed) { Report(f, disp, Details(f, true), flags); continue; }   // SUMMARY still
                    t.Add(Log.T(f.Created), disp, Usb.AttrText(f.Attr), Details(f, false), Rules.FlagCol(flags));
                    var key = f.Files.Where(x => KeyFile.IsMatch(x.Name)).OrderBy(x => x.Name, Util.IC).ToList();
                    foreach (var x in key.Take(EntriesListed)) t.More("entry", EntryText(f, x));
                    var others = f.Files.Where(x => !KeyFile.IsMatch(x.Name)).Select(x => Rules.Fix(x.Name))
                                  .Concat(key.Skip(EntriesListed).Select(x => Rules.Fix(x.Name))).OrderBy(x => x, Util.IC).ToList();
                    foreach (var chunk in Log.Chunks(others)) t.More("others", chunk);
                    if (f.Head != f) t.More("group", Usb.Shown(f.Head.Path) + "\\");
                    Report(f, disp, Details(f, true), flags);
                }
                if (byTime > NearListed) t.More("others", $"+{byTime - NearListed} more folders created within {NearSeconds} s (not listed)");
            }
            t.WriteTo(c.Out, "no loader project folders");
            c.Out.Comment($"Took {sw.Elapsed.TotalSeconds:N1} s.");
        }

        /// <summary>The SYSTEM account's profile (and its 32-bit view).</summary>
        internal static IEnumerable<string> SystemProfiles(string winDir) =>
            new[] { @"System32\config\systemprofile", @"SysWOW64\config\systemprofile" }.Select(x => Path.Combine(winDir ?? @"C:\Windows", x));

        /// <summary>
        /// (pure) The roots to sweep: the cache folders of each profile and ProgramData's Caches first (small, and where PavinLoader
        /// drops), then each profile's LocalAppData (the vendor folders, big): when the item cap is reached, it cuts the vendor folders.
        /// </summary>
        internal static List<(string Root, bool Cache, string Profile)> Roots(IEnumerable<string> profiles, string programData)
        {
            var res = new List<(string, bool, string)>();
            var ps = profiles.Where(p => !string.IsNullOrEmpty(p)).ToList();
            foreach (var p in ps)
                foreach (var r in CacheRoots) res.Add((Path.Combine(p, r), true, p));
            if (!string.IsNullOrEmpty(programData)) res.Add((Path.Combine(programData, @"Microsoft\Windows\Caches"), true, null));
            foreach (var p in ps) res.Add((Path.Combine(p, @"AppData\Local"), false, p));
            return res;
        }

        /// <summary>The original name of a program in its version resource (null for other files or none).</summary>
        static string OriginalName(string path) => path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? Signature.Names(path).Original : null;

        /// <summary>
        /// The folders 1 to Depth levels below each root with their files, each with its Layout decision. Hidden and system items are
        /// read too, reparse points are not entered, names are read with the \\?\ prefix (a name ending in a space or dot stays).
        /// LocalAppData (not a cache root): its Temp and Packages folders are not entered.
        /// </summary>
        internal static List<Folder> Sweep(IEnumerable<(string Root, bool Cache, string Profile)> roots, Func<string, string> origName, Counter n)
        {
            var res = new List<Folder>();
            var seen = new HashSet<string>(Util.IC);
            foreach (var (root, cache, profile) in roots)
            {
                if (n.Capped || !Directory.Exists(root)) continue;
                var st = new Stack<(string Dir, int Depth, FileSystemInfo Info)>();
                st.Push((root, 0, null));
                while (st.Count > 0 && !n.Capped)
                {
                    var (dir, depth, info) = st.Pop();
                    var items = List(dir, n);
                    if (items == null) continue;
                    var subs = new List<FileSystemInfo>();
                    var f = depth > 0 ? new Folder { Path = dir, CacheRoot = cache, Profile = profile } : null;
                    if (f != null) try { f.Created = info.CreationTimeUtc; f.Attr = info.Attributes; } catch { }
                    foreach (var x in items)
                    {
                        if (++n.Items > MaxItems) { n.Capped = true; break; }
                        FileAttributes a = 0;
                        try { a = x.Attributes; } catch { }
                        if ((a & FileAttributes.Directory) != 0)
                        {
                            if ((a & FileAttributes.ReparsePoint) != 0 || depth >= Depth) continue;
                            if (depth == 0 && !cache && SkipVendor.IsMatch(x.Name)) continue;
                            subs.Add(x);
                        }
                        else if (f != null)
                        {
                            var e = new Entry { Name = x.Name, Attr = a };
                            try { e.Size = ((FileInfo)x).Length; e.Created = x.CreationTimeUtc; } catch { }
                            f.Files.Add(e);
                        }
                    }
                    // LocalAppData is swept as a vendor root and its Microsoft\Windows cache folders as cache roots: each folder once,
                    // as a cache folder when both (the cache roots come first)
                    if (f != null && seen.Add(f.Path))
                    {
                        f.Reason = Layout(f.Files.Select(x => (x.Name, x.Size)).ToList(), cache, name => origName?.Invoke(Path.Combine(dir, name)));
                        res.Add(f);
                    }
                    foreach (var s in subs.OrderByDescending(s => s.Name, StringComparer.OrdinalIgnoreCase)) st.Push((Path.Combine(dir, s.Name), depth + 1, s));
                }
            }
            return res;
        }

        /// <summary>The entries of a folder, or null when it cannot be read.</summary>
        static FileSystemInfo[] List(string dir, Counter n)
        {
            n.Dirs++;
            try { return new DirectoryInfo(@"\\?\" + dir.TrimEnd('\\') + "\\").GetFileSystemInfos(); }
            catch { n.Denied++; return null; }
        }

        /// <summary>
        /// (pure) Why a folder is a loader project folder, or null. Project files: .sln, .csproj, .csproj.user, .vbproj, .targets, .props.
        /// Below a Windows cache folder (cacheRoot) any project file, an MSBuild.exe (by name or original name), a .wsf / .vbs or a
        /// build.cmd is enough: no developer project lives in WebCache, Protect or INetCache. In a LocalAppData vendor folder the layout
        /// must be complete: MSBuild.exe with a .wsf, or project files with a .resx over 5 MB, an MSBuild.exe, a .wsf or a .cmd / .bat.
        /// origName: a file name -> its original name (null when none).
        /// </summary>
        internal static string Layout(IReadOnlyList<(string Name, long Size)> files, bool cacheRoot, Func<string, string> origName)
        {
            bool Is(string a, string b) => string.Equals(a, b, StringComparison.OrdinalIgnoreCase);
            var wsf = files.Where(f => Wsf.IsMatch(f.Name)).Select(f => f.Name).ToList();
            var batch = files.Where(f => Batch.IsMatch(f.Name)).Select(f => f.Name).ToList();
            // solution and project first, then the rest (in the reason's short list)
            var proj = files.Where(f => ProjectFile.IsMatch(f.Name)).Select(f => f.Name)
                            .OrderBy(n => Array.FindIndex(ProjectOrder, e => n.EndsWith(e, StringComparison.OrdinalIgnoreCase)) is int i && i >= 0 ? i : 99)
                            .ThenBy(n => n, Util.IC).ToList();
            // a renamed MSBuild only counts next to a script or a project (or in a cache folder): its version resource is read only then
            bool lookOrig = origName != null && (cacheRoot || wsf.Count > 0 || proj.Count > 0);
            var msbuild = files.Where(f => Is(f.Name, "MSBuild.exe") || (lookOrig && f.Name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) && Is(origName(f.Name), "MSBuild.exe")))
                               .Select(f => Is(f.Name, "MSBuild.exe") ? f.Name : f.Name + " (MSBuild.exe)").ToList();
            var resx = files.Where(f => f.Name.EndsWith(".resx", StringComparison.OrdinalIgnoreCase) && f.Size > BigResx).ToList();
            bool match = cacheRoot
                ? proj.Count > 0 || msbuild.Count > 0 || wsf.Count > 0 || batch.Any(b => Is(b, "build.cmd"))
                : (msbuild.Count > 0 && wsf.Any(w => w.EndsWith(".wsf", StringComparison.OrdinalIgnoreCase)))
                  || (proj.Count > 0 && (resx.Count > 0 || msbuild.Count > 0 || wsf.Count > 0 || batch.Count > 0));
            if (!match) return null;
            var named = msbuild.Concat(wsf).Concat(cacheRoot ? batch.Where(b => Is(b, "build.cmd")) : batch).Concat(proj)
                               .Distinct(Util.IC).ToList();
            var text = string.Join(", ", named.Take(4).Select(Rules.Fix)) + (named.Count > 4 ? $", +{named.Count - 4} more" : "");
            if (resx.Count > 0) text += "; " + string.Join(", ", resx.Select(r => Rules.Fix(r.Name) + " " + r.Size + " bytes"));
            return "project folder (" + text + ")";
        }

        /// <summary>A developer or script file name: what makes shared names count (README.md and LICENSE alone do not).</summary>
        static bool DevOrScript(string name) => ProjectFile.IsMatch(name) || Wsf.IsMatch(name) || Batch.IsMatch(name)
            || name.EndsWith(".resx", StringComparison.OrdinalIgnoreCase) || name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase);

        /// <summary>
        /// Folders below AppData\Local, Roaming and LocalLow of a profile (NearDepth levels, Packages not entered) created within 10 s of
        /// one of the times, with their files. Stops after NearMax folders or when n.Clock passes the budget (one budget for all profiles).
        /// </summary>
        internal static List<Folder> Near(string profile, IList<DateTime> times, Counter n, TimeSpan budget)
        {
            var res = new List<Folder>();
            if (times.Count == 0) return res;
            foreach (var root in new[] { @"AppData\Local", @"AppData\Roaming", @"AppData\LocalLow" }.Select(r => Path.Combine(profile, r)))
            {
                if (!Directory.Exists(root)) continue;
                var st = new Stack<(string Dir, int Depth)>();
                st.Push((root, 0));
                while (st.Count > 0)
                {
                    if (n.Dirs >= NearMax) { n.Capped = true; return res; }
                    if (n.Clock.Elapsed > budget) { n.OutOfTime = true; return res; }
                    var (dir, depth) = st.Pop();
                    n.Dirs++;
                    DirectoryInfo[] subs;
                    try { subs = new DirectoryInfo(@"\\?\" + dir + "\\").GetDirectories(); }
                    catch { n.Denied++; continue; }
                    foreach (var s in subs)
                    {
                        FileAttributes a; DateTime cr;
                        try { a = s.Attributes; cr = s.CreationTimeUtc; } catch { continue; }
                        if ((a & FileAttributes.ReparsePoint) != 0) continue;
                        var path = Path.Combine(dir, s.Name);
                        if (times.Any(t => Math.Abs((cr - t).TotalSeconds) <= NearSeconds))
                        {
                            var f = new Folder { Path = path, Created = cr, Attr = a, Profile = profile, ByTime = true };
                            try
                            {
                                foreach (var x in new DirectoryInfo(@"\\?\" + path + "\\").GetFiles())
                                    f.Files.Add(new Entry { Name = x.Name, Size = x.Length, Attr = x.Attributes, Created = x.CreationTimeUtc });
                            }
                            catch { }
                            res.Add(f);
                        }
                        if (depth + 1 < NearDepth && !(depth == 0 && s.Name.Equals("Packages", StringComparison.OrdinalIgnoreCase))) st.Push((path, depth + 1));
                    }
                }
            }
            return res;
        }

        static bool Under(string path, string dir) => path.StartsWith(dir.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase);

        /// <summary>
        /// (pure) The groups of the matches (Reason set), oldest first: matches created within 10 s of a match of the group, then folders
        /// of the sweep with at least 4 of the group's file names (one a developer, script or program file), then the folders found by
        /// their time (near) that are not inside or above a member. Sets Head (the group's first match) and Link.
        /// </summary>
        internal static List<List<Folder>> Link(List<Folder> folders, List<Folder> near)
        {
            var groups = new List<List<Folder>>();
            foreach (var m in folders.Where(f => f.Reason != null).OrderBy(f => f.Created).ThenBy(f => f.Path, Util.IC))
            {
                var g = groups.FirstOrDefault(x => x.Any(y => Math.Abs((y.Created - m.Created).TotalSeconds) <= NearSeconds));
                if (g == null) { g = new List<Folder>(); groups.Add(g); }
                m.Head = g.Count > 0 ? g[0] : m;
                g.Add(m);
            }
            foreach (var g in groups)
            {
                var names = new HashSet<string>(g.SelectMany(x => x.Files.Select(f => f.Name)), Util.IC);
                foreach (var f in folders.Where(f => f.Head == null))
                {
                    var shared = f.Files.Select(x => x.Name).Where(names.Contains).Distinct(Util.IC).ToList();
                    if (shared.Count < 4 || !shared.Any(DevOrScript)) continue;
                    f.Head = g[0];
                    f.Link = $"same file names as {Usb.Shown(g[0].Path)}\\ ({string.Join(", ", shared.Take(5).Select(Rules.Fix))}{(shared.Count > 5 ? ", ..." : "")})";
                    g.Add(f);
                }
            }
            foreach (var f in near.OrderBy(f => f.Created).ThenBy(f => f.Path, Util.IC))
            {
                if (groups.Any(g => g.Any(m => m.Path.Equals(f.Path, StringComparison.OrdinalIgnoreCase) || Under(f.Path, m.Path) || Under(m.Path, f.Path)))) continue;
                var g = groups.FirstOrDefault(x => x.Any(m => m.Reason != null && m.Profile != null && m.Profile.Equals(f.Profile, StringComparison.OrdinalIgnoreCase)
                                                                && Math.Abs((m.Created - f.Created).TotalSeconds) <= NearSeconds));
                if (g == null) continue;
                var m0 = g.Where(m => m.Reason != null).OrderBy(m => Math.Abs((m.Created - f.Created).TotalSeconds)).First();
                var d = (f.Created - m0.Created).TotalSeconds;
                f.Head = g[0];
                f.Link = $"created {Math.Abs(d):0} s {(d < 0 ? "before" : "after")} {Usb.Shown(m0.Path)}\\";
                g.Add(f);
            }
            foreach (var g in groups)
            {
                var head = g[0];
                var rest = g.Skip(1).OrderBy(f => f.Created).ThenBy(f => f.Path, Util.IC).ToList();
                g.Clear(); g.Add(head); g.AddRange(rest);
            }
            return groups;
        }

        /// <summary>A match, or a member with the same file names and a PavinLoader launcher (MSBuild.exe, .wsf, .vbs): !known-malware.
        /// A folder that only shares the creation time needs the whole layout (Reason) for it.</summary>
        static bool Launcher(Folder f) => f.Files.Any(x => x.Name.Equals("MSBuild.exe", StringComparison.OrdinalIgnoreCase) || Wsf.IsMatch(x.Name));

        List<string> Flags(Folder f)
        {
            var fl = new List<string>();
            if (f.Reason != null || (!f.ByTime && Launcher(f))) fl.Add(Autodetect.Flag);
            if (f.Files.Any(x => KeyFile.IsMatch(x.Name) && c.LolbinCopy(Path.Combine(f.Path, x.Name)) != null)) fl.Add(Rules.LolbinCopyFlag);
            return fl;
        }

        /// <summary>A folder's details; withAttributes: its attributes when hidden or system (SUMMARY; the section has a column for them).</summary>
        static string Details(Folder f, bool withAttributes)
        {
            var parts = new List<string>();
            if (f.Reason != null) parts.Add($"known malware {Family}: {f.Reason}");
            if (f.Link != null) parts.Add(f.Link);
            if (withAttributes && (f.Attr & (FileAttributes.Hidden | FileAttributes.System)) != 0) parts.Add(Usb.AttrText(f.Attr));
            parts.Add(Util.Plural(f.Files.Count, "file", "files"));
            return string.Join("; ", parts);
        }

        /// <summary>"path [status] => N bytes; created T; attributes hidden; copy of MSBuild.exe ... &lt;==== flags" (status, hash, signature: c.F).</summary>
        string EntryText(Folder f, Entry x)
        {
            var path = Path.Combine(f.Path, x.Name);
            var st = c.F(path);
            var parts = new List<string> { x.Size + " bytes", "created " + Log.T(x.Created) };
            if ((x.Attr & (FileAttributes.Hidden | FileAttributes.System)) != 0) parts.Add(Usb.AttrText(x.Attr));
            if (c.LolbinCopy(path) is string copy) parts.Add(copy);
            return Log.Item(Usb.Shown(path), st.Status, string.Join("; ", parts), Rules.FlagCol(c.WithLolbinCopy(path, Rules.Flags(path))));
        }

        /// <summary>
        /// Into SUMMARY (and the timeline when created in the time window): matches, folders with the same file names, and folders found
        /// by their time that hold a developer, script or program file (others are only in the section: a folder of the same 20 seconds
        /// can be a browser's cache). group: names the group's first folder.
        /// </summary>
        void Report(Folder f, string disp, string details, List<string> flags)
        {
            if (f.ByTime && !f.Files.Any(x => DevOrScript(x.Name))) return;
            var more = f.Head != f ? new List<(string Key, string Value)> { ("group", Usb.Shown(f.Head.Path) + "\\") } : null;
            bool inWindow = f.Created >= c.Since;
            if (inWindow) c.Event(f.Created, "DRP", null, details, flags, text: disp, more: more);
            // a timeline line goes to SUMMARY only with a strong flag
            if (!inWindow || Rules.Strong(flags).Count == 0) c.Find(f.Created, disp, details, flags, more);
        }
    }
}
