using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

namespace Spor.Modules
{
    /// <summary>
    /// File drops: executables, scripts, archives and disk images created in the time window in user-writable places
    /// (Downloads, Desktop, Documents, AppData, Temp, ProgramData, Public, Windows\Temp), with the download URL from Zone.Identifier.
    /// Time = file creation (when it was downloaded, extracted or dropped).
    /// </summary>
    class Files : IModule
    {
        public string Id => "files";
        public string Name => "NEW FILES";
        public string Description => "executables, scripts and archives created recently, with download origin";

        internal static readonly Regex Exec = new Regex(@"\.(exe|dll|scr|com|pif|cpl|sys|ocx|drv|efi|msi|msp|msc|jar|jnlp|xll|xlam|docm|dotm|xlsm|pptm|ppam|appx|msix|appinstaller|application|appref-ms|rdp|library-ms|search-ms|settingcontent-ms|scf|iqy|slk)$", Util.RX);
        // scripts: up to 3 folder levels deep (loaders use e.g. AppData\Roaming\x\y\run.vbs), except where scripts are normal
        internal static readonly Regex Script = new Regex(@"\.(bat|cmd|ps1|psm1|psd1|vbs|vbe|js|jse|jsc|wsf|wsh|wsc|sct|hta|py|pyw|au3|a3x|ahk)$", Util.RX);
        static readonly Regex Shortcut = new Regex(@"\.(lnk|url)$", Util.RX);
        static Regex ScriptNoise => Whitelist.ScriptNoise;   // resources/whitelist.txt
        static readonly Regex Archive = new Regex(@"\.(zip|rar|7z|cab|iso|img|vhd|vhdx|tar|gz|tgz|ace|arj|z)$", Util.RX);
        static HashSet<string> SkipDirs => Whitelist.SkipDirs;   // resources/whitelist.txt
        static Regex Breadcrumb => Whitelist.Breadcrumb;   // resources/whitelist.txt

        /// <summary>A new file of one folder, with its Zone.Identifier.</summary>
        sealed class NewFile
        {
            public FileInfo F;
            public Zone Zone;
            public bool HasUrl => Zone != null && Zone.HasUrl;
            public bool Padded;   // hashing it would read hundreds of MB of padding
            public readonly List<string> Flags = new List<string>();     // besides the name flags (Rules.Flags), which the timeline adds itself
            public readonly List<string> Details = new List<string>();   // after the origin
        }

        /// <summary>
        /// Signed programs in a drop-location folder with new files, and the unsigned DLLs next to them they import (Sideload).
        /// The DLL gets !sideload and the evidence, the program "side-loads x.dll"; files that are not new get their own timeline lines.
        /// </summary>
        void SideLoading(string dir, List<NewFile> all)
        {
            List<string> exes;
            try { exes = Directory.EnumerateFiles(dir, "*.exe").Take(50).ToList(); } catch { return; }
            foreach (var exe in exes)
                foreach (var h in Sideload.For(c, exe))
                {
                    var dll = all.FirstOrDefault(f => f.F.FullName.Equals(h.Dll.Path, StringComparison.OrdinalIgnoreCase));
                    var host = all.FirstOrDefault(f => f.F.FullName.Equals(h.Host.Path, StringComparison.OrdinalIgnoreCase));
                    if (dll != null && Sideload.Claim(c, h, dllLine: true)) { if (!dll.Flags.Contains(Sideload.Flag)) dll.Flags.Add(Sideload.Flag); dll.Details.Add(h.DllDetails); }
                    if (host != null && Sideload.Claim(c, h, dllLine: false)) host.Details.Add(h.HostDetails);
                    Sideload.Events(c, h);   // the lines not written here (a file that is not new); never twice
                }
        }

        static string Details(NewFile f)
        {
            var d = new[] { f.Zone?.Text }.Concat(f.Details).Where(s => !string.IsNullOrEmpty(s)).ToList();
            return d.Count > 0 ? string.Join("; ", d) : null;
        }

        Ctx c;
        Regex noise;

        public void Execute(Ctx ctx)
        {
            c = ctx; noise = Rules.Noise(Whitelist.Noise("files"));
            var sw = Stopwatch.StartNew();
            var roots = new List<(string Dir, bool Archives)>();
            foreach (var p in c.Profiles)
            {
                foreach (var d in new[] { "Downloads", "Desktop", "Documents" }) roots.Add((Path.Combine(p.Path, d), true));
                roots.Add((Path.Combine(p.Path, @"AppData\Local\Temp"), true));
                roots.Add((Path.Combine(p.Path, @"AppData\Roaming"), false));
                roots.Add((Path.Combine(p.Path, @"AppData\Local"), false));
            }
            roots.Add((Path.Combine(c.WinDir, "Temp"), true));
            roots.Add((Ctx.Env("ProgramData"), false));
            roots.Add((Ctx.Env("PUBLIC"), true));

            var seen = new HashSet<string>(Util.IC);
            var found = new List<(FileInfo F, bool Arch)>();
            int nfiles = 0, ndirs = 0;
            var back = new List<(FileInfo F, DateTime Ch)>();   // programs/scripts with old whole-second creation time and recent change time
            var qk = new Dictionary<string, int>(Util.IC);
            var padded = new Dictionary<string, string>(Util.IC);   // file -> "padded: N MB of byte 0xXX"
            foreach (var (root, arch) in roots)
            {
                if (string.IsNullOrEmpty(root) || !Directory.Exists(root)) continue;
                var st = new Stack<(string, int)>(); st.Push((root, 0));
                while (st.Count > 0)
                {
                    var (dir, depth) = st.Pop();
                    if (!seen.Add(dir)) continue;   // AppData\Local\Temp is inside AppData\Local
                    ndirs++;
                    FileSystemInfo[] items;
                    try { items = new DirectoryInfo(dir).GetFileSystemInfos(); } catch { continue; }
                    foreach (var it in items)
                    {
                        if ((it.Attributes & FileAttributes.Directory) != 0)
                        {
                            if ((it.Attributes & FileAttributes.ReparsePoint) == 0 && depth < 7 && !(Rules.Whitelist && SkipDirs.Contains(it.Name))) st.Push((it.FullName, depth + 1));
                            continue;
                        }
                        nfiles++;
                        if ((it.Attributes & (FileAttributes)(0x1000 | 0x40000 | 0x400000)) != 0) continue;   // cloud placeholders
                        bool isArch = Archive.IsMatch(it.Name);
                        bool script = Script.IsMatch(it.Name) && depth <= 3 && !(Rules.Whitelist && ScriptNoise.IsMatch(it.FullName));
                        // shortcuts only with a lowered zone (!motw-removed): new .lnk files on the Desktop are normal
                        bool shortcut = Shortcut.IsMatch(it.Name) && Rules.DropLocation(it.FullName);
                        // big new files in drop locations, whatever their type: padding against scanner size limits (!padded)
                        string pad = depth <= 3 && it.CreationTimeUtc >= c.Since && ((FileInfo)it).Length > Padded.MinExe && Rules.DropLocation(it.FullName)
                                     ? Padded.OfFile((FileInfo)it) : null;
                        if (pad != null) padded[it.FullName] = pad;
                        if (!Exec.IsMatch(it.Name) && !script && !shortcut && !(isArch && arch && depth <= 2) && pad == null) continue;
                        if (it.CreationTimeUtc < c.Since)
                        {
                            // an "old" program or script whose creation time is a whole second (as timestomping tools write it) but whose
                            // NTFS change time is recent: its times were probably set back to hide it from this scan
                            // (programs and scripts only: shortcuts and padded data files are here for other checks)
                            if ((Exec.IsMatch(it.Name) || script) && it.CreationTimeUtc.Ticks % 10000000 == 0 && Native.ChangeTime(it.FullName) is DateTime ch
                                && ch >= c.Since && ch > it.CreationTimeUtc.AddDays(1) && ch > it.LastWriteTimeUtc.AddDays(1))
                            {
                                back.Add(((FileInfo)it, ch));
                            }
                            continue;
                        }
                        if (shortcut && !Exec.IsMatch(it.Name) && !Rules.MotwRemoved(it.FullName, Ads.Origin(it.FullName))) continue;
                        var rel = it.FullName.Length > 2 ? it.FullName.Substring(2) : it.FullName;
                        // known-noise folders hide only files without flags and, for executables, with a valid signature
                        if (Rules.Whitelist && noise.IsMatch(rel) && Rules.Flags(it.FullName).Count == 0 && pad == null && c.SignedOk(it.FullName))
                        {
                            var m = noise.Match(rel); var k = it.FullName.Substring(0, 2 + m.Index + m.Length);
                            qk[k] = qk.TryGetValue(k, out var n) ? n + 1 : 1;
                            continue;
                        }
                        // .NET's BreadcrumbStore: empty marker files named after assemblies ("netcore,DryIoc.dll"); a file with content stays
                        if (Rules.Whitelist && Breadcrumb.IsMatch(rel) && ((FileInfo)it).Length == 0)
                        {
                            var k = it.FullName.Substring(0, 2) + Breadcrumb.Match(rel).Value;
                            qk[k] = qk.TryGetValue(k, out var n) ? n + 1 : 1;
                            continue;
                        }
                        found.Add(((FileInfo)it, isArch));
                    }
                }
            }

            // per folder: up to PerDir files one by one, else one line for the folder (installers unpack hundreds of DLLs)
            int per = c.Opt.PerDir, withUrl = 0;
            // folders with a new program: padding next to one (same folder or the folder above) is a strong sign
            var programDirs = new HashSet<string>(found.Where(f => Exec.IsMatch(f.F.Name)).Select(f => f.F.DirectoryName), Util.IC);
            foreach (var g in found.GroupBy(f => f.F.DirectoryName, Util.IC))
            {
                var all = g.OrderBy(f => f.F.CreationTimeUtc).Select(f => new NewFile { F = f.F, Zone = Ads.Origin(f.F.FullName) }).ToList();
                foreach (var f in all)
                    if (Rules.MotwRemoved(f.F.FullName, f.Zone)) f.Flags.Add("!motw-removed");
                if (Rules.DropLocation(g.Key + @"\x")) SideLoading(g.Key, all);
                foreach (var f in all)
                    if (Names.RenamedDetail(c, f.F.FullName) is string renamed) { f.Flags.Add(Names.RenamedFlag); f.Details.Add(renamed); }
                foreach (var f in all.Where(f => padded.ContainsKey(f.F.FullName)))
                {
                    // the flag on programs and on data next to a new program; else only the detail (a big download can be padded too)
                    f.Padded = true;
                    f.Details.Add(padded[f.F.FullName]);
                    var parent = Path.GetDirectoryName(g.Key);
                    if (Exec.IsMatch(f.F.Name) || programDirs.Contains(g.Key) || (parent != null && programDirs.Contains(parent))) f.Flags.Add(Padded.Flag);
                }
                // a file with a strong flag or a hint (from its name or from the checks above) always gets its own line
                var flagged = all.Where(f => Rules.Strong(Rules.Flags(f.F.FullName)).Count > 0 || f.Flags.Count > 0).ToList();
                var rest = all.Except(flagged).ToList();
                var single = rest.Count <= per ? rest : rest.Where(f => f.HasUrl || f.Padded).ToList();   // every download and padded file keeps its own line
                foreach (var f in flagged.Concat(single))
                {
                    if (f.HasUrl) withUrl++;
                    var urls = f.Zone?.Urls;
                    c.Event(f.F.CreationTimeUtc, "NEW", f.F.FullName, Details(f), f.Flags.Count > 0 ? f.Flags : null, noHash: f.Padded,
                            more: urls != null && urls.Count > 0 ? urls : null);
                }
                var others = rest.Except(single).ToList();
                if (others.Count > 0)
                {
                    var names = others.Select(f => f.F.Name).ToList();
                    var ordered = names.Where(n => n.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)).Concat(names).Distinct(Util.IC);   // programs first
                    // the names on files: sub-lines (an installer unpacks hundreds)
                    c.Event(others[0].F.CreationTimeUtc, "NEW", null, text: $"{c.RealCase(g.Key)}\\ => {others.Count} new files",
                            more: Log.Chunks(ordered).Select(p => ("files", p)).ToList());
                }
            }
            c.Out.Comment($"Checked {nfiles} files in {ndirs} folders ({sw.Elapsed.TotalSeconds:N1} s): {found.Count} executables, scripts or archives created in the last {c.Opt.Days} days, {withUrl} of them with a download URL.");
            Backdated(back);
            c.Out.Comment("They are in the timeline (NEW). A folder with more than " + per + " new files is one line, its names on files: lines (installers, updates); files with a download URL always get their own line.");
            c.Out.Hidden(qk, "new files");
        }

        /// <summary>
        /// Old-looking files with a recent NTFS change time. Installers and updaters copy files with their original (whole-second) times,
        /// many files in one folder tree within a minute: one unflagged line per such batch, with the names of its files that are not
        /// validly signed. A single file or two, unsigned or not validly signed, is flagged !timestomped. Validly signed files are not
        /// timestomping candidates, but they count for the batch: an install of signed programs with one unsigned .jar is a batch.
        /// Windows Update's download folder is left out (its packages keep the times they were built with).
        /// </summary>
        void Backdated(List<(FileInfo F, DateTime Ch)> back)
        {
            bool Candidate(string p) => !Rules.Whitelist || !Signature.Applies(p) || !c.SignedOk(p);
            foreach (var x in Batches(back.Where(b => !(Rules.Whitelist && Rules.InWindowsUpdateFolder(b.F.FullName))), b => b.F.FullName, b => b.Ch))
            {
                var cand = x.Where(b => Candidate(b.F.FullName)).ToList();
                if (cand.Count == 0) continue;
                if (Rules.Whitelist && x.Count >= 3)
                {
                    foreach (var fo in cand.GroupBy(b => b.F.DirectoryName, Util.IC))
                        c.Event(fo.Max(b => b.Ch), "STP", null,
                                text: $"{Rules.Fix(fo.Key)}\\ => {Util.Plural(fo.Count(), "file", "files")} written with older timestamps (installer or update, {x.Count} programs at once)",
                                more: Log.Chunks(fo.Select(b => Rules.Fix(b.F.Name))).Select(p => ("files", p)).ToList());
                    continue;
                }
                foreach (var b in cand)
                {
                    // the line's time is the NTFS change time (when the times were set)
                    c.Event(b.Ch, "STP", b.F.FullName, Timestomp.StpDetail(b.F.CreationTimeUtc, b.F.LastWriteTimeUtc), new List<string> { "!timestomped" });
                }
            }
        }

        /// <summary>
        /// (pure) Backdated files in batches: the same folder tree (two levels below AppData\Local|Roaming|LocalLow, ProgramData or a
        /// profile folder, else the file's folder) and change times at most 60 s apart.
        /// </summary>
        internal static List<List<T>> Batches<T>(IEnumerable<T> items, Func<T, string> path, Func<T, DateTime> changed)
        {
            string Root(string p)
            {
                foreach (var rx in new[] { @"^(.*?\\AppData\\(Local|Roaming|LocalLow)\\[^\\]+(\\[^\\]+)?)\\", @"^([a-z]:\\ProgramData\\[^\\]+(\\[^\\]+)?)\\", @"^([a-z]:\\Users\\[^\\]+\\[^\\]+(\\[^\\]+)?)\\" })
                { var m = Regex.Match(p, rx, Util.RX); if (m.Success) return m.Groups[1].Value; }
                return Util.Folder(p);
            }
            var res = new List<List<T>>();
            foreach (var g in items.GroupBy(b => Root(path(b)), Util.IC))
            {
                List<T> cur = null;
                foreach (var b in g.OrderBy(changed))
                {
                    if (cur == null || (changed(b) - changed(cur[cur.Count - 1])).TotalSeconds > 60) res.Add(cur = new List<T>());
                    cur.Add(b);
                }
            }
            return res;
        }
    }
}
