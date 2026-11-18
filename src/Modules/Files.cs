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

        static readonly Regex Exec = new Regex(@"\.(exe|dll|scr|com|pif|cpl|sys|ocx|drv|efi|msi|msp|msc|jar|jnlp|xll|xlam|docm|dotm|xlsm|pptm|ppam|appx|msix|appinstaller|application|appref-ms|rdp|library-ms|search-ms|settingcontent-ms|scf|iqy|slk)$", Util.RX);
        // scripts: up to 3 folder levels deep (loaders use e.g. AppData\Roaming\x\y\run.vbs), except where scripts are normal
        static readonly Regex Script = new Regex(@"\.(bat|cmd|ps1|psm1|psd1|vbs|vbe|js|jse|jsc|wsf|wsh|wsc|sct|hta|py|pyw|au3|a3x|ahk)$", Util.RX);
        static readonly Regex ScriptNoise = new Regex(@"\\(Mozilla\\(Firefox|Thunderbird)|Thunderbird|Waterfox|LibreWolf)\\|\\(nvm|npm|npm-cache|pnpm|yarn|JetBrains|Code\\User|Code - Insiders|Cursor\\User|GitHub Desktop|Postman)\\|\\(prefs|user|times)\.js$", Util.RX);
        static readonly Regex Archive = new Regex(@"\.(zip|rar|7z|cab|iso|img|vhd|vhdx|tar|gz|tgz|ace|arj|z)$", Util.RX);
        static readonly HashSet<string> SkipDirs = new HashSet<string>(new[] {
            "node_modules", ".git", "site-packages", "__pycache__", "Cache", "Code Cache", "GPUCache", "Service Worker", "IndexedDB",
            "Packages", "WinSxS", "assembly", "CacheStorage", "ShaderCache", "DawnCache", "DawnGraphiteCache", "DawnWebGPUCache", "GrShaderCache", "blob_storage",
            "Local Storage", "Session Storage", "INetCache", "WebCache", "Crashpad", "CrashDumps", "Package Cache", "WindowsApps", "pip", "npm-cache",
            ".nuget", ".gradle", ".m2", ".cargo", ".rustup", "venv", ".venv" }, Util.IC);
        const string NoiseList = @"\\APPDATA\\LOCAL\\PROGRAMS\\MICROSOFT VS CODE\\|\\APPDATA\\LOCAL\\MICROSOFT\\(EDGE|ONEDRIVE|TEAMS|WINGET)\\|\\APPDATA\\LOCAL\\(DISCORD|SLACK|GITHUBDESKTOP|SQUIRRELTEMP)\\|\\\.VSCODE\\|\\APPDATA\\LOCAL\\TEMP\\(MSEDGE_|CHROME_|SCOPED_DIR|.*\\RESOURCES\\APP\\SERVICEHUB\\)|\\PROGRAMDATA\\MICROSOFT\\(WINDOWS DEFENDER|CLICKTORUN|EDGEUPDATE|WINDOWS\\WER)\\|\\PYTHON\d+\\(LIB|DLLS|SCRIPTS)\\|\\APPDATA\\LOCAL\\TEMP\\IS-[A-Z0-9]+\.TMP\\";

        Ctx c;
        Regex noise;

        public void Execute(Ctx ctx)
        {
            c = ctx; noise = Rules.Noise(NoiseList);
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
                        if (!Exec.IsMatch(it.Name) && !script && !(isArch && arch && depth <= 2)) continue;
                        if (it.CreationTimeUtc < c.Since)
                        {
                            // an "old" program or script whose creation time is a whole second (as timestomping tools write it) but whose
                            // NTFS change time is recent: its times were probably set back to hide it from this scan
                            if (!isArch && it.CreationTimeUtc.Ticks % 10000000 == 0 && Native.ChangeTime(it.FullName) is DateTime ch
                                && ch >= c.Since && ch > it.CreationTimeUtc.AddDays(1) && ch > it.LastWriteTimeUtc.AddDays(1))
                            {
                                back.Add(((FileInfo)it, ch));
                            }
                            continue;
                        }
                        var rel = it.FullName.Length > 2 ? it.FullName.Substring(2) : it.FullName;
                        // known-noise folders hide only files without flags and, for executables, with a valid signature
                        if (Rules.Whitelist && noise.IsMatch(rel) && Rules.Flags(it.FullName).Count == 0 && c.SignedOk(it.FullName))
                        {
                            var m = noise.Match(rel); var k = it.FullName.Substring(0, 2 + m.Index + m.Length);
                            qk[k] = qk.TryGetValue(k, out var n) ? n + 1 : 1;
                            continue;
                        }
                        found.Add(((FileInfo)it, isArch));
                    }
                }
            }

            // per folder: up to PerDir files one by one, else one line for the folder (installers unpack hundreds of DLLs)
            int per = c.Opt.PerDir, withUrl = 0;
            var lines = new List<(DateTime T, string Text)>();
            foreach (var g in found.GroupBy(f => f.F.DirectoryName, Util.IC))
            {
                var all = g.OrderBy(f => f.F.CreationTimeUtc).ToList();
                var flagged = all.Where(f => Rules.Strong(Rules.Flags(f.F.FullName)).Count > 0).ToList();
                var rest = all.Except(flagged).ToList();
                var single = rest.Count <= per ? rest : rest.Where(f => Ads.Origin(f.F.FullName) != null).ToList();   // every download keeps its URL
                foreach (var f in flagged.Concat(single))
                {
                    var o = Ads.Origin(f.F.FullName); if (o != null) withUrl++;
                    c.Event(f.F.CreationTimeUtc, "NEW", f.F.FullName, o);
                }
                var others = rest.Except(single).ToList();
                if (others.Count > 0)
                {
                    var names = others.Select(f => f.F.Name).ToList();
                    var ordered = names.Where(n => n.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)).Concat(names).Distinct(Util.IC);   // programs first
                    var text = $"{c.RealCase(g.Key)}\\ => {others.Count} new files: {string.Join(", ", ordered)}";
                    c.Event(others[0].F.CreationTimeUtc, "NEW", null, text: text);
                    lines.Add((others[0].F.CreationTimeUtc, text));
                }
            }
            c.Out.Comment($"Checked {nfiles} files in {ndirs} folders ({sw.Elapsed.TotalSeconds:N1} s): {found.Count} executables, scripts or archives created in the last {c.Opt.Days} days, {withUrl} of them with a download URL.");
            Backdated(back);
            c.Out.Comment("They are in the timeline (NEW). A folder with more than " + per + " new files is one line with all names (installers, updates); files with a download URL always get their own line.");
            c.Out.Hidden(qk, "new files");
        }

        /// <summary>
        /// Old-looking files with a recent NTFS change time. Installers and updaters copy files with their original (whole-second) times,
        /// many files in one folder tree within a minute: one unflagged line per such batch, with every name. A single file or two,
        /// unsigned or not validly signed, is flagged !timestomped. Validly signed files are not timestomping candidates.
        /// </summary>
        void Backdated(List<(FileInfo F, DateTime Ch)> back)
        {
            var cand = back.Where(b => !Rules.Whitelist || !Signature.Applies(b.F.FullName) || !c.SignedOk(b.F.FullName)).ToList();
            int signedSkipped = back.Count - cand.Count, flagged = 0, batches = 0;
            // batch = same folder tree (three levels below AppData\Local|Roaming, ProgramData or the profile) and change times within 60 s
            string Root(string p)
            {
                foreach (var rx in new[] { @"^(.*?\\AppData\\(Local|Roaming|LocalLow)\\[^\\]+(\\[^\\]+)?)\\", @"^([a-z]:\\ProgramData\\[^\\]+(\\[^\\]+)?)\\", @"^([a-z]:\\Users\\[^\\]+\\[^\\]+(\\[^\\]+)?)\\" })
                { var m = Regex.Match(p, rx, Util.RX); if (m.Success) return m.Groups[1].Value; }
                return Util.Folder(p);
            }
            foreach (var g in cand.GroupBy(b => Root(b.F.FullName), Util.IC))
            {
                var cl = new List<List<(FileInfo F, DateTime Ch)>>();
                foreach (var b in g.OrderBy(b => b.Ch))
                {
                    if (cl.Count == 0 || (b.Ch - cl[cl.Count - 1].Last().Ch).TotalSeconds > 60) cl.Add(new List<(FileInfo, DateTime)>());
                    cl[cl.Count - 1].Add(b);
                }
                foreach (var x in cl)
                {
                    if (Rules.Whitelist && x.Count >= 3)
                    {
                        batches++;
                        foreach (var fo in x.GroupBy(b => b.F.DirectoryName, Util.IC))
                            c.Event(fo.Max(b => b.Ch), "STP", null, text: $"{Rules.Fix(fo.Key)}\\ => {fo.Count()} files written with older timestamps (installer or update): " +
                                                                            string.Join(", ", fo.Select(b => Rules.Fix(b.F.Name))));
                        continue;
                    }
                    foreach (var b in x)
                    {
                        flagged++;
                        c.Event(b.Ch, "STP", b.F.FullName, $"times set back: created {b.F.CreationTimeUtc:yyyy-MM-dd HH:mm:ss.fffffff}, modified {b.F.LastWriteTimeUtc:yyyy-MM-dd HH:mm:ss.fffffff}, " +
                                $"but NTFS change time {b.Ch:yyyy-MM-dd HH:mm:ss}", new List<string> { "!timestomped" });
                    }
                }
            }
            if (back.Count > 0)
                c.Out.Comment($"{back.Count} programs or scripts look old (whole-second creation time) but their NTFS change time is recent: {flagged} flagged !timestomped, " +
                              $"{back.Count - flagged - signedSkipped} in {batches} installer/update batches (3+ files in one folder tree within a minute, unflagged), {signedSkipped} validly signed (not counted). All are in the timeline (STP) except the signed ones.");
        }
    }
}
