using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

namespace Spor
{
    /// <summary>What Correlate found around a script-runtime launcher; the decision (Signals) is pure.</summary>
    sealed class RuntimeFolder
    {
        public string Launcher;                                   // the program
        public bool New;                                          // it or files below it were created in the time window
        public List<string> Padded = new List<string>();          // padded files below it (!padded or a "padded:" detail)
        public List<string> RandomData = new List<string>();      // random-named, high-entropy data files with an unknown extension
        public List<string> DotFiles = new List<string>();        // hidden or dot files next to a script container
        public List<(string Path, DateTime? Run)> Children = new List<(string, DateTime?)>();   // programs it started outside its folder, and the run that did (null: none known)
        public List<(string Path, DateTime Run)> MotwNearRun = new List<(string, DateTime)>();  // !motw-removed files written within 2 minutes of one of its runs, and that run
    }

    /// <summary>
    /// Checks that need the results of several modules. Runs after all modules, before the timeline is written.
    /// Script-runtime launchers: their script files on the timeline line, and !runtime-loader when the folder also shows loader signs.
    /// </summary>
    static class Correlate
    {
        public const string RuntimeFlag = "!runtime-loader";
        const long RandomDataMin = 512 * 1024;
        static readonly string[] RunSources = { "PF", "PCA", "UA", "BAM", "PROC", "TSK", "4688", "SYSMON" };

        /// <summary>Data files a random name and high entropy are normal for (media, archives, models, caches, ...).</summary>
        static readonly Regex KnownData = new Regex(
            @"\.(exe|dll|pyd|so|zip|7z|rar|gz|xz|bz2|tar|zst|png|jpe?g|webp|gif|bmp|ico|svg|ogg|opus|mp3|wav|flac|m4a|mp4|webm|mkv|avi|mov|ttf|otf|woff2?|" +
            @"pak|asar|rpa|rpyc|rpy|pyc|pyz|jar|class|json|xml|txt|log|ini|cfg|db|sqlite|cab|msi|iso|img|pdf|docx?|xlsx?|pptx?|chm|pck|bundle|assets|" +
            @"ress?|unity3d|npz|pt|onnx|gguf|safetensors|nupkg|vsix|crx|blob|ldb|idx|pack)$", Util.RX);

        /// <summary>The loader signs that make a new script-runtime folder !runtime-loader; none for a folder that is not new.</summary>
        public static List<string> Signals(RuntimeFolder r)
        {
            var s = new List<string>();
            if (r == null || !r.New) return s;
            s.AddRange(FolderSigns(r));
            s.AddRange(r.Children.Select(x => "started " + x.Path).Distinct(Util.IC));
            s.AddRange(r.MotwNearRun.Select(x => "!motw-removed file " + x.Path + " written within 2 minutes of a run").Distinct(Util.IC));
            return s;
        }

        /// <summary>The signs in the folder itself: on the launcher's first line.</summary>
        static IEnumerable<string> FolderSigns(RuntimeFolder r) =>
            r.Padded.Select(p => "padded file " + p)
             .Concat(r.RandomData.Select(p => "random-named encrypted-looking data file " + p))
             .Concat(r.DotFiles.Select(p => "hidden file " + p + " next to its scripts"));

        /// <summary>
        /// (pure) The signs of each run (programs it started, !motw-removed files written near it), for that run's line: a later run's
        /// notes do not belong on the first line. Run null: a started program without a known run (on the first line). None for a
        /// folder that is not new.
        /// </summary>
        public static List<(DateTime? Run, List<string> Notes)> RunNotes(RuntimeFolder r)
        {
            if (r == null || !r.New) return new List<(DateTime?, List<string>)>();
            return r.Children.Select(x => (Run: x.Run, Note: "started " + x.Path))
                    .Concat(r.MotwNearRun.Select(x => (Run: (DateTime?)x.Run, Note:"!motw-removed file " + x.Path + " written within 2 minutes of this run")))
                    .GroupBy(x => x.Run).OrderBy(g => g.Key ?? DateTime.MinValue)
                    .Select(g => (g.Key, g.Select(x => x.Note).Distinct(Util.IC).ToList())).ToList();
        }

        /// <summary>
        /// (pure) The run something at time t belongs to: the latest run at or before t (a dropper writes and starts things after it
        /// starts), else the nearest; only runs within `window` seconds when given. Null for none.
        /// </summary>
        internal static DateTime? RunOf(IEnumerable<DateTime> runs, DateTime t, double? window = null)
        {
            var near = runs.Where(r => window == null || Math.Abs((r - t).TotalSeconds) <= window.Value).ToList();
            if (near.Count == 0) return null;
            var before = near.Where(r => r <= t).ToList();
            return before.Count > 0 ? before.Max() : near.OrderBy(r => Math.Abs((r - t).TotalSeconds)).First();
        }

        /// <summary>
        /// (pure) The run lines of a launcher: each run with notes, in time order. Only the first and the last are flagged: a loader task
        /// that runs every few minutes would fill the timeline and SUMMARY otherwise; the runs between are counted ("+N more times").
        /// </summary>
        internal static List<(DateTime Run, List<string> Notes, bool Flagged)> RunLines(List<(DateTime? Run, List<string> Notes)> notes)
        {
            var runs = notes.Where(n => n.Run != null).OrderBy(n => n.Run.Value).ToList();
            return runs.Select((n, i) => (n.Run.Value, n.Notes, i == 0 || i == runs.Count - 1)).ToList();
        }

        /// <summary>
        /// (pure) The signs on the launcher's first line: the folder's, and programs it started without a known run. The first line
        /// carries !runtime-loader only with one of these; the others are on their run's line.
        /// </summary>
        internal static List<string> FirstLineSigns(RuntimeFolder r, List<(DateTime? Run, List<string> Notes)> notes) =>
            FolderSigns(r).Concat(notes.Where(n => n.Run == null).SelectMany(n => n.Notes)).ToList();

        public static void Run(Ctx c)
        {
            try { RuntimeLaunchers(c); }
            catch (Exception e) { c.Err.Add("script-runtime check: " + e.Message); }
        }

        static bool Under(string path, string dir) => path != null && path.StartsWith(dir + "\\", StringComparison.OrdinalIgnoreCase);

        static void RuntimeLaunchers(Ctx c)
        {
            var trees = new Dictionary<string, List<(string Rel, FileInfo F)>>(Util.IC);
            var exes = c.Events.Where(e => e.Path != null && e.Path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) && Rules.DrivePath.IsMatch(e.Path))
                                .GroupBy(e => c.RealCase(e.Path), Util.IC).ToList();
            foreach (var g in exes)
            {
                var exe = g.Key;
                if (Rules.InTrustedLocation(exe) || Rules.Interpreter.IsMatch(exe) || !File.Exists(exe)) continue;
                var dir = Path.GetDirectoryName(exe);
                // a program directly in Downloads, Desktop, Temp, ...: the folder holds other apps' files, its markers say nothing
                if (Rules.SharedFolder(dir)) continue;
                if (!trees.TryGetValue(dir, out var tree)) trees[dir] = tree = Tree(dir);
                var kind = Rules.ScriptRuntime(exe, tree.Select(t => t.Rel));
                if (kind == null) continue;
                // Electron apps of well-known publishers are everywhere (Discord, VS Code, Slack, with updaters and helpers):
                // they keep the normal whitelist and are never !runtime-loader
                bool electron = kind == "Electron";
                if (!electron) c.RuntimeLaunchers.Add(exe);

                var containers = tree.Where(t => Rules.ScriptContainer.IsMatch(t.Rel) && !Rules.RuntimeLibFolder.IsMatch(t.Rel)).ToList();
                var containerDirs = new HashSet<string>(containers.Select(t => t.F.DirectoryName), Util.IC);
                var hidden = tree.Where(t => !Rules.RuntimeLibFolder.IsMatch(t.Rel) && (t.F.Name.StartsWith(".") || (t.F.Attributes & FileAttributes.Hidden) != 0)
                                             && !Regex.IsMatch(t.F.Name, @"^(desktop\.ini|thumbs\.db|\.ds_store)$", Util.RX)).ToList();
                var created = tree.Select(t => t.F.CreationTimeUtc).Concat(new[] { File.GetCreationTimeUtc(exe) });
                var events = g.ToList();
                var runs = events.Where(e => RunSources.Contains(e.Src)).ToList();
                var runTimes = runs.Select(e => e.T).ToList();
                // the run a thing belongs to (RunOf)
                DateTime? RunAt(DateTime? t, double? window = null) => t.HasValue ? RunOf(runTimes, t.Value, window) : null;
                var r = new RuntimeFolder
                {
                    Launcher = exe,
                    New = created.Any(t => t >= c.Since),
                    Padded = c.Events.Where(e => Under(e.Path, dir) && ((e.Flags != null && e.Flags.Contains("!padded")) || (e.Extra ?? "").Contains("padded: ")))
                                     .Select(e => c.RealCase(e.Path)).Distinct(Util.IC).ToList(),
                    RandomData = tree.Where(t => t.F.Length > RandomDataMin && !KnownData.IsMatch(t.F.Name) && Names.IsRandom(t.F.Name) && Entropy(t.F) > 7.9)
                                     .Select(t => t.F.FullName).ToList(),
                    DotFiles = hidden.Where(t => containerDirs.Contains(t.F.DirectoryName)).Select(t => t.F.FullName).ToList(),
                    // programs it started itself: outside its folder and outside Windows and Program Files, or a proxy-execution
                    // launcher with arguments that start a program (conhost, WerFault, a shell of a CLI tool are no sign)
                    Children = c.Launches.Where(l => l.Parent.Equals(exe, StringComparison.OrdinalIgnoreCase) && !Under(l.Child, dir)
                                                     && (!Rules.InTrustedLocation(l.Child) || Rules.ProxyLaunch(l.Child, l.CommandLine)))
                                         .Select(l => (l.Child, RunAt(l.T))).Distinct().ToList(),
                    // written within 2 minutes of a run: given to the latest such run at or before it, else the nearest
                    MotwNearRun = c.Events.Where(e => e.Path != null && e.Flags != null && e.Flags.Contains("!motw-removed"))
                                          .Select(e => (Run: RunAt(e.T, 120), Path: c.RealCase(e.Path)))
                                          .Where(x => x.Run != null)
                                          .Select(x => (x.Path, x.Run.Value)).Distinct().ToList(),
                };
                var signals = electron ? new List<string>() : Signals(r);
                var notes = signals.Count > 0 ? RunNotes(r) : new List<(DateTime? Run, List<string> Notes)>();

                // the script files on the launcher's first line: hidden ones first, then the biggest containers
                var shown = hidden.Concat(containers.OrderByDescending(t => t.F.Length)).Distinct().Take(10).ToList();
                var more = shown.Select(t => ("script", Log.Item(c.F(t.F.FullName, false).Path, null,
                    $"{Log.T(t.F.CreationTimeUtc)}; {t.F.Length} bytes" + ((t.F.Attributes & FileAttributes.Hidden) != 0 || t.F.Name.StartsWith(".") ? "; hidden" : "")))).ToList();
                // the first line: the folder's signs (and programs it started without a known run); each run's signs go on its own line
                var firstSigns = signals.Count > 0 ? FirstLineSigns(r, notes) : new List<string>();
                var extra = $"script runtime {kind}" + (containers.Count + hidden.Count > shown.Count ? $", {containers.Count + hidden.Count} script and hidden files" : "")
                            + (firstSigns.Count > 0 ? "; " + string.Join("; ", firstSigns) : "");
                var first = events.OrderBy(e => e.T).First();
                c.Events.Add(new TEvent
                {
                    T = first.T, Src = first.Src, Path = first.Path, Extra = extra, NoHash = first.NoHash,
                    // flagged only with signs of its own: the others are on their run's line
                    Flags = firstSigns.Count > 0 ? new List<string> { RuntimeFlag } : null, More = more,
                });
                foreach (var (runT, runNotes, flagged) in RunLines(notes))
                {
                    var run = runs.First(e => e.T == runT);
                    c.Events.Add(new TEvent
                    {
                        T = run.T, Src = run.Src, Path = run.Path, Extra = string.Join("; ", runNotes), NoHash = run.NoHash, Pid = run.Pid,
                        Flags = flagged ? new List<string> { RuntimeFlag } : null,
                    });
                }
            }
        }

        /// <summary>Files up to two folders below dir (relative paths), at most 5000.</summary>
        static List<(string Rel, FileInfo F)> Tree(string dir)
        {
            var res = new List<(string, FileInfo)>();
            var st = new Stack<(DirectoryInfo D, int Depth)>();
            st.Push((new DirectoryInfo(dir), 0));
            while (st.Count > 0 && res.Count < 5000)
            {
                var (d, depth) = st.Pop();
                FileSystemInfo[] items;
                try { items = d.GetFileSystemInfos(); } catch { continue; }
                foreach (var it in items)
                {
                    if ((it.Attributes & FileAttributes.Directory) != 0)
                    {
                        if (depth < 2 && (it.Attributes & FileAttributes.ReparsePoint) == 0) st.Push(((DirectoryInfo)it, depth + 1));
                        continue;
                    }
                    res.Add((it.FullName.Substring(dir.Length).TrimStart('\\'), (FileInfo)it));
                }
            }
            return res;
        }

        /// <summary>Entropy of 128 KB: the start and the middle of the file.</summary>
        static double Entropy(FileInfo f)
        {
            try
            {
                using (var fs = new FileStream(f.FullName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                {
                    var b = new byte[128 * 1024];
                    int n = fs.Read(b, 0, 64 * 1024);
                    fs.Position = Math.Max(0, fs.Length / 2);
                    int m = fs.Read(b, n, 64 * 1024);
                    return Util.Entropy(b, n + m);
                }
            }
            catch { return 0; }
        }
    }
}
