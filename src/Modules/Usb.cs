using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace Spor.Modules
{
    /// <summary>
    /// USB worms: the contents of the drives (removable and USB drives in full, other drives their root and hidden root folders, the
    /// system drive only its flagged root items and invisible-named root folders) with
    /// attributes, hidden and invisible-named items, autorun.inf, shortcuts with target, arguments and icon, Explorer settings that hide
    /// files, MountPoints2, USB device history and files opened from removable drives. Every listed file goes to FILES (hash, version).
    /// </summary>
    class Usb : IModule
    {
        public string Id => "usb";
        public string Name => "USB DRIVES";
        public string Description => "drives with hidden and invisible-named items, autorun.inf, shortcuts, USB device history";

        public const string WormFlag = "!usb-worm-lnk", IconFlag = "!disguised-icon", AutorunFlag = "!autorun", HiddenSystemFlag = "!hidden-system",
                            ClsidFlag = "!clsid-folder", AdsFlag = "!ads", ExplorerFlag = "!explorer-hiding", RootFlag = Rules.RootProgramFlag;

        sealed class Drive
        {
            public string Letter, Root, Label, Fs, Serial, Vendor, Product;
            public DriveType Type;
            public int Bus = -1;
            public long Size;
            public bool Deep;   // removable or on the USB bus: everything is listed
            public bool OnUsb;  // removable or on the USB bus, any size (a big USB hard disk too): checked as a USB drive
        }

        sealed class Item
        {
            public string Path, Name;
            public bool Dir;
            public FileAttributes Attr;
            public DateTime Created, Modified;
            public long Size;
            public int Depth;
            public List<(string Name, long Size)> Streams = new List<(string, long)>();
            public List<string> Flags = new List<string>();
            public List<string> Details = new List<string>();
        }

        Ctx c;

        public void Execute(Ctx ctx)
        {
            c = ctx;
            var sw = Stopwatch.StartNew();
            var drives = Drives();
            var shortcuts = new List<(Drive D, Item I)>();
            var autoruns = new List<(Drive D, Item I)>();
            foreach (var d in drives)
            {
                var items = Contents(d);
                shortcuts.AddRange(items.Where(i => !i.Dir && Regex.IsMatch(i.Name, @"\.(lnk|url)$", Util.RX)).Select(i => (d, i)));
                autoruns.AddRange(items.Where(i => i.Depth == 0 && i.Name.Equals("autorun.inf", StringComparison.OrdinalIgnoreCase)).Select(i => (d, i)));
            }
            Autorun(autoruns);
            Shortcuts(shortcuts);
            Settings();
            History();
            OpenedFromRemovable();
            c.Out.W();
            c.Out.Comment($"USB DRIVES took {sw.Elapsed.TotalSeconds:N1} s.");
        }

        // ---------------------------------------------------------------- drives

        /// <summary>Seconds a network drive may take to answer (a disconnected share would stall the scan).</summary>
        const int NetworkWait = 15;

        /// <summary>
        /// f() on a worker thread; default and timedOut when it takes longer than `seconds` (it is then left running). An exception of f
        /// is thrown here, as if f had run on this thread.
        /// </summary>
        static T Timed<T>(Func<T> f, int seconds, out bool timedOut)
        {
            var task = System.Threading.Tasks.Task.Run(f);
            try { timedOut = !task.Wait(TimeSpan.FromSeconds(seconds)); }
            catch (AggregateException e) { throw e.GetBaseException(); }
            return timedOut ? default(T) : task.Result;
        }

        /// <summary>Drive letters of network drives ("Z:"): their files are listed, not hashed.</summary>
        readonly HashSet<string> networkLetters = new HashSet<string>(Util.IC);

        /// <summary>A file on a network drive or share: not hashed (reading it goes over the network).</summary>
        bool OnNetwork(string p) => !string.IsNullOrEmpty(p) && (p.StartsWith(@"\\") || (p.Length >= 2 && networkLetters.Contains(p.Substring(0, 2))));

        /// <summary>The status of a file (hashed for FILES), or null for a file on a network drive.</summary>
        string Status(string p) => OnNetwork(p) ? null : c.F(p).Status;

        /// <summary>A file as a sub-line value with its USB flags: "path [status] &lt;==== flags" (not hashed on a network drive).</summary>
        string FileValue(string p) => OnNetwork(p) ? Log.Item(Shown(p), null, null, Rules.FlagCol(UsbFlags(p))) : c.FF(p, true, UsbFlags(p));

        List<Drive> Drives()
        {
            var res = new List<Drive>();
            c.Out.Sub("Drives", "deep = removable or USB drive: listed in full (hidden, system and invisible-named items too); network drives: the root, not hashed;\n" +
                                "other drives: the root and hidden root folders (a USB disk over 256 GB too, its items checked as on a USB drive);\n" +                                "the system drive: flagged root items and invisible-named root folders.");
            var t = new Table("*drive", "type", "bus", "device", "label", "file system", "serial", "size", "=listing");
            foreach (var di in DriveInfo.GetDrives())
            {
                var d = new Drive { Letter = di.Name.TrimEnd('\\'), Root = di.Name, Type = di.DriveType };
                bool ready = false, timedOut = false;
                // a disconnected network drive can block IsReady and the volume queries for a long time
                var info = Timed(() =>
                {
                    bool r = false;
                    try { r = di.IsReady; } catch { }
                    if (!r) return (Ready: false, Fs: (string)null, Size: 0L, Label: (string)null, Serial: (string)null);
                    string fs = null; long size = 0;
                    try { fs = di.DriveFormat; size = di.TotalSize; } catch { }
                    return (Ready: true, Fs: fs, Size: size, Label: Native.VolumeLabel(d.Root), Serial: Native.VolumeSerial(d.Root));
                }, d.Type == DriveType.Network ? NetworkWait : 120, out timedOut);
                ready = info.Ready;
                if (ready) { d.Fs = info.Fs; d.Size = info.Size; d.Label = info.Label; d.Serial = info.Serial; }
                if (d.Type == DriveType.Network) networkLetters.Add(d.Letter);
                if (d.Type == DriveType.Removable || d.Type == DriveType.Fixed)
                {
                    var s = Native.Storage(d.Letter);
                    d.Bus = s.Bus; d.Vendor = s.Vendor; d.Product = s.Product;
                }
                // listed file by file: removable drives and USB disks up to 256 GB (sticks, small SSDs: what worms spread on); a big USB
                // disk (media, backups) gets the root listing other fixed drives get
                d.Deep = ready && (d.Type == DriveType.Removable || (d.Bus == 7 && d.Size > 0 && d.Size <= DeepMaxBytes)) && !IsSystem(d);
                // a big USB disk is listed like a fixed drive (its root and hidden root folders), but worms spread on it like on a stick:
                // its hidden system items are flagged, and timeline lines of its files say "on USB drive"
                d.OnUsb = d.Deep || (ready && d.Bus == 7 && !IsSystem(d));
                if (d.OnUsb)
                {
                    if (d.Serial != null) c.UsbVolumes[d.Serial] = d.Label ?? "";
                    c.UsbLetters[d.Letter] = (d.Label ?? "", null);   // the time it was connected: History()
                }
                t.Add(d.Letter, d.Type.ToString().ToLowerInvariant(), BusName(d.Bus), string.Join(" ", new[] { d.Vendor, d.Product }.Where(x => x != null)),
                      d.Label != null ? Rules.Fix(d.Label) : null, d.Fs, d.Serial, d.Size > 0 ? d.Size + " bytes" : null,
                      timedOut ? $"not reachable (no answer in {NetworkWait} s)" : !ready ? "not ready (no medium)" : d.Deep ? "deep"
                      : d.Type == DriveType.Network ? "root, not hashed" : d.Type == DriveType.CDRom ? "root"
                      : IsSystem(d) ? "root, flagged items only" : d.OnUsb ? "root and hidden root folders (USB disk not listed in full)" : "root and hidden root folders");
                if (ready && d.Type != DriveType.NoRootDirectory && d.Type != DriveType.Unknown) res.Add(d);
                if (ready && !d.OnUsb) localLetters.Add(d.Letter);
            }
            t.WriteTo(c.Out);
            return res;
        }

        static string BusName(int bus)
        {
            switch (bus)
            {
                case -1: return null;
                case 1: return "SCSI";
                case 3: return "ATA";
                case 7: return "USB";
                case 8: return "RAID";
                case 0x0A: return "SAS";
                case 0x0B: return "SATA";
                case 0x0C: return "SD";
                case 0x0D: return "MMC";
                case 0x0E: return "virtual";
                case 0x0F: return "file-backed virtual";
                case 0x11: return "NVMe";
                default: return "bus " + bus;
            }
        }

        // ---------------------------------------------------------------- contents

        /// <summary>The largest USB disk (not removable) listed file by file: 256 GB.</summary>
        internal const long DeepMaxBytes = 256L * 1000 * 1000 * 1000;

        /// <summary>Hidden root folders of Windows and common software: not entered on non-removable drives.</summary>
        static readonly Regex KnownRootFolder = new Regex(
            @"^(\$Recycle\.Bin|System Volume Information|Recovery|Config\.Msi|\$WinREAgent|\$Windows\.~(BT|WS)|\$SysReset|\$GetCurrent|ProgramData|PerfLogs|Documents and Settings|MSOCache|OneDriveTemp|Boot|EFI|\$AV_ASW|\$Windows\.old)$", Util.RX);

        /// <summary>Hidden+system items that Windows itself makes: not !hidden-system.</summary>
        static readonly Regex WindowsHiddenSystem = new Regex(@"^(System Volume Information|\$RECYCLE\.BIN|desktop\.ini|Thumbs\.db|IndexerVolumeGuid|WPSettings\.dat|pagefile\.sys|hiberfil\.sys|swapfile\.sys|DumpStack\.log(\.tmp)?|bootmgr|BOOTNXT|BOOTSECT\.BAK|\.dropbox\.device)$", Util.RX);

        /// <summary>Root files of the system drive that cannot or need not be hashed (page file, hibernation file, ...).</summary>
        static readonly Regex SystemRootFile = new Regex(@"^(pagefile\.sys|hiberfil\.sys|swapfile\.sys|DumpStack\.log(\.tmp)?|bootmgr|BOOTNXT|BOOTSECT\.BAK)$", Util.RX);

        /// <summary>Films, music, subtitles, photos, Blu-ray and DVD structure: a media disk's bulk, no evidence.</summary>
        static readonly Regex MediaFile = new Regex(
            @"\.(MKV|MP4|AVI|MOV|WMV|M4V|WEBM|M2TS|MTS|MPG|MPEG|VOB|FLV|MP3|M4A|FLAC|WAV|OGG|OPUS|AAC|WMA|SRT|ASS|SSA|SUB|IDX|SUP|VTT|NFO|JPG|JPEG|PNG|GIF|BMP|WEBP|HEIC|TIF|TIFF|NEF|CR2|MPLS|CLPI|BDMV|BDJO|IFO|BUP)$", Util.RX);

        /// <summary>
        /// Aggressive whitelist (Aggr) for a drive listing: plain media files (MediaFile), and plain folders whose listed contents are all
        /// such (or that are not entered: a fixed drive's root folders). Plain = not hidden or system, no invisible character or
        /// space / dot at the end of the name, no alternate data stream, no details, no flags. Executables, shortcuts, scripts,
        /// archives, disk images and autorun.inf are never media.
        /// </summary>
        Dictionary<Item, string> ListingAggr(List<Item> items)
        {
            var res = new Dictionary<Item, string>();
            bool Plain(Item it) => (it.Attr & (FileAttributes.Hidden | FileAttributes.System)) == 0 && !Unseen(it.Name) && !EdgeName(it.Name)
                                   && it.Streams.Count == 0 && it.Details.Count == 0 && it.Flags.Count == 0;
            foreach (var it in items.Where(i => !i.Dir && Plain(i) && MediaFile.IsMatch(i.Name)))
                res[it] = "media, subtitle and image files and their folders on drives";
            // deepest folders first, so a folder sees whether its sub-folders are marked
            foreach (var dir in items.Where(i => i.Dir && Plain(i)).OrderByDescending(i => i.Depth))
            {
                var below = items.Where(o => o != dir && o.Path.StartsWith(dir.Path + "\\", StringComparison.OrdinalIgnoreCase)).ToList();
                if (below.All(res.ContainsKey)) res[dir] = below.Count == 0 ? "folders on drives whose contents are not listed or empty" : "media, subtitle and image files and their folders on drives";
            }
            return res;
        }

        List<Item> Contents(Drive d)
        {
            var items = new List<Item>();
            bool capped = false, network = d.Type == DriveType.Network, unreachable = false;
            int dirs = 0, denied = 0;
            var st = new Stack<(string Dir, int Depth)>();
            st.Push((d.Root.TrimEnd('\\'), 0));
            while (st.Count > 0)
            {
                var (dir, depth) = st.Pop();
                dirs++;
                FileSystemInfo[] fs;
                // the \\?\ form lists names that end with a space or a dot too (Win32 path rules would strip them);
                // a network drive gets a time limit
                try
                {
                    var path = @"\\?\" + dir + "\\";
                    if (!network) fs = new DirectoryInfo(path).GetFileSystemInfos();
                    else
                    {
                        fs = Timed(() => new DirectoryInfo(path).GetFileSystemInfos(), NetworkWait, out var to);
                        if (to) { unreachable = true; continue; }
                        if (fs == null) throw new IOException();
                    }
                }
                catch { denied++; continue; }
                var sub = new List<string>();
                foreach (var f in fs.OrderBy(x => x.Name, StringComparer.OrdinalIgnoreCase))
                {
                    if (items.Count >= c.Opt.UsbMax) { capped = true; break; }
                    var it = new Item { Path = dir + "\\" + f.Name, Name = f.Name, Depth = depth };
                    try { it.Attr = f.Attributes; it.Created = f.CreationTimeUtc; it.Modified = f.LastWriteTimeUtc; } catch { }
                    it.Dir = (it.Attr & FileAttributes.Directory) != 0;
                    if (!it.Dir) try { it.Size = ((FileInfo)f).Length; } catch { }
                    if (!network) try { it.Streams = Native.Streams(@"\\?\" + it.Path); } catch { }
                    items.Add(it);
                    if (it.Dir && (it.Attr & FileAttributes.ReparsePoint) == 0 && depth < c.Opt.UsbDepth && Enter(d, it)) sub.Add(it.Path);
                }
                if (capped) break;
                for (int i = sub.Count - 1; i >= 0; i--) st.Push((sub[i], depth + 1));   // listed in name order
            }

            // names of hidden items near the root: a worm's shortcut points into them or is named like them
            var hiddenNames = new HashSet<string>(items.Where(i => i.Depth <= 1 && (i.Attr & FileAttributes.Hidden) != 0).Select(i => i.Name), StringComparer.OrdinalIgnoreCase);
            foreach (var it in items) Classify(d, it, items);

            // the system drive: only what is flagged (its hidden root folders are a PC maker's and tools' own; thousands of log files)
            bool sys = IsSystem(d);
            c.Out.Sub($"Contents of {d.Letter}\\" + (d.Label != null ? " (" + Rules.Fix(d.Label) + ")" : ""),
                      d.Deep ? "Everything on the drive, folders end with \\. Times UTC; hash, signature and version of the files: FILES."
                      : network ? "Network drive: the root, folders end with \\. Times UTC. Files are not hashed and their streams not read (that would go over the network)."
                      : sys ? "System drive: only root items with flags (programs, scripts and shortcuts, invisible characters, alternate data streams, CLSID folders) " +
                              "and the contents of invisible-named root folders. Times UTC; hashes: FILES."
                      : "The root of the drive, and the contents of hidden, system or invisible-named root folders (not Windows' own). Times UTC; hashes: FILES.");
            var t = new Table("*item", "!status", "=attributes", "created", "modified", "size", "streams", "=details", "<flags");
            var aggr = Aggr.On ? ListingAggr(items) : new Dictionary<Item, string>();
            foreach (var it in items)
            {
                if (sys && it.Flags.Count == 0) continue;
                string status = null;
                // hashed (FILES): what can run or carry what runs; a drive's films and photos are no evidence
                bool hashable = !it.Dir && !(d.Letter.Equals(c.SystemDrive, StringComparison.OrdinalIgnoreCase) && it.Depth == 0 && SystemRootFile.IsMatch(it.Name))
                                && (Rules.ProgramFile(it.Path) || Signature.Applies(it.Path) || Archive.IsMatch(it.Name) || Rules.Strong(it.Flags).Count > 0);
                if (hashable && !EdgeName(it.Name)) status = Status(it.Path);
                // a name with a space or dot at its edge: a note in the details, not a status
                if (!it.Dir && EdgeName(it.Name) && !it.Details.Contains(EdgeNote(it.Name))) it.Details.Add(EdgeNote(it.Name));
                var streams = it.Streams.Count > 0 ? string.Join(", ", it.Streams.Select(s => Rules.Fix(s.Name) + " " + s.Size + " bytes")) : null;
                t.Add(Shown(it.Path) + (it.Dir ? "\\" : ""), status, AttrText(it.Attr), Log.T(it.Created), Log.T(it.Modified), it.Dir ? null : it.Size + " bytes",
                      streams, it.Details.Count > 0 ? string.Join("; ", it.Details) : null, Rules.FlagCol(it.Flags));
                if (aggr.TryGetValue(it, out var why)) t.Aggr(why);
                var strong = Rules.Strong(it.Flags);
                var hints = Rules.HintsOf(it.Flags);
                bool isNew = !it.Dir && !EdgeName(it.Name) && !network && it.Created >= c.Since;
                if (strong.Count > 0)
                {
                    // a new file goes to the timeline (and from there to the SUMMARY); folders and older files straight to the SUMMARY
                    if (isNew)
                        c.Event(it.Created, "NEW", it.Path, string.Join("; ", new[] { "on " + DriveText(d), AttrText(it.Attr) }.Concat(it.Details)),
                                it.Flags.Where(f => !Rules.Flags(it.Path).Contains(f)).ToList());
                    else
                        c.Find(it.Created, Log.Item(Shown(it.Path) + (it.Dir ? "\\" : ""), null, AttrText(it.Attr), Rules.FlagCol(strong.Concat(hints).ToList())), "created");
                }
                else if (hints.Count > 0 && isNew)
                    // a new program, script or shortcut in a drive's root (!root-program): the timeline; the SUMMARY shows it only next to a
                    // strong flag in the same folder (Scanner.Summary)
                    c.Event(it.Created, "NEW", it.Path, string.Join("; ", new[] { "on " + DriveText(d), AttrText(it.Attr) }.Concat(it.Details)), hints);
            }
            t.WriteTo(c.Out, sys ? "no flagged items" : "empty");
            if (capped) c.Out.Comment($"Stopped at {c.Opt.UsbMax} items; the rest of the drive is not listed.");
            if (unreachable) c.Out.Comment($"The drive did not answer in {NetworkWait} s; not listed.");
            if (denied > 0) c.Out.Comment($"{denied} of {dirs} folders could not be read (access denied).");
            c.Out.Comment($"{items.Count} items in {dirs} folders, {items.Count(i => (i.Attr & FileAttributes.Hidden) != 0)} hidden, " +
                          $"{items.Count(i => Unseen(i.Name) || EdgeName(i.Name))} with invisible characters or a space/dot at the end of the name.");
            AddHiddenNames(d, hiddenNames);
            return items;
        }

        readonly Dictionary<string, HashSet<string>> hiddenByDrive = new Dictionary<string, HashSet<string>>(Util.IC);
        void AddHiddenNames(Drive d, HashSet<string> names) => hiddenByDrive[d.Letter] = names;

        static string DriveText(Drive d) => (d.OnUsb ? "USB drive " : "drive ") + d.Letter + (string.IsNullOrEmpty(d.Label) ? "" : " " + Rules.Fix(d.Label));

        bool IsSystem(Drive d) => d.Letter.Equals(c.SystemDrive, StringComparison.OrdinalIgnoreCase);

        bool Enter(Drive d, Item it) => EnterFolder(d.Deep, IsSystem(d), d.Type, it.Depth, it.Name, it.Attr);

        /// <summary>
        /// (pure) Folders to list: everything on a deep drive; on other drives only hidden, system or oddly named root folders; on the
        /// system drive only invisible-named root folders (its hidden ones are a PC maker's or a tool's: C:\OEM, C:\Intel, ...).
        /// </summary>
        internal static bool EnterFolder(bool deep, bool systemDrive, DriveType type, int depth, string name, FileAttributes attr)
        {
            if (deep) return true;
            if (depth > 0) return true;   // inside a root folder that was entered
            if (type == DriveType.Network || type == DriveType.CDRom) return false;
            if (KnownRootFolder.IsMatch(name ?? "")) return false;
            if (Unseen(name) || EdgeName(name)) return true;
            return !systemDrive && (attr & (FileAttributes.Hidden | FileAttributes.System)) != 0;
        }

        /// <summary>
        /// (pure) !root-program: a program, script or shortcut (Rules.ProgramFile) in the root of a drive, where USB worms put their copy
        /// and shortcuts; not the page, hibernation and swap files of the system drive's root.
        /// </summary>
        internal static bool RootProgram(string name, int depth, bool dir) =>
            !dir && depth == 0 && !string.IsNullOrEmpty(name) && Rules.ProgramFile(name) && !SystemRootFile.IsMatch(name);

        /// <summary>Any character that cannot be seen: bidi overrides and every invisible character (also a no-break space).</summary>
        static bool Unseen(string s) => Rules.Bidi.IsMatch(s ?? "") || Rules.Invisible.IsMatch(s ?? "");

        /// <summary>
        /// (pure) The flags of a path on a drive: Rules.Flags, and !invisible-char for any invisible character (Rules.Flags flags only those
        /// never used in names; on a USB drive a no-break space in a folder name is a worm's) or a space / dot at the edge of a name.
        /// </summary>
        internal static List<string> UsbFlags(string path)
        {
            var f = Rules.Flags(path);
            if (!f.Contains(Rules.InvisibleFlag) && (Rules.Invisible.IsMatch(path ?? "") || Shown(path) != Rules.Fix(path))) f.Add(Rules.InvisibleFlag);
            return f;
        }

        void Classify(Drive d, Item it, List<Item> all)
        {
            it.Flags.AddRange(UsbFlags(it.Path));
            if (HiddenSystem(d.Deep, d.OnUsb, it.Depth, it.Name, it.Path, it.Attr)) it.Flags.Add(HiddenSystemFlag);
            if (RootProgram(it.Name, it.Depth, it.Dir)) it.Flags.Add(RootFlag);
            if (it.Dir && ClsidName(it.Name)) { it.Flags.Add(ClsidFlag); it.Details.Add("Explorer shows this folder as a shell object (CLSID in the name)"); }
            if (!it.Dir && it.Name.Equals("desktop.ini", StringComparison.OrdinalIgnoreCase) && it.Size < 64 * 1024)
            {
                string text = null;
                try { text = ReadIni(it.Path); } catch { }
                var cls = DesktopIniClsid(text);
                // the Recycle Bin's own desktop.ini (in $RECYCLE.BIN\S-1-...) sets the Recycle Bin's CLSID: Windows, not a disguise
                if (cls != null && RecycleBinIni(it.Path, cls)) cls = null;
                if (cls != null)
                {
                    it.Flags.Add(ClsidFlag); it.Details.Add("sets " + cls);
                    var folder = all.FirstOrDefault(x => x.Dir && x.Path.Equals(Util.Folder(it.Path), StringComparison.OrdinalIgnoreCase));
                    if (folder != null && !folder.Flags.Contains(ClsidFlag)) { folder.Flags.Add(ClsidFlag); folder.Details.Add("desktop.ini sets " + cls); }
                }
            }
            var odd = UnusualStreams(it.Streams.Select(s => s.Name));
            if ((d.Deep || it.Depth == 0) && odd.Count > 0) it.Flags.Add(AdsFlag);
            if (it.Dir && it.Name.Equals("RECYCLER", StringComparison.OrdinalIgnoreCase) && d.OnUsb) it.Details.Add("RECYCLER is the recycle bin name of Windows XP; newer Windows use $RECYCLE.BIN");
        }

        /// <summary>Archives and disk images: hashed on a drive like programs (a worm's payload can be packed).</summary>
        static readonly Regex Archive = new Regex(@"\.(zip|rar|7z|cab|iso|img|vhdx?)$", Util.RX);

        /// <summary>(pure) The note for a name with a space or dot at its edge.</summary>
        internal static string EdgeNote(string name) =>
            (name ?? "").EndsWith(" ") || (name ?? "").EndsWith(".") ? "name ends with a space or dot: Windows programs cannot open it"
                                                                   : "name starts with a space: Explorer hides it";

        /// <summary>
        /// (pure) !hidden-system: a hidden and system item on a removable drive or USB disk (`onUsb`), not one Windows makes itself. On a
        /// USB disk that is not listed in full (over 256 GB) also not Windows' and common software's root folders (KnownRootFolder): such a
        /// disk may have been a PC's system disk.
        /// </summary>
        internal static bool HiddenSystem(bool deep, bool onUsb, int depth, string name, string path, FileAttributes attr)
        {
            if (!onUsb || (attr & FileAttributes.Hidden) == 0 || (attr & FileAttributes.System) == 0) return false;
            if (WindowsHiddenSystem.IsMatch(name ?? "") || InWindowsHiddenFolder(path)) return false;
            return deep || depth > 0 || !KnownRootFolder.IsMatch(name ?? "");
        }

        /// <summary>(pure) An item inside a folder Windows itself keeps hidden and system ($RECYCLE.BIN, System Volume Information).</summary>
        internal static bool InWindowsHiddenFolder(string path) =>
            Regex.IsMatch(path ?? "", @"\\(\$RECYCLE\.BIN|System Volume Information)\\", Util.RX);

        /// <summary>The Recycle Bin's CLSID.</summary>
        const string RecycleBinClsid = "{645FF040-5081-101B-9F08-00AA002F954E}";

        /// <summary>(pure) A desktop.ini in the Recycle Bin that sets the Recycle Bin's CLSID (normal: Windows writes it).</summary>
        internal static bool RecycleBinIni(string path, string clsid) =>
            InWindowsHiddenFolder(path) && (clsid ?? "").IndexOf(RecycleBinClsid, StringComparison.OrdinalIgnoreCase) >= 0;

        /// <summary>(pure) A name ending with a space or a dot, or made only of spaces and dots: Explorer hides the difference.</summary>
        internal static bool EdgeName(string name) => !string.IsNullOrEmpty(name) && (name.EndsWith(" ") || name.EndsWith(".") || name.StartsWith(" "));

        /// <summary>
        /// (pure) A path for the log: invisible characters as &lt;U+XXXX&gt; (Rules.Fix), and spaces at the start or end of a name and dots
        /// at its end as &lt;U+0020&gt; / &lt;U+002E&gt;, so a folder named " " or "x." can be seen.
        /// </summary>
        internal static string Shown(string path)
        {
            if (string.IsNullOrEmpty(path)) return path;
            var parts = path.Split('\\');
            for (int i = 0; i < parts.Length; i++)
            {
                var p = parts[i];
                if (p.Length == 0 || (i == 0 && Regex.IsMatch(p, @"^[A-Za-z]:$"))) continue;
                int lead = 0; while (lead < p.Length && p[lead] == ' ') lead++;
                int trail = p.Length; while (trail > lead && (p[trail - 1] == ' ' || p[trail - 1] == '.')) trail--;
                if (lead == 0 && trail == p.Length) continue;
                var sb = new StringBuilder();
                for (int k = 0; k < lead; k++) sb.Append("<U+0020>");
                sb.Append(p.Substring(lead, trail - lead));
                for (int k = trail; k < p.Length; k++) sb.Append(p[k] == ' ' ? "<U+0020>" : "<U+002E>");
                parts[i] = sb.ToString();
            }
            return Rules.Fix(string.Join("\\", parts));
        }

        /// <summary>(pure) The attributes in words: "hidden, system, read-only, archive", or "normal".</summary>
        internal static string AttrText(FileAttributes a)
        {
            var w = new List<string>();
            if ((a & FileAttributes.Hidden) != 0) w.Add("hidden");
            if ((a & FileAttributes.System) != 0) w.Add("system");
            if ((a & FileAttributes.ReadOnly) != 0) w.Add("read-only");
            if ((a & FileAttributes.Directory) != 0) w.Add("folder");
            if ((a & FileAttributes.Archive) != 0) w.Add("archive");
            if ((a & FileAttributes.ReparsePoint) != 0) w.Add("reparse point");
            if ((a & FileAttributes.Temporary) != 0) w.Add("temporary");
            if ((a & FileAttributes.Compressed) != 0) w.Add("compressed");
            if ((a & FileAttributes.Encrypted) != 0) w.Add("encrypted");
            if ((a & FileAttributes.Offline) != 0) w.Add("offline");
            if ((a & FileAttributes.SparseFile) != 0) w.Add("sparse");
            if ((a & FileAttributes.NotContentIndexed) != 0) w.Add("not indexed");
            if ((a & (FileAttributes)0x40000) != 0) w.Add("recall on open");
            if ((a & (FileAttributes)0x400000) != 0) w.Add("recall on data access");
            return w.Count > 0 ? "attributes " + string.Join(", ", w) : "attributes normal";
        }

        /// <summary>(pure) A folder named like "x.{GUID}": Explorer opens the shell object of that CLSID instead of the folder.</summary>
        internal static bool ClsidName(string name) => Regex.IsMatch(name ?? "", @"\.\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}\s*$", Util.RX);

        /// <summary>(pure) "CLSID={...}" (or CLSID2, UICLSID) set in a desktop.ini, or null.</summary>
        internal static string DesktopIniClsid(string text)
        {
            var m = Regex.Match(text ?? "", @"^\s*(CLSID2?|UICLSID)\s*=\s*(\{[0-9a-f-]{36}\})", RegexOptions.Multiline | Util.RX);
            return m.Success ? m.Groups[1].Value + "=" + m.Groups[2].Value : null;
        }

        /// <summary>Streams that browsers, Windows and sync tools write: not !ads.</summary>
        static readonly Regex NormalStream = new Regex(@"^(Zone\.Identifier|SmartScreen|com\.dropbox\.attrs?|com\.dropbox\.attributes|ms-properties|OECustomProperty|encryptable|favicon|AFP_AfpInfo|AFP_Resource|Win32App_1|shield|\{4c8cc155-6c1e-11d1-8e41-00c04fb9386d\})$", Util.RX);

        /// <summary>(pure) The streams that are not ones Windows, browsers or sync tools write.</summary>
        internal static List<string> UnusualStreams(IEnumerable<string> names) => (names ?? Enumerable.Empty<string>()).Where(n => !NormalStream.IsMatch(n ?? "")).ToList();

        // ---------------------------------------------------------------- autorun.inf

        /// <summary>A small text file (autorun.inf, desktop.ini, .url), up to 64 KB; names with a space or dot at the end work too.</summary>
        static string ReadIni(string path)
        {
            byte[] b;
            using (var fs = new FileStream(@"\\?\" + path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            {
                b = new byte[Math.Min(fs.Length, 64 * 1024)];
                int r = 0, k;
                while (r < b.Length && (k = fs.Read(b, r, b.Length - r)) > 0) r += k;
                if (r < b.Length) Array.Resize(ref b, r);
            }
            return DecodeText(b);
        }

        /// <summary>
        /// (pure) Text of an .ini-style file: UTF-16 (with or without BOM), UTF-8, else the PC's ANSI code page. Worms write autorun.inf in
        /// ANSI, so a no-break space (0xA0) in a folder name must not become U+FFFD.
        /// </summary>
        internal static string DecodeText(byte[] b)
        {
            if (b == null || b.Length == 0) return "";
            if ((b.Length >= 2 && b[0] == 0xFF && b[1] == 0xFE) || (b.Length >= 4 && b[1] == 0 && b[3] == 0)) return Encoding.Unicode.GetString(b).TrimStart('\uFEFF');
            try { return new UTF8Encoding(false, true).GetString(b).TrimStart('\uFEFF'); }
            catch (DecoderFallbackException) { return Encoding.Default.GetString(b); }
        }

        /// <summary>(pure) The entries of an .inf file: (section, key, value), in order; keys without a section get "".</summary>
        internal static List<(string Section, string Key, string Value)> ParseInf(string text)
        {
            var res = new List<(string, string, string)>();
            string sec = "";
            foreach (var raw in Regex.Split(text ?? "", "\r?\n"))
            {
                // only ASCII blanks are trimmed: string.Trim() would remove a no-break space, which can be a worm's whole folder name
                var line = raw.Trim(Blanks);
                if (line.Length == 0 || line.StartsWith(";")) continue;
                if (line.StartsWith("[") && line.Contains("]")) { sec = line.Substring(1, line.IndexOf(']') - 1).Trim(Blanks); continue; }
                int i = line.IndexOf('=');
                if (i <= 0) { res.Add((sec, line, "")); continue; }
                res.Add((sec, line.Substring(0, i).Trim(Blanks), Regex.Replace(line.Substring(i + 1), @"[\x00-\x1F\x7F]", "").Trim(Blanks)));
            }
            return res;
        }

        static readonly char[] Blanks = { ' ', '\t', '\r', '\n' };

        /// <summary>
        /// (pure) The file an autorun.inf command starts: the quoted part, else up to the first program extension, else the first word.
        /// Relative paths are relative to the drive root. Leading no-break spaces stay (they are part of the worm's folder name).
        /// </summary>
        internal static string AutorunFile(string root, string cmd)
        {
            var s = Environment.ExpandEnvironmentVariables(cmd ?? "").Trim(Blanks);
            if (s.Length == 0) return null;
            string p;
            if (s[0] == '"') { int e = s.IndexOf('"', 1); p = e > 0 ? s.Substring(1, e - 1) : s.Trim('"'); }
            else
            {
                var m = Regex.Match(s, @"^(.*?\.(exe|com|scr|pif|bat|cmd|vbs|vbe|js|jse|wsf|hta|ps1|dll|cpl|lnk|ico))(?=[ \t,]|$)", Util.RX);
                p = m.Success ? m.Groups[1].Value : s.Split(' ')[0];
            }
            if (p.Length == 0) return null;
            if (!Rules.DrivePath.IsMatch(p) && !p.StartsWith("\\\\")) p = root.TrimEnd('\\') + "\\" + p.TrimStart('\\');
            return p;
        }

        /// <summary>(pure) The commands an autorun.inf starts: open, shellexecute and shell\verb\command in [autorun] (any [autorun.*] variant).</summary>
        internal static List<(string Key, string Command)> AutorunCommands(IEnumerable<(string Section, string Key, string Value)> inf) =>
            inf.Where(e => e.Section.StartsWith("autorun", StringComparison.OrdinalIgnoreCase) && e.Value.Length > 0 &&
                           Regex.IsMatch(e.Key, @"^(open|shellexecute|shell\\[^\\]+\\command)$", Util.RX))
               .Select(e => (e.Key, e.Value)).ToList();

        void Autorun(List<(Drive D, Item I)> autoruns)
        {
            c.Out.Sub("autorun.inf", "On the root of a drive. Windows runs \"open\" only from CDs/DVDs now, but worms still write it and add Explorer menu entries (shell\\...\\command).\n" +
                                     "A folder named autorun.inf is a \"vaccine\" that stops worms from writing the file.");
            var t = new Table("*file", "!status", "=what", "<flags");
            foreach (var (d, it) in autoruns)
            {
                if (it.Dir) { t.Add(Shown(it.Path) + "\\", null, "folder (autorun vaccine), " + AttrText(it.Attr)); continue; }
                string text = null;
                try { text = ReadIni(it.Path); } catch (Exception e) { c.Err.Add("autorun.inf on " + d.Letter + ": " + e.Message); }
                var inf = ParseInf(text);
                var cmds = AutorunCommands(inf);
                var starts = string.Join(", ", cmds.Select(x => Rules.Fix(x.Command)).Distinct(Util.IC));
                var fl = new List<string>();
                if (cmds.Count > 0) fl.Add(AutorunFlag);
                t.Add(Shown(it.Path), Status(it.Path), AttrText(it.Attr) + (cmds.Count > 0 ? "; starts " + starts : ""), Rules.FlagCol(fl));
                // "inf: [autorun] open=x.exe": the file as written (keys like shell\open\command cannot be sub-line keys);
                // "target:" the files it starts, "icon file:" its icon: hashed, and found by log parsers like other targets
                foreach (var e in inf) t.More("inf", (e.Section.Length > 0 ? "[" + e.Section + "] " : "") + e.Key + (e.Value.Length > 0 ? "=" + Rules.Fix(e.Value) : ""));
                var files = new HashSet<string>(Util.IC);
                foreach (var e in inf.Where(e => e.Section.StartsWith("autorun", StringComparison.OrdinalIgnoreCase) && e.Value.Length > 0 &&
                                                 Regex.IsMatch(e.Key, @"^(open|shellexecute|shell\\[^\\]+\\command|icon)$", Util.RX)))
                {
                    bool icon = e.Key.Equals("icon", StringComparison.OrdinalIgnoreCase);
                    var f = AutorunFile(d.Root, icon ? Regex.Replace(e.Value, @",\s*-?\d+$", "") : e.Value);
                    if (f != null && files.Add((icon ? "i|" : "t|") + f)) t.More(icon ? "icon file" : "target", FileValue(f));
                }
                if (fl.Count > 0) c.Find(it.Modified, Log.Item(Shown(it.Path), null, "starts " + starts, Rules.FlagCol(fl)), "file modified");
            }
            t.WriteTo(c.Out, "no autorun.inf on any drive");
        }

        // ---------------------------------------------------------------- shortcuts

        /// <summary>Programs a USB worm's shortcut starts to run its hidden copy.</summary>
        static readonly Regex WormHost = new Regex(@"(^|\\)(cmd|wscript|cscript|powershell|pwsh|mshta|rundll32|regsvr32|conhost|explorer|forfiles|msiexec|javaw?)\.exe$", Util.RX);

        /// <summary>
        /// (pure) The kind of icon a shortcut shows when it is a folder, document or drive icon of Windows (shell32.dll / imageres.dll
        /// indices), or the icon of a document or picture file; null otherwise (the target's own icon, a program's icon, ...).
        /// </summary>
        internal static string IconKind(string iconLocation, int index)
        {
            if (string.IsNullOrWhiteSpace(iconLocation)) return null;
            var leaf = iconLocation.Trim().Trim('"');
            leaf = leaf.Substring(leaf.LastIndexOf('\\') + 1).ToLowerInvariant();
            if (leaf == "shell32.dll")
            {
                switch (index)
                {
                    case 0: case 1: case 70: case 151: case 152: return "document icon";
                    case 3: case 4: case 126: case 127: case 158: case 205: case 206: return "folder icon";
                    case 5: case 6: case 7: case 8: case 11: case 12: case 79: case 194: return "drive icon";
                }
                return null;
            }
            if (leaf == "imageres.dll")
            {
                switch (index)
                {
                    case 2: case 97: case 102: return "document icon";
                    case 3: case 4: case 5: case 6: case 184: case 186: return "folder icon";
                    case 25: case 26: case 27: case 28: case 29: case 30: case 31: case 32: case 33: return "drive icon";
                }
                return null;
            }
            var m = Regex.Match(leaf, @"\.(docx?|xlsx?|pptx?|pdf|txt|rtf|odt|jpe?g|png|gif|bmp|mp3|mp4|avi|zip|rar)$", Util.RX);
            return m.Success ? "icon of a ." + m.Groups[1].Value.ToLowerInvariant() + " file" : null;
        }

        /// <summary>(pure) A file a shortcut can start as a program or script (not a document or folder).</summary>
        internal static bool Runnable(string target) =>
            !string.IsNullOrEmpty(target) && (Files.Exec.IsMatch(target) || Files.Script.IsMatch(target) || Rules.Lol.IsMatch(target) || WormHost.IsMatch(target));

        /// <summary>
        /// (pure) Why a shortcut on a drive looks like a USB worm's: it starts a script host / cmd / rundll32 ..., its target or arguments
        /// point into a hidden folder of the drive, it has no normal target (only an item list or a relative path), or it is named like
        /// the drive's label or a hidden folder. Empty: none.
        /// </summary>
        internal static List<string> WormSigns(string lnkName, Lnk l, string label, ICollection<string> hiddenNames)
        {
            var s = new List<string>();
            if (l == null) return s;
            var target = l.Target ?? "";
            if (WormHost.IsMatch(target)) s.Add("starts " + target.Substring(target.LastIndexOf('\\') + 1));
            var both = target + " " + (l.Args ?? "");
            var hidden = (hiddenNames ?? new string[0]).Where(h => !string.IsNullOrEmpty(h) && !WindowsHiddenSystem.IsMatch(h) && !h.Equals("autorun.inf", StringComparison.OrdinalIgnoreCase)
                                                                   && Regex.IsMatch(both, @"(^|[\\""\s])" + Regex.Escape(h) + @"([\\""\s]|$)", Util.RX)).ToList();
            if (hidden.Count > 0) s.Add("points into hidden " + string.Join(", ", hidden.Select(Shown)));
            if (l.TargetFrom == null || l.TargetFrom == "item list" || l.TargetFrom == "relative path")
                s.Add(l.TargetFrom == null ? "no target" : "target only as " + l.TargetFrom + " (no link info)");
            var stem = Path.GetFileNameWithoutExtension(lnkName ?? "");
            if (!string.IsNullOrEmpty(label) && stem.Trim().Equals(label.Trim(), StringComparison.OrdinalIgnoreCase)) s.Add("named like the drive label");
            else if ((hiddenNames ?? new string[0]).Any(h => !string.IsNullOrEmpty(h) && stem.Equals(h, StringComparison.OrdinalIgnoreCase))) s.Add("named like a hidden folder");
            // a relative target or a target that only names something on a drive is a sign only together with a runnable target
            if (s.Count == 1 && s[0].StartsWith("target only") && !Runnable(target) && !Runnable(l.Args ?? "")) s.Clear();
            return s;
        }

        /// <summary>
        /// (pure but for `exists`) The existing files a shortcut's arguments name: quoted parts and words with a file extension, full paths
        /// or relative to the working folder, the shortcut's folder or the drive root. Worms start their hidden copy with a relative path
        /// ("cmd /c start "" "&lt;U+00A0&gt;\x.exe""), so the copy is found and hashed. Leading no-break spaces stay part of the name.
        /// </summary>
        internal static List<string> ArgumentFiles(string args, string lnkFolder, string workDir, string driveRoot, Func<string, bool> exists)
        {
            var res = new List<string>();
            if (string.IsNullOrEmpty(args)) return res;
            foreach (var raw in ArgWords(args))
            {
                var c = Environment.ExpandEnvironmentVariables(raw.Trim(Blanks)).TrimEnd(',', ';');
                if (!Regex.IsMatch(c, @"\.[A-Za-z0-9]{1,5}$") || c.StartsWith("/") || c.Contains("://")) continue;
                var tries = Rules.DrivePath.IsMatch(c) ? new[] { c }
                    : new[] { workDir, lnkFolder, driveRoot }.Where(b => !string.IsNullOrEmpty(b) && Rules.DrivePath.IsMatch(b.TrimEnd('\\') + "\\"))
                                                       .Select(b => b.TrimEnd('\\') + "\\" + (c.StartsWith(@".\") ? c.Substring(2) : c.TrimStart('\\'))).ToArray();
                var hit = tries.FirstOrDefault(exists);
                if (hit != null && !res.Contains(hit, StringComparer.OrdinalIgnoreCase)) res.Add(hit);
            }
            return res;
        }

        /// <summary>
        /// (pure) The words of a command line: a quoted part is one word (quotes removed, its blanks kept), else words end at ASCII blanks
        /// and at &amp; | &lt; &gt; ( ) , ; (a no-break space is part of a name, not a separator).
        /// </summary>
        internal static List<string> ArgWords(string args)
        {
            var res = new List<string>();
            var cur = new StringBuilder();
            bool quoted = false, any = false;
            void End() { if (any && cur.Length > 0) res.Add(cur.ToString()); cur.Clear(); any = false; }
            foreach (var ch in args ?? "")
            {
                if (ch == '"') { End(); quoted = !quoted; any = true; continue; }
                if (!quoted && (ch == ' ' || ch == '\t' || "&|<>(),;".IndexOf(ch) >= 0)) { End(); continue; }
                cur.Append(ch); any = true;
            }
            End();
            return res;
        }

        static string ShowText(int cmd) => cmd == 3 ? "maximized" : cmd == 7 ? "minimized" : cmd == 2 ? "minimized" : null;

        void Shortcuts(List<(Drive D, Item I)> shortcuts)
        {
            c.Out.Sub("Shortcuts on the drives", "target => [status], arguments, icon (path,index; a folder/document/drive icon on a program is a disguise), working folder, window,\n" +
                                                 "description, made on = the PC the shortcut was made on, volume = the target's drive when the shortcut was made, target from = where the target was read");
            var t = new Table("*shortcut", ">target", "!status", "args", "icon", "workdir", "window", "description", "made on", "volume", "target from", "<flags");
            foreach (var (d, it) in shortcuts)
            {
                var fl = new List<string>(UsbFlags(it.Path));
                if (it.Name.EndsWith(".url", StringComparison.OrdinalIgnoreCase))
                {
                    UrlFile u = null;
                    try { u = UrlFile.Parse(ReadIni(it.Path)); } catch { }
                    if (u == null) continue;
                    var kindU = IconKind(u.IconFile, u.IconIndex);
                    var fileTarget = Regex.Match(u.Url ?? "", @"^file:/+([a-z]:[\\/].*)$", Util.RX);
                    var tgt = fileTarget.Success ? Uri.UnescapeDataString(fileTarget.Groups[1].Value).Replace('/', '\\') : u.Url;
                    if (kindU != null && Runnable(tgt)) fl.Add(IconFlag);
                    t.Add(Shown(it.Path), Rules.Fix(tgt), fileTarget.Success ? Status(tgt) : null, null,
                          u.IconFile != null ? Rules.Fix(u.IconFile) + "," + u.IconIndex + (kindU != null ? " (" + kindU + ")" : "") : null,
                          null, null, null, null, null, "url file", Rules.FlagCol(fl));
                    Report(it, fl, tgt);
                    continue;
                }
                Lnk l = null;
                try { l = Lnk.Parse(c.ReadLocked(@"\\?\" + it.Path)); } catch { }
                if (l == null) { t.Add(Shown(it.Path), null, "not a valid shortcut file"); continue; }
                var kind = IconKind(Environment.ExpandEnvironmentVariables(l.EnvIcon ?? l.IconLocation ?? ""), l.IconIndex);
                bool onDrive = d.Deep || it.Depth == 0;
                hiddenByDrive.TryGetValue(d.Letter, out var hidden);
                var signs = onDrive ? WormSigns(it.Name, l, d.Label, hidden) : new List<string>();
                if (signs.Count > 0) fl.Add(WormFlag);
                if (kind != null && (Runnable(l.Target) || WormHost.IsMatch(l.Target ?? ""))) fl.Add(IconFlag);
                string status = null;
                if (!string.IsNullOrEmpty(l.Target))
                {
                    var exp = Environment.ExpandEnvironmentVariables(l.Target);
                    if (Rules.DrivePath.IsMatch(exp)) status = Status(exp);
                }
                t.Add(Shown(it.Path), l.Target != null ? Rules.Fix(l.Target) : null, status, l.Args != null ? Rules.Fix(l.Args) : null,
                      l.Icon != null ? Rules.Fix(l.Icon) + (kind != null ? " (" + kind + ")" : "") : null, l.WorkDir != null ? Rules.Fix(l.WorkDir) : null,
                      ShowText(l.ShowCmd), l.Description != null ? Rules.Fix(l.Description) : null, l.Machine,
                      l.VolumeSerial != null ? "serial " + l.VolumeSerial + (l.VolumeLabel != null ? " label " + Rules.Fix(l.VolumeLabel) : "") + (l.Where != null ? " " + l.Where : "") : null,
                      l.TargetFrom, Rules.FlagCol(fl));
                if (signs.Count > 0) t.More("worm signs", string.Join("; ", signs));
                if (l.EnvTarget != null && !l.EnvTarget.Equals(l.Target, StringComparison.OrdinalIgnoreCase)) t.More("target with variables", Rules.Fix(l.EnvTarget));
                if (l.IdListTarget != null && !l.IdListTarget.Equals(l.Target, StringComparison.OrdinalIgnoreCase)) t.More("item list target", Rules.Fix(l.IdListTarget));
                if (l.RelPath != null) t.More("relative path", Rules.Fix(l.RelPath));
                // files the arguments name (the worm's hidden copy, often a path relative to the drive): hashed for FILES
                foreach (var f in ArgumentFiles(l.Args, Util.Folder(it.Path), l.WorkDir, d.Root, p => { try { return new FileInfo(@"\\?\" + p).Exists; } catch { return false; } }))
                    t.More("argument file", FileValue(f));
                // no target of its own (the worm's "no target" sign): what its shell items name, else its relative path
                Report(it, fl, l.Target ?? (l.IdListTarget != null ? "item list target " + l.IdListTarget : l.RelPath != null ? "relative path " + l.RelPath : null));
            }
            t.WriteTo(c.Out, "no shortcuts on the drives");
        }

        void Report(Item it, List<string> fl, string target)
        {
            var strong = Rules.Strong(fl).Where(f => !UsbFlags(it.Path).Contains(f)).ToList();
            if (strong.Count == 0) return;
            c.Find(it.Created, Log.Item(Shown(it.Path), null, Rules.Fix(target ?? "no target"), Rules.FlagCol(strong)), "created");
        }

        // ---------------------------------------------------------------- Explorer settings, MountPoints2

        static string Val(RegistryKey k, string name) { try { return Convert.ToString(k?.GetValue(name)); } catch { return null; } }
        static int? Int(RegistryKey k, string name) { try { var v = k?.GetValue(name); return v == null ? (int?)null : Convert.ToInt32(v); } catch { return null; } }

        void Settings()
        {
            c.Out.Sub("Explorer settings", "Worms hide their copies with the hidden and system attributes and switch Explorer to not show them.\n" +
                                           "hidden files 1 = shown, 2 = not shown (default); file extensions 1 = hidden (default); protected system files 1 = shown");
            var t = new Table("*where", "=setting", "<flags");
            foreach (var h in c.Hives)
                try
                {
                    using (var k = h.Root.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"))
                        if (k != null)
                            t.Add("[" + h.User + "] Explorer\\Advanced", $"hidden files {Int(k, "Hidden")?.ToString() ?? "-"}, file extensions hidden {Int(k, "HideFileExt")?.ToString() ?? "-"}, " +
                                                                        $"protected system files shown {Int(k, "ShowSuperHidden")?.ToString() ?? "-"}");
                    Policies(t, h.Root, "[" + h.User + "] HKCU");
                }
                catch (Exception e) { c.Err.Add("Explorer settings of " + h.User + ": " + e.Message); }
            try { Policies(t, Registry.LocalMachine, "HKLM"); }
            catch (Exception e) { c.Err.Add("Explorer policies (HKLM): " + e.Message); }
            try
            {
                using (var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\Hidden\SHOWALL"))
                {
                    var v = Int(k, "CheckedValue");
                    var fl = new List<string>();
                    if (k != null && v != 1) fl.Add(ExplorerFlag);
                    t.Add(@"HKLM ...\Explorer\Advanced\Folder\Hidden\SHOWALL", "CheckedValue " + (v?.ToString() ?? "missing") + " (1 = normal; else \"Show hidden files\" does not stick)", Rules.FlagCol(fl));
                    if (fl.Count > 0) c.Find(Native.LastWrite(k), Log.Item(@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\Hidden\SHOWALL", null,
                                                               "CheckedValue " + (v?.ToString() ?? "missing") + ": hidden files cannot be shown", Rules.FlagCol(fl)), "key changed");
                }
            }
            catch (Exception e) { c.Err.Add("SHOWALL: " + e.Message); }
            t.WriteTo(c.Out);
            MountPoints();
        }

        void Policies(Table t, RegistryKey root, string where)
        {
            using (var k = root.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"))
            {
                if (k == null) return;
                var parts = new List<string>();
                var nd = Int(k, "NoDriveTypeAutoRun");
                if (nd.HasValue) parts.Add($"NoDriveTypeAutoRun 0x{nd.Value:X} (" + ((nd.Value & 0x04) != 0 ? "AutoRun off for removable drives" : "AutoRun ON for removable drives") + ")");
                var na = Int(k, "NoAutorun"); if (na.HasValue) parts.Add("NoAutorun " + na);
                var nf = Int(k, "NoFolderOptions"); if (nf.HasValue) parts.Add("NoFolderOptions " + nf);
                var hn = Int(k, "HonorAutorunSetting"); if (hn.HasValue) parts.Add("HonorAutorunSetting " + hn);
                if (parts.Count == 0) return;
                var fl = new List<string>();
                if (nf == 1) fl.Add(ExplorerFlag);
                t.Add(where + @" Policies\Explorer", string.Join(", ", parts), Rules.FlagCol(fl));
                if (fl.Count > 0) c.Find(Native.LastWrite(k), Log.Item(where + @" Policies\Explorer", null, "NoFolderOptions 1: Folder Options are blocked", Rules.FlagCol(fl)), "key changed");
            }
        }

        /// <summary>SYSTEM\MountedDevices: volume GUID or drive letter -> device ("USBSTOR#Disk&amp;Ven_...#serial&amp;0#...") for USB volumes.</summary>
        Dictionary<string, string> mounted;
        /// <summary>SYSTEM\MountedDevices values of fixed disks (a USB hard disk): name -> disk key (DiskKey: "mbr:..." / "gpt:...").</summary>
        readonly Dictionary<string, string> mountedKeys = new Dictionary<string, string>(Util.IC);
        Dictionary<string, string> Mounted()
        {
            if (mounted != null) return mounted;
            mounted = new Dictionary<string, string>(Util.IC);
            try
            {
                using (var k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\MountedDevices"))
                    if (k != null)
                        foreach (var n in k.GetValueNames())
                        {
                            if (!(k.GetValue(n) is byte[] b)) continue;
                            // a fixed disk's volume: MBR disk signature + offset, or a GPT partition GUID (before the text form: a
                            // signature's second byte can be 0)
                            var key = MountedKey(b);
                            if (key != null) { mountedKeys[n] = key; continue; }
                            if (b.Length > 8 && b[1] == 0)
                            {
                                var s = Encoding.Unicode.GetString(b).TrimEnd('\0');
                                if (s.StartsWith(@"_??_") || s.StartsWith(@"\??\")) mounted[n] = s.Substring(4);
                            }
                        }
            }
            catch (Exception e) { c.Err.Add("MountedDevices: " + e.Message); }
            return mounted;
        }

        /// <summary>
        /// (pure) The disk key of a MountedDevices value of a fixed disk's volume: 12 bytes = MBR disk signature (4 bytes as on disk) and
        /// the partition's offset -> "mbr:&lt;8 hex digits&gt;"; "DMIO:ID:" and 16 bytes = the GPT partition GUID -> "gpt:&lt;32 hex digits&gt;".
        /// Null for other values (a removable drive's device path, ...).
        /// </summary>
        internal static string MountedKey(byte[] b)
        {
            if (b == null) return null;
            if (b.Length == 12) return NonZero(b, 0, 4) ? "mbr:" + HexOf(b, 0, 4) : null;
            if (b.Length == 24 && Encoding.ASCII.GetString(b, 0, 8) == "DMIO:ID:") return NonZero(b, 8, 16) ? "gpt:" + HexOf(b, 8, 16) : null;
            return null;
        }

        static bool NonZero(byte[] b, int start, int count)
        {
            for (int i = start; i < start + count && i < b.Length; i++) if (b[i] != 0) return true;
            return false;
        }

        static string HexOf(byte[] b, int start, int count)
        {
            var sb = new StringBuilder(count * 2);
            for (int i = start; i < start + count; i++) sb.Append(b[i].ToString("X2"));
            return sb.ToString();
        }

        /// <summary>
        /// (pure) The disk keys of a disk from a Partition/Diagnostic 1006 event: its PartitionTable (DRIVE_LAYOUT_INFORMATION_EX: style,
        /// count, MBR signature at offset 8; 48-byte header, then 144 bytes per partition with the GPT partition GUID at +48) and its Mbr
        /// (512 bytes, the signature at offset 440). Keys as MountedKey writes them.
        /// </summary>
        internal static List<string> DiskKeys(byte[] table, byte[] mbr)
        {
            var res = new List<string>();
            int style = table != null && table.Length >= 48 ? BitConverter.ToInt32(table, 0) : -1;
            if (style == 0 && NonZero(table, 8, 4)) res.Add("mbr:" + HexOf(table, 8, 4));
            if (style == 1)
            {
                int count = BitConverter.ToInt32(table, 4);
                for (int p = 0; p < count && p < 256; p++)
                {
                    int o = 48 + 144 * p;
                    if (o + 64 > table.Length) break;
                    if (NonZero(table, o + 48, 16)) res.Add("gpt:" + HexOf(table, o + 48, 16));
                }
            }
            if (style != 1 && res.Count == 0 && mbr != null && mbr.Length >= 512 && mbr[510] == 0x55 && mbr[511] == 0xAA && NonZero(mbr, 440, 4))
                res.Add("mbr:" + HexOf(mbr, 440, 4));
            return res;
        }

        /// <summary>(pure) The bytes of a binary event field (byte[], or hex text), or null.</summary>
        internal static byte[] FieldBytes(object v)
        {
            if (v is byte[] b) return b;
            var s = v as string;
            if (string.IsNullOrEmpty(s) || s.Length % 2 != 0 || !Regex.IsMatch(s, "^[0-9A-Fa-f]+$")) return null;
            var res = new byte[s.Length / 2];
            for (int i = 0; i < res.Length; i++) res[i] = Convert.ToByte(s.Substring(i * 2, 2), 16);
            return res;
        }

        /// <summary>A USB disk as a Partition/Diagnostic 1006 event shows it (connected or removed).</summary>
        sealed class DiskEvent
        {
            public DateTime? Time;
            public bool Removed;
            public string Device;                                     // manufacturer and model
            public List<string> Serials = new List<string>();         // the disk's serial, and the serial of its USB parent device
            public List<string> Keys = new List<string>();            // DiskKeys
        }

        /// <summary>Events of USB disks read for drive letters and history: up to this many, newest first, any age.</summary>
        const int MaxDiskEvents = 3000;

        List<DiskEvent> disks;
        /// <summary>USB disks in the Partition/Diagnostic 1006 events, newest first, of any age (letters of disks connected long ago).</summary>
        List<DiskEvent> Disks()
        {
            if (disks != null) return disks;
            disks = new List<DiskEvent>();
            var fields = Ev.Fields("BusType", "Manufacturer", "Model", "SerialNumber", "Capacity", "ParentId", "PartitionTable", "Mbr");
            foreach (var e in Ev.Query("Microsoft-Windows-Partition/Diagnostic", "EventID=1006", new DateTime(2000, 1, 1, 0, 0, 0, DateTimeKind.Utc), MaxDiskEvents))
            {
                try
                {
                    var v = ((System.Diagnostics.Eventing.Reader.EventLogRecord)e).GetPropertyValues(fields);
                    string S(int i) => i < v.Count && v[i] != null && !(v[i] is byte[]) ? Convert.ToString(v[i]) : null;
                    var parent = S(5) ?? "";
                    if (S(0) != "7" && parent.IndexOf("USB", StringComparison.OrdinalIgnoreCase) < 0) continue;
                    var d = new DiskEvent
                    {
                        Time = e.TimeCreated?.ToUniversalTime(),
                        Removed = S(4) == "0",
                        Device = string.Join(" ", new[] { S(1), S(2) }.Where(x => !string.IsNullOrWhiteSpace(x)).Select(x => x.Trim())),
                        Keys = DiskKeys(FieldBytes(v.Count > 6 ? v[6] : null), FieldBytes(v.Count > 7 ? v[7] : null)),
                    };
                    if (!string.IsNullOrWhiteSpace(S(3))) d.Serials.Add(S(3).Trim());
                    var ps = ParentSerial(parent);
                    if (ps != null && !d.Serials.Contains(ps, StringComparer.OrdinalIgnoreCase)) d.Serials.Add(ps);
                    disks.Add(d);
                }
                catch { }
                finally { e.Dispose(); }
            }
            return disks;
        }

        /// <summary>(pure) The serial of a USB device id ("USB\VID_0BC2&amp;PID_2343\NA9LV5LQ" -> "NA9LV5LQ"); null when it has none (a "&amp;" id).</summary>
        internal static string ParentSerial(string id)
        {
            var m = Regex.Match(id ?? "", @"^USB\\[^\\]+\\([^\\&]+)$", Util.RX);
            return m.Success ? m.Groups[1].Value : null;
        }

        /// <summary>Letters of drives mounted now that are not on USB (the system drive, internal disks, network and CD drives): Drives().</summary>
        readonly HashSet<string> localLetters = new HashSet<string>(Util.IC);

        /// <summary>
        /// The newest USB disk event of a MountedDevices value of a fixed disk's volume ("\DosDevices\E:", "\??\Volume{...}"), or null.
        /// Not for a key of a drive mounted now that is not on USB: a USB backup disk cloned from an internal disk has the same MBR
        /// signature or GPT partition GUIDs.
        /// </summary>
        DiskEvent MountedDisk(string name)
        {
            Mounted();
            if (!mountedKeys.TryGetValue(name, out var key)) return null;
            if (localLetters.Any(l => mountedKeys.TryGetValue(@"\DosDevices\" + l, out var lk) && lk.Equals(key, StringComparison.OrdinalIgnoreCase))) return null;
            return Disks().FirstOrDefault(d => d.Keys.Contains(key, StringComparer.OrdinalIgnoreCase));
        }

        void MountPoints()
        {
            c.Out.Sub("MountPoints2 (volumes each user opened)", "last written = when the user's Explorer last saw the volume; a Shell\\...\\command under it runs when the drive is opened (autorun persistence).");
            var t = new Table("@last written", "*volume", "user", "device", "=shell command", "<flags");
            var m = Mounted();
            foreach (var h in c.Hives)
                try
                {
                    using (var mp = h.Root.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2"))
                    {
                        if (mp == null) continue;
                        foreach (var n in mp.GetSubKeyNames())
                            using (var k = mp.OpenSubKey(n))
                            {
                                if (k == null) continue;
                                m.TryGetValue(@"\??\Volume" + n, out var dev);
                                var cmds = new List<string>();
                                using (var sh = k.OpenSubKey("Shell"))
                                    if (sh != null)
                                        foreach (var verb in sh.GetSubKeyNames())
                                            using (var cmd = sh.OpenSubKey(verb + @"\command"))
                                            {
                                                var v = Val(cmd, "");
                                                if (!string.IsNullOrEmpty(v)) cmds.Add(verb + ": " + v);
                                            }
                                var fl = cmds.Count > 0 ? new List<string> { AutorunFlag } : new List<string>();
                                var lw = Native.LastWrite(k);
                                // all volumes with a USB device or a shell command; others (fixed disks, shares) only in the time window
                                bool usb = dev != null && dev.StartsWith("USBSTOR", StringComparison.OrdinalIgnoreCase);
                                var devName = dev != null ? UsbName(dev) : null;
                                // a volume of a USB hard disk (a fixed disk: MountedDevices has its signature, not a device path)
                                if (dev == null && MountedDisk(@"\??\Volume" + n) is DiskEvent disk)
                                {
                                    usb = true;
                                    devName = string.Join(" ", new[] { disk.Device, disk.Serials.Count > 0 ? "(serial " + disk.Serials[0] + ")" : null }
                                                                   .Where(x => !string.IsNullOrEmpty(x)));
                                    if (devName.Length == 0) devName = null;
                                }
                                if (!usb && cmds.Count == 0 && !(lw >= c.Since)) continue;
                                t.Add(Log.T(lw), n, h.User, devName, cmds.Count > 0 ? Rules.Fix(string.Join(" | ", cmds)) : null, Rules.FlagCol(fl));
                                if (cmds.Count > 0) c.Find(lw, Log.Item($"[{h.User}] MountPoints2\\{n}", null, "shell command " + Rules.Fix(string.Join(" | ", cmds)), Rules.FlagCol(fl)), "key changed");
                            }
                    }
                }
                catch (Exception e) { c.Err.Add("MountPoints2 of " + h.User + ": " + e.Message); }
            t.WriteTo(c.Out);
        }

        // ---------------------------------------------------------------- USB device history

        /// <summary>
        /// (pure) A USB storage device id for the log: "USBSTOR#Disk&amp;Ven_SanDisk&amp;Prod_Cruzer_Blade&amp;Rev_1.00#4C53...&amp;0#{...}" or
        /// "Disk&amp;Ven_SanDisk&amp;Prod_Cruzer_Blade&amp;Rev_1.00" -> "SanDisk Cruzer Blade"; the input when it has no Ven_/Prod_.
        /// </summary>
        internal static string UsbName(string id)
        {
            var m = Regex.Match(id ?? "", @"Ven_([^&#\\]*)&Prod_([^&#\\]*)", Util.RX);
            if (!m.Success) return id;
            return string.Join(" ", new[] { m.Groups[1].Value, m.Groups[2].Value }.Select(x => x.Replace('_', ' ').Trim()).Where(x => x.Length > 0));
        }

        /// <summary>
        /// (pure) A disk event's or letter's device ("ST1000LM 035-1RK172", manufacturer and model) is the USBSTOR device of this name
        /// (UsbName of its key, or its FriendlyName): one contains the other, letters and digits only, case ignored. For devices that
        /// share one serial (USB-SATA bridges).
        /// </summary>
        internal static bool SameModel(string usbName, string friendlyName, string device)
        {
            string N(string s) => Regex.Replace(s ?? "", "[^A-Za-z0-9]", "").ToLowerInvariant();
            var d = N(device);
            if (d.Length == 0) return false;
            return new[] { N(usbName), N(friendlyName) }.Any(x => x.Length > 0 && (x.Contains(d) || d.Contains(x)));
        }

        /// <summary>(pure) The device serial in a USBSTOR id ("...#4C530001231115104383&amp;0#{...}" -> "4C530001231115104383"), or null.</summary>
        internal static string UsbSerial(string id)
        {
            var m = Regex.Match(id ?? "", @"USBSTOR[#\\][^#\\]+[#\\]([^#\\]+?)(&\d+)?([#\\]|$)", Util.RX);
            return m.Success ? m.Groups[1].Value : null;
        }

        /// <summary>
        /// (pure) An EMDMgmt (ReadyBoost) key name: "_??_USBSTOR#Disk&amp;Ven_...#serial&amp;0#{53f56307-...}LABEL_123456789" ->
        /// (device id, label, volume serial as 8 hex digits). Null when it is not one.
        /// </summary>
        internal static (string Device, string Label, string Serial)? Emd(string key)
        {
            var m = Regex.Match(key ?? "", @"^(?:_\?\?_)?(USBSTOR#.*\})(.*)_(\d+)$", Util.RX);
            if (!m.Success || !uint.TryParse(m.Groups[3].Value, NumberStyles.None, CultureInfo.InvariantCulture, out var serial)) return null;
            return (m.Groups[1].Value, m.Groups[2].Value, serial.ToString("X8"));
        }

        static DateTime? PropTime(RegistryKey dev, string id)
        {
            try
            {
                using (var k = dev.OpenSubKey(@"Properties\{83da6326-97a6-4088-9453-a1923f573b29}\" + id))
                {
                    var b = Native.RawValue(k, "");
                    return b != null && b.Length >= 8 ? Util.FtTime(BitConverter.ToInt64(b, 0)) : null;
                }
            }
            catch { return null; }
        }

        /// <summary>
        /// setupapi.dev.log and the older ones Windows rotated it into (setupapi.dev.YYYYMMDD_HHMMSS.log): the first "Device Install"
        /// section of each USBSTOR device (local time in the file) -> UTC.
        /// </summary>
        Dictionary<string, DateTime> SetupApi()
        {
            var res = new Dictionary<string, DateTime>(Util.IC);
            var dir = Path.Combine(c.WinDir, "INF");
            string[] names;
            try { names = Directory.GetFiles(dir, "setupapi.dev*.log").Select(Path.GetFileName).ToArray(); }
            catch (Exception e) { c.Err.Add("setupapi.dev.log: " + e.Message); return res; }
            foreach (var name in SetupApiOrder(names))
                try
                {
                    string dev = null;
                    foreach (var line in Util.AllLines(Path.Combine(dir, name)))
                    {
                        if (!line.StartsWith(">>>")) continue;
                        var m = Regex.Match(line, @"^>>>\s+\[Device Install[^\]]*-\s*(USBSTOR\\[^\]]+)\]", Util.RX);
                        if (m.Success) { dev = m.Groups[1].Value.Trim(); continue; }
                        if (dev == null) continue;
                        var s = Regex.Match(line, @"^>>>\s+Section start (\d{4}/\d\d/\d\d \d\d:\d\d:\d\d)");
                        if (s.Success && DateTime.TryParseExact(s.Groups[1].Value, "yyyy/MM/dd HH:mm:ss", CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out var t))
                        {
                            var serial = UsbSerial(dev);
                            if (serial != null && !res.ContainsKey(serial)) res[serial] = t.ToUniversalTime();
                        }
                        dev = null;
                    }
                }
                catch (Exception e) { c.Err.Add(name + ": " + e.Message); }
            return res;
        }

        /// <summary>
        /// (pure) The setupapi.dev logs to read, oldest first: the rotated ones (setupapi.dev.YYYYMMDD_HHMMSS.log) by their time, then
        /// setupapi.dev.log. Other names (a copy someone saved, setupapi.dev.log.txt) are left out.
        /// </summary>
        internal static List<string> SetupApiOrder(IEnumerable<string> names)
        {
            var all = (names ?? Enumerable.Empty<string>()).ToList();
            var rotated = all.Where(n => Regex.IsMatch(n ?? "", @"^setupapi\.dev\.\d{8}_\d{6}\.log$", Util.RX)).OrderBy(n => n.ToLowerInvariant(), StringComparer.Ordinal).ToList();
            rotated.AddRange(all.Where(n => (n ?? "").Equals("setupapi.dev.log", StringComparison.OrdinalIgnoreCase)));
            return rotated;
        }

        void History()
        {
            // volume labels: Windows Portable Devices (FriendlyName per device) and EMDMgmt (label and volume serial)
            var labels = new Dictionary<string, string>(Util.IC);   // device serial -> label(s)
            void Label(string serial, string label)
            {
                if (string.IsNullOrEmpty(serial) || string.IsNullOrWhiteSpace(label)) return;
                label = label.Trim();
                labels[serial] = labels.TryGetValue(serial, out var o) ? (o.Split(new[] { ", " }, StringSplitOptions.None).Contains(label, StringComparer.OrdinalIgnoreCase) ? o : o + ", " + label) : label;
            }
            try
            {
                using (var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows Portable Devices\Devices"))
                    if (k != null)
                        foreach (var n in k.GetSubKeyNames())
                            using (var d = k.OpenSubKey(n)) Label(UsbSerial(n.ToUpperInvariant().Replace("##?#", "")), Val(d, "FriendlyName"));
            }
            catch (Exception e) { c.Err.Add("Windows Portable Devices: " + e.Message); }
            try
            {
                using (var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt"))
                    if (k != null)
                        foreach (var n in k.GetSubKeyNames())
                            if (Emd(n) is var e && e.HasValue)
                            {
                                Label(UsbSerial(e.Value.Device), e.Value.Label.Length > 0 ? e.Value.Label : null);
                                if (!c.UsbVolumes.ContainsKey(e.Value.Serial)) c.UsbVolumes[e.Value.Serial] = e.Value.Label;
                            }
            }
            catch (Exception e) { c.Err.Add("EMDMgmt: " + e.Message); }

            var setup = SetupApi();
            // drive letters (the last letter each volume had): a removable drive's MountedDevices value names its USBSTOR device; a USB hard
            // disk's holds its MBR signature or GPT partition GUID, found in the Partition/Diagnostic events of the disk
            var letterOf = new List<(string Serial, string Letter, string Device)>();
            foreach (var kv in Mounted())
                if (kv.Key.StartsWith(@"\DosDevices\", StringComparison.OrdinalIgnoreCase) && kv.Value.StartsWith("USBSTOR", StringComparison.OrdinalIgnoreCase))
                    letterOf.Add((UsbSerial(kv.Value) ?? "", kv.Key.Substring(12), UsbName(kv.Value)));
            foreach (var name in mountedKeys.Keys.ToList())
                if (name.StartsWith(@"\DosDevices\", StringComparison.OrdinalIgnoreCase) && MountedDisk(name) is DiskEvent disk)
                    foreach (var s in disk.Serials) letterOf.Add((s, name.Substring(12), disk.Device));

            c.Out.Sub("USB storage devices (USBSTOR)", "last connected / removed: from the device's properties (needs SYSTEM rights), else the newest Partition/Diagnostic 1006 event of\n" +
                                                       "the device (any age the event log keeps), else the key time (usually the last connect);\n" +
                                                       "first installed: setupapi.dev logs or the device's properties. label: volume names seen by Windows Portable Devices and ReadyBoost.\n" +
                                                       "letter: the last drive letter (MountedDevices; a USB hard disk's through its disk signature in the 1006 events).");
            var t = new Table("@last connected", "*device", "serial", "first installed", "last removed", "label", "letter", "key written");
            try
            {
                using (var us = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum\USBSTOR"))
                    if (us != null)
                    {
                        var rows = new List<(DateTime? Last, string[] F)>();
                        // cheap USB-SATA bridges give many disks one serial: then a disk event or letter belongs to the device of its model
                        var bySerial = us.GetSubKeyNames().SelectMany(dn => { using (var dk = us.OpenSubKey(dn)) return dk?.GetSubKeyNames() ?? new string[0]; })
                                         .GroupBy(sn => Regex.Replace(sn, @"&\d+$", ""), Util.IC).ToDictionary(g => g.Key, g => g.Count(), Util.IC);
                        foreach (var dn in us.GetSubKeyNames())
                            using (var dk = us.OpenSubKey(dn))
                                foreach (var sn in dk?.GetSubKeyNames() ?? new string[0])
                                    using (var sk = dk.OpenSubKey(sn))
                                    {
                                        var serial = Regex.Replace(sn, @"&\d+$", "");
                                        var name = Val(sk, "FriendlyName");
                                        bool shared = bySerial.TryGetValue(serial, out var nSerial) && nSerial > 1;
                                        bool Mine(string device) => !shared || SameModel(UsbName(dn), name, device);
                                        var mine = Disks().Where(d => d.Serials.Contains(serial, StringComparer.OrdinalIgnoreCase) && Mine(d.Device)).ToList();
                                        var first = PropTime(sk, "0064") ?? (setup.TryGetValue(serial, out var su) ? su : (DateTime?)null);
                                        var propArrival = PropTime(sk, "0066");
                                        var propRemoval = PropTime(sk, "0067");
                                        // without SYSTEM rights: the newest connect and removal in the Partition/Diagnostic events (Disks: newest first)
                                        var arrival = propArrival ?? mine.FirstOrDefault(d => !d.Removed)?.Time;
                                        var removal = propRemoval ?? mine.FirstOrDefault(d => d.Removed)?.Time;
                                        var kw = Native.LastWrite(sk);
                                        var last = arrival ?? kw;
                                        labels.TryGetValue(serial, out var lab);
                                        var lets = letterOf.Where(x => x.Serial.Equals(serial, StringComparison.OrdinalIgnoreCase) && Mine(x.Device))
                                                           .Select(x => x.Letter).Distinct(Util.IC).OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToList();
                                        var let = lets.Count > 0 ? string.Join(", ", lets) : null;
                                        // a drive letter this device has now: timeline lines of that letter after this connect are on it
                                        if (let != null && last.HasValue)
                                            foreach (var l in let.Split(new[] { ", " }, StringSplitOptions.RemoveEmptyEntries))
                                                if (c.UsbLetters.TryGetValue(l, out var cur) && (cur.Since == null || last > cur.Since))
                                                    c.UsbLetters[l] = (cur.Label, last);
                                        rows.Add((last, new[] { Log.T(last), string.IsNullOrEmpty(name) ? UsbName(dn) : name + " (" + UsbName(dn) + ")", serial, Log.T(first),
                                                               Log.T(removal), lab != null ? Rules.Fix(lab) : null, let, arrival.HasValue ? Log.T(kw) : null }));
                                        if (first >= c.Since) c.Event(first, "USB", null, text: $"USB storage device first installed: {name ?? UsbName(dn)} (serial {serial})" + (lab != null ? ", label " + Rules.Fix(lab) : ""));
                                        // times from the events are in the timeline already (Connects), within the time window
                                        if (propArrival.HasValue) c.Event(propArrival, "USB", null, text: $"USB storage device last connected: {name ?? UsbName(dn)} (serial {serial})");
                                        if (propRemoval.HasValue) c.Event(propRemoval, "USB", null, text: $"USB storage device last removed: {name ?? UsbName(dn)} (serial {serial})");
                                    }
                        foreach (var r in rows.OrderByDescending(r => r.Last ?? DateTime.MinValue)) t.Add(r.F);
                    }
            }
            catch (Exception e) { c.Err.Add("USBSTOR: " + e.Message); }
            t.WriteTo(c.Out, "no USB storage device was ever connected (or the key cannot be read)");
            Connects();
        }

        /// <summary>
        /// USB storage connects and removals in the time window: Partition/Diagnostic 1006 (Windows 10 1903+; with vendor, model, serial,
        /// size; size 0 = removed), else Kernel-PnP 410 (a USBSTOR device started).
        /// </summary>
        void Connects()
        {
            c.Out.Sub($"USB storage connects in the last {c.Opt.Days} days", "Partition/Diagnostic event 1006 (size 0 = removed), else Kernel-PnP 410 (device started). Also in the timeline (USB).");
            var t = new Table("@time", "[event", "*device", "=details");
            var err = new List<string>();
            var ev = Ev.Query("Microsoft-Windows-Partition/Diagnostic", "EventID=1006", c.Since, 1000, err);
            var fields = Ev.Fields("BusType", "Manufacturer", "Model", "SerialNumber", "Capacity", "ParentId");
            int n = 0;
            ev.Reverse();
            foreach (var e in ev)
            {
                var v = Ev.Values(e, fields, 6);
                if (v[0] != "7" && (v[5] ?? "").IndexOf("USB", StringComparison.OrdinalIgnoreCase) < 0) { e.Dispose(); continue; }
                var time = e.TimeCreated?.ToUniversalTime();
                bool removed = v[4] == "0";
                var dev = string.Join(" ", new[] { v[1], v[2] }.Where(x => !string.IsNullOrWhiteSpace(x)).Select(x => x.Trim()));
                var size = long.TryParse(v[4], out var cap) && cap > 0 ? cap + " bytes" : null;
                t.Add(Log.T(time), "1006", dev, string.Join("; ", new[] { removed ? "removed" : "connected", v[3] != null ? "serial " + v[3].Trim() : null, size }.Where(x => x != null)));
                c.Event(time, "USB", null, text: $"USB drive {(removed ? "removed" : "connected")}: {dev}" + (v[3] != null ? $" (serial {v[3].Trim()})" : ""));
                n++;
                e.Dispose();
            }
            if (n == 0)
            {
                var pnp = Ev.Query("Microsoft-Windows-Kernel-PnP/Configuration", "EventID=410", c.Since, 2000, err);
                pnp.Reverse();
                var pf = Ev.Fields("DeviceInstanceId");
                foreach (var e in pnp)
                {
                    var id = Ev.Values(e, pf, 1)[0] ?? "";
                    if (id.StartsWith("USBSTOR", StringComparison.OrdinalIgnoreCase))
                    {
                        var time = e.TimeCreated?.ToUniversalTime();
                        t.Add(Log.T(time), "410", UsbName(id), "started; serial " + UsbSerial(id.Replace('\\', '#')));
                        c.Event(time, "USB", null, text: $"USB drive connected: {UsbName(id)} (serial {UsbSerial(id.Replace('\\', '#'))})");
                    }
                    e.Dispose();
                }
            }
            foreach (var x in err) c.Err.Add(x);
            t.WriteTo(c.Out);
        }

        // ---------------------------------------------------------------- files opened from removable drives

        /// <summary>Recent and Office Recent shortcuts whose target was on a removable drive: files the user opened from a USB drive.</summary>
        void OpenedFromRemovable()
        {
            c.Out.Sub("Files opened from removable drives (Recent shortcuts)", "opened = when the Recent shortcut was last written; volume = the USB drive's volume serial and label.");
            var t = new Table("@opened", "*target", "user", "volume", "shortcut");
            var rows = new List<(DateTime T, string[] F)>();
            foreach (var p in c.Profiles)
                foreach (var dir in new[] { @"AppData\Roaming\Microsoft\Windows\Recent", @"AppData\Roaming\Microsoft\Office\Recent" })
                {
                    var full = Path.Combine(p.Path, dir);
                    if (!Directory.Exists(full)) continue;
                    FileInfo[] fs;
                    try { fs = new DirectoryInfo(full).GetFiles("*.lnk"); } catch { continue; }
                    foreach (var f in fs)
                    {
                        Lnk l = null;
                        try { l = Lnk.Parse(c.ReadLocked(f.FullName)); } catch { }
                        if (l == null || l.DriveType != 2 || string.IsNullOrEmpty(l.Target)) continue;
                        if (l.VolumeSerial != null && !c.UsbVolumes.ContainsKey(l.VolumeSerial)) c.UsbVolumes[l.VolumeSerial] = l.VolumeLabel ?? "";
                        rows.Add((f.LastWriteTimeUtc, new[] { Log.T(f.LastWriteTimeUtc), Rules.Fix(l.Target), p.User,
                            "serial " + l.VolumeSerial + (l.VolumeLabel != null ? " label " + Rules.Fix(l.VolumeLabel) : ""), Rules.Fix(f.FullName) }));
                    }
                }
            foreach (var r in rows.OrderByDescending(r => r.T)) t.Add(r.F);
            t.WriteTo(c.Out);
        }
    }
}
