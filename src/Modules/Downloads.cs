using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace Spor.Modules
{
    /// <summary>
    /// Where files came from and what the user opened: browser download history (Chromium browsers, Firefox), files opened in
    /// Explorer (Recent shortcuts, WebCache file:/// entries), disk images mounted (ISO/IMG/VHD), archive tools (WinRAR, 7-Zip).
    /// </summary>
    class Downloads : IModule
    {
        public string Id => "downloads";
        public string Name => "DOWNLOADS AND OPENED FILES";
        public string Description => "browser downloads, files opened, ISO mounts, archive history";

        // types worth listing with the whitelist on: executables, scripts, archives, disk images, Office files with macros, shortcuts
        static readonly Regex Risky = new Regex(@"\.(exe|dll|scr|com|pif|cpl|sys|msi|msp|msc|msix|appx|appinstaller|application|appref-ms|bat|cmd|ps1|psm1|vbs|vbe|js|jse|jsc|wsf|wsh|wsc|sct|hta|py|pyw|au3|a3x|ahk|jar|jnlp|lnk|url|rdp|library-ms|search-ms|settingcontent-ms|scf|iqy|slk|xll|xlam|zip|rar|7z|cab|iso|img|vhd|vhdx|tar|gz|tgz|xz|bz2|zst|lzh|arj|uue|ace|docm|dotm|xlsm|pptm|ppam|one|chm|svg|htm|html|mht|reg)$", Util.RX);
        static readonly Regex Docs = new Regex(@"\.(pdf|doc|docx|xls|xlsx|ppt|pptx|rtf|odt|txt)$", Util.RX);
        // aggressive whitelist (Aggr): opened documents (not rtf: exploit documents), Nexus Mods archives
        static readonly Regex WebDocs = new Regex(@"\.(pdf|doc|docx|xls|xlsx|ppt|pptx|odt|txt|csv)$", Util.RX);
        static readonly Regex NexusMod = new Regex(@"\.(zip|rar|7z)$", Util.RX);
        static readonly Regex NexusCdn = new Regex(@"(^|\.)nexus-cdn\.com$", Util.RX);
        Ctx c;

        public void Execute(Ctx ctx)
        {
            c = ctx;
            Browsers();
            Extensions();
            Recent();
            WebCache();
            Images();
            Archivers();
        }

        bool Show(string path) => !Rules.Whitelist || Risky.IsMatch(path ?? "") || Rules.Strong(Rules.Flags(path ?? "")).Count > 0;

        /// <summary>The Chromium profiles Browsers read: (user, browser and profile, profile folder).</summary>
        readonly List<(string User, string Browser, string Dir)> profiles = new List<(string, string, string)>();

        /// <summary>
        /// Browser extensions not installed from a store (BrowserExtensions): loaded unpacked or from the command line, !unpacked-extension;
        /// developer mode on, the context flag !dev-mode. Their folders are listed with their files hashed when they are programs.
        /// </summary>
        void Extensions()
        {
            c.Out.Sub("Browser extensions not from a store", "Chromium profiles: extensions loaded unpacked or from the command line, and developer mode");
            var t = new Table("@changed", "[user", "[browser", "<flags", "*extension", "=details");
            var seen = new HashSet<string>(Util.IC);   // an extension in Secure Preferences and Preferences: once
            foreach (var (user, browser, dir) in profiles.Distinct())
                foreach (var file in new[] { "Secure Preferences", "Preferences" })
                {
                    var f = Path.Combine(dir, file);
                    try
                    {
                        if (!File.Exists(f)) continue;
                        var when = File.GetLastWriteTimeUtc(f);
                        var r = BrowserExtensions.Parse(Util.ReadText(f, BrowserExtensions.MaxText));
                        if (r == null) continue;
                        if (r.Value.DevMode && file == "Preferences")
                        {
                            var dfl = new List<string> { BrowserExtensions.DevModeFlag };
                            t.Add(Log.T(when), user, browser, Rules.FlagCol(dfl), "developer mode on", null);
                            c.Find(when, $"{c.U(user)}{browser}: extension developer mode on", null, dfl);
                        }
                        foreach (var x in r.Value.Unpacked)
                        {
                            if (!seen.Add(dir + "|" + x.Id)) continue;
                            var name = x.Name.Length > 0 ? x.Name : BrowserExtensions.ManifestName(x.Path);
                            var item = (x.Path.Length > 0 ? x.Path : x.Id) + (name.Length > 0 ? " (" + Rules.Fix(name) + ")" : "");
                            var fl = new List<string> { BrowserExtensions.UnpackedFlag };
                            DateTime? changed = Directory.Exists(x.Path) ? Directory.GetLastWriteTimeUtc(x.Path) : (DateTime?)null;
                            t.Add(Log.T(changed ?? when), user, browser, Rules.FlagCol(fl), Rules.Fix(item), $"{x.Location}; id {x.Id}");
                            if (Rules.DrivePath.IsMatch(x.Path)) c.Observe("path", x.Path + "\\", changed);
                            c.Find(changed ?? when, $"{c.U(user)}{browser}: extension {Rules.Fix(item)}", $"{x.Location}; id {x.Id}", fl);
                        }
                    }
                    catch (Exception e) { c.Err.Add($"extensions {browser} ({f}): {e.Message}"); }
                }
            t.WriteTo(c.Out, "none");
        }

        // ---------------- browser downloads ----------------
        void Browsers()
        {
            c.Out.Sub(Rules.Whitelist ? "Browser downloads: executables, scripts, archives, disk images" : "Browser downloads", "Time = download start. Page = the tab the download came from.");
            var rows = new List<(DateTime T, string User, string Browser, string Path, string Url, string Page, List<string> Fl)>();
            int total = 0;
            var browsers = new List<string>();
            foreach (var p in c.Profiles)
            {
                string la = Path.Combine(p.Path, @"AppData\Local"), ra = Path.Combine(p.Path, @"AppData\Roaming");
                // Chromium-based browsers: any folder with a "Local State" file (Chrome, Edge, Brave, Vivaldi, Opera, Yandex, Arc, Thorium, ...)
                var chromium = new List<(string, string)>();
                foreach (var root in new[] { la, ra })
                    if (Directory.Exists(root))
                        foreach (var ls in Util.Walk(root, 4, "Local State"))
                            chromium.Add((BrowserName(ls.DirectoryName), ls.DirectoryName));
                try
                {
                    var pk = Path.Combine(la, "Packages");   // Store-packaged browsers (Arc)
                    if (Directory.Exists(pk))
                        foreach (var d in Directory.GetDirectories(pk))
                        {
                            var lc = Path.Combine(d, @"LocalCache\Local");
                            if (Directory.Exists(lc)) foreach (var ls in Util.Walk(lc, 3, "Local State")) chromium.Add((BrowserName(ls.DirectoryName), ls.DirectoryName));
                        }
                }
                catch { }
                foreach (var (br, dir) in chromium)
                {
                    if (!Directory.Exists(dir)) continue;
                    var hist = new List<(string, string)>();
                    if (File.Exists(Path.Combine(dir, "History"))) hist.Add((br, Path.Combine(dir, "History")));
                    foreach (var d in Directory.GetDirectories(dir).Where(d => Regex.IsMatch(Path.GetFileName(d), @"^(Default|Profile \d+|Guest Profile)$", Util.RX)))
                        if (File.Exists(Path.Combine(d, "History"))) hist.Add((br + (Path.GetFileName(d) == "Default" ? "" : " " + Path.GetFileName(d)), Path.Combine(d, "History")));
                    foreach (var (name, h) in hist)
                    {
                        browsers.Add(c.U(p.User) + name);
                        profiles.Add((p.User, name, Path.GetDirectoryName(h)));   // for the extensions (Extensions)
                        try
                        {
                            var db = Sqlite.Open(c, h);
                            var chain = new Dictionary<long, (long Idx, string Url)>();
                            foreach (var r in db.Table("downloads_url_chains"))
                            {
                                long id = Convert.ToInt64(r["id"] ?? 0L), ix = Convert.ToInt64(r["chain_index"] ?? 0L);
                                if (!chain.TryGetValue(id, out var x) || ix > x.Idx) chain[id] = (ix, r["url"] as string);
                            }
                            foreach (var r in db.Table("downloads"))
                            {
                                total++;
                                var t = Util.FtTime(Convert.ToInt64(r["start_time"] ?? 0L) * 10);
                                if (t == null || t < c.Since) continue;
                                var path = r["target_path"] as string ?? r["current_path"] as string ?? "";
                                if (!Show(path)) continue;
                                var id = Convert.ToInt64(r["id"] ?? 0L);
                                var url = chain.TryGetValue(id, out var cu) ? cu.Url : r.TryGetValue("site_url", out var su) ? su as string : null;
                                var page = (r.TryGetValue("tab_url", out var tu) ? tu as string : null) is string tus && tus.Length > 0 ? tus : r.TryGetValue("referrer", out var rf) ? rf as string : null;
                                var fl = new List<string>();
                                var danger = Convert.ToInt64(r.TryGetValue("danger_type", out var dt) ? dt ?? 0L : 0L);
                                if (danger == 6 || danger == 16) fl.Add("!kept-despite-warning");   // USER_VALIDATED / DEEP_SCANNED_OPENED_DANGEROUS
                                rows.Add((t.Value, p.User, name, path, url, page, fl));
                            }
                        }
                        catch (Exception e) { c.Err.Add($"{name} history ({h}): {e.Message}"); }
                    }
                }
                // Firefox and its forks (Waterfox, LibreWolf, Floorp, Zen, ...): any folder with profiles.ini; downloads are annotations on the source URL
                var ffs = new List<(string Name, string Dir)>();
                foreach (var root in new[] { ra, la })
                    if (Directory.Exists(root))
                        foreach (var pi in Util.Walk(root, 3, "profiles.ini")) ffs.Add((Path.GetFileName(pi.DirectoryName), pi.DirectoryName));
                foreach (var (ffName, ffDir) in ffs)
                    foreach (var prof in Directory.GetDirectories(ffDir).Where(d => Path.GetFileName(d).Equals("Profiles", StringComparison.OrdinalIgnoreCase)).SelectMany(Directory.GetDirectories).Concat(Directory.GetDirectories(ffDir)))
                    {
                        var pl = Path.Combine(prof, "places.sqlite");
                        if (!File.Exists(pl)) continue;
                        try
                        {
                            var db = Sqlite.Open(c, pl);
                            var attr = db.Table("moz_anno_attributes").Where(r => (r["name"] as string) == "downloads/destinationFileURI").Select(r => Convert.ToInt64(r["id"])).ToList();
                            if (attr.Count == 0) continue;
                            var places = db.Table("moz_places").ToDictionary(r => Convert.ToInt64(r["id"]), r => r["url"] as string);
                            foreach (var r in db.Table("moz_annos").Where(r => attr.Contains(Convert.ToInt64(r["anno_attribute_id"] ?? 0L))))
                            {
                                total++;
                                var t = DateTimeOffset.FromUnixTimeMilliseconds(Convert.ToInt64(r["dateAdded"] ?? 0L) / 1000).UtcDateTime;
                                if (t < c.Since) continue;
                                var content = r["content"] as string ?? "";
                                string path; try { path = new Uri(content).LocalPath; } catch { path = content; }
                                if (!Show(path)) continue;
                                places.TryGetValue(Convert.ToInt64(r["place_id"] ?? 0L), out var url);
                                rows.Add((t, p.User, ffName + " " + Path.GetFileName(prof), path, url, null, new List<string>()));
                            }
                        }
                        catch (Exception e) { c.Err.Add($"{ffName} history ({pl}): {e.Message}"); }
                    }
            }
            c.Out.Comment($"{total} downloads in the browser histories");
            c.Out.Comment("browsers: " + (browsers.Count > 0 ? string.Join(", ", browsers.Distinct()) : "none found"));
            // The user is a tag of its own ("[anna] [Brave]"), never inside the browser's brackets.
            var dlt = new Table("@time", "[user", "[browser", "!status", "<flags", "*file");
            var keptSeen = new HashSet<string>(Util.IC);
            var dlSeen = new HashSet<string>(Util.IC);   // aggressive: the same file from the same host again
            foreach (var r in rows.OrderBy(r => r.T))
            {
                if (r.Fl.Contains(KeptFlag))
                {
                    // the tools a helper asked for (this Spor, FRST from bleepingcomputer.com) are no finding; the same file from the same
                    // page again ("x (1).py", 27 times from one chat) only the first time
                    if (OwnTool(r.Path, r.Url, SelfPath, SelfHash) || !keptSeen.Add(SameDownload(r.Path, r.Page ?? r.Url)))
                        r.Fl.Remove(KeptFlag);
                }
                // a download from a cheap TLD campaigns favour (.lol, .top, ...): a hint, in the SUMMARY only next to a strong flag
                if (new[] { r.Url, r.Page }.Any(u => HostNames.AbusedTld(HostOnly(u))) && !r.Fl.Contains(Rules.AbusedTldFlag)) r.Fl.Add(Rules.AbusedTldFlag);
                var fl = Rules.Flags(r.Path).Concat(r.Fl).Distinct().ToList();
                var f = c.F(r.Path);
                dlt.Add(Log.T(r.T), c.MultiUser ? r.User : null, r.Browser, f.Status, Rules.FlagCol(fl), f.Path);
                if (Aggr.On && fl.Count == 0)
                {
                    if (!dlSeen.Add(r.Path + "|" + Host(r.Url))) dlt.Aggr("the same file downloaded again from the same host");
                    else if (NexusMod.IsMatch(r.Path) && NexusCdn.IsMatch(HostOnly(r.Url) ?? "")) dlt.Aggr("mod archives from Nexus Mods (nexus-cdn.com)");
                }
                else if (Aggr.On) dlSeen.Add(r.Path + "|" + Host(r.Url));
                dlt.More("from", LongUrl(r.Url));
                if (!string.IsNullOrEmpty(r.Page) && r.Page != r.Url) dlt.More("page", LongUrl(r.Page));
                // the URLs on sub-lines (they make the line too long); the page only when it is not the download URL itself
                var urls = new List<(string Key, string Value)> { ("from", Host(r.Url)) };
                if (!string.IsNullOrEmpty(r.Page) && !Host(r.Page).Equals(Host(r.Url), StringComparison.OrdinalIgnoreCase)) urls.Add(("page", Host(r.Page)));
                c.Event(r.T, "DL", r.Path, $"{c.U(r.User)}{r.Browser}", r.Fl, more: urls);
                // a flagged download in the time window is in the SUMMARY through its timeline line (one line, not two); an older one here
                if (Rules.Strong(fl).Count > 0 && r.T < c.Since) c.Find(r.T, c.File(r.Path), $"downloaded from {r.Url}", Rules.Strong(fl));
            }
            dlt.WriteTo(c.Out, $"none in the last {c.Opt.Days} days");
        }

        /// <summary>Browser name from its data folder: ...\Google\Chrome\User Data -> "Chrome", ...\Opera Software\Opera Stable -> "Opera Stable".</summary>
        static string BrowserName(string dir)
        {
            var n = Path.GetFileName(dir);
            if (n.Equals("User Data", StringComparison.OrdinalIgnoreCase)) n = Path.GetFileName(Path.GetDirectoryName(dir));
            // an app's numbered profile folders (...\App\0, ...\App\1): "App 0", not "0"
            else if (Regex.IsMatch(n, @"^\d+$")) n = Path.GetFileName(Path.GetDirectoryName(dir)) + " " + n;
            return n.Replace("-Browser", "").Replace("YandexBrowser", "Yandex");
        }

        /// <summary>(pure) A URL for the section: whole up to 250 characters, else cut with "…" (signed download links carry 1 KB of tokens).</summary>
        internal static string LongUrl(string url) => url == null || url.Length <= 250 ? url : url.Substring(0, 250) + "…";

        const string KeptFlag = "!kept-despite-warning";

        static string selfPath, selfHash;
        /// <summary>The running Spor.exe.</summary>
        static string SelfPath => selfPath ?? (selfPath = System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName ?? "");
        /// <summary>SHA256 of the running Spor.exe ("" when unreadable).</summary>
        static string SelfHash
        {
            get
            {
                if (selfHash != null) return selfHash;
                try
                {
                    using (var s = File.OpenRead(SelfPath)) using (var sha = System.Security.Cryptography.SHA256.Create())
                        selfHash = BitConverter.ToString(sha.ComputeHash(s)).Replace("-", "");
                }
                catch { selfHash = ""; }
                return selfHash;
            }
        }

        static readonly Regex SporName = new Regex(@"^Spor( \(\d+\))?\.exe$", Util.RX);
        static readonly Regex FrstName = new Regex(@"^FRST(64)?( \(\d+\))?\.exe$", Util.RX);

        /// <summary>
        /// (pure with the test hooks) A download of a tool the helper asked for: this Spor.exe (its path, or a Spor.exe that is gone or
        /// has the running one's SHA256; a file of that name with other content is not), or FRST(64).exe downloaded from
        /// bleepingcomputer.com (FRST is unsigned). Its "kept despite warning" is no finding.
        /// </summary>
        internal static bool OwnTool(string path, string url, string selfPath, string selfHash)
        {
            if (string.IsNullOrEmpty(path)) return false;
            var name = Path.GetFileName(path);
            if (!string.IsNullOrEmpty(selfPath) && path.Equals(selfPath, StringComparison.OrdinalIgnoreCase)) return true;
            if (SporName.IsMatch(name))
            {
                if (!File.Exists(path)) return true;
                try
                {
                    using (var s = File.OpenRead(path)) using (var sha = System.Security.Cryptography.SHA256.Create())
                        return selfHash.Length > 0 && BitConverter.ToString(sha.ComputeHash(s)).Replace("-", "").Equals(selfHash, StringComparison.OrdinalIgnoreCase);
                }
                catch { return false; }
            }
            if (FrstName.IsMatch(name) && Regex.IsMatch(HostOnly(url), @"(^|\.)bleepingcomputer\.com$", Util.RX))
                return true;
            return false;
        }

        /// <summary>(pure) One download "again": its name without " (1)" and the host of its page, lower case.</summary>
        internal static string SameDownload(string path, string page) =>
            Regex.Replace(Path.GetFileName(path ?? ""), @" \(\d+\)(?=\.[^.]+$|$)", "").ToLowerInvariant() + "|" + HostOnly(page).ToLowerInvariant();

        /// <summary>The host name of a URL ("blob:https://x.lol/..." too), '' if none.</summary>
        static string HostOnly(string url)
        {
            if (string.IsNullOrEmpty(url)) return "";
            try { return new Uri(Regex.Replace(url, @"^blob:", "", RegexOptions.IgnoreCase)).Host; } catch { return ""; }
        }

        /// <summary>(pure) A download's address for the timeline: host and path, no scheme and query ("blob:https://claude.ai/x" -> "blob:claude.ai/x").</summary>
        internal static string Host(string url)
        {
            if (string.IsNullOrEmpty(url)) return "?";
            var blob = url.StartsWith("blob:", StringComparison.OrdinalIgnoreCase);
            var inner = blob ? url.Substring(5) : url;
            try { var u = new Uri(inner); return u.Scheme == "file" ? url : (blob ? "blob:" : "") + u.Host + (u.AbsolutePath.Length > 1 ? u.AbsolutePath : ""); } catch { return url; }
        }

        // ---------------- Recent shortcuts ----------------
        void Recent()
        {
            c.Out.Sub(Rules.Whitelist ? "Files opened in Explorer (Recent): executables, scripts, archives, disk images, and anything on a CD/DVD or mounted ISO"
                                      : "Files opened in Explorer (Recent)", "Time = last opened (shortcut written); first opened when different.");
            var rows = new List<(DateTime T, DateTime First, string User, Lnk L)>();
            foreach (var p in c.Profiles)
            {
                var dir = Path.Combine(p.Path, @"AppData\Roaming\Microsoft\Windows\Recent");
                if (!Directory.Exists(dir)) continue;
                foreach (var f in new DirectoryInfo(dir).GetFiles("*.lnk"))
                {
                    if (f.LastWriteTimeUtc < c.Since) continue;
                    try
                    {
                        var l = Lnk.Parse(c.ReadLocked(f.FullName));
                        if (l?.Target == null) continue;
                        if (Rules.Whitelist && !Risky.IsMatch(l.Target) && l.DriveType != 5 && Rules.Strong(Rules.Flags(l.Target)).Count == 0) continue;
                        rows.Add((f.LastWriteTimeUtc, f.CreationTimeUtc, p.User, l));
                    }
                    catch (Exception e) { c.Err.Add("Recent " + f.Name + ": " + e.Message); }
                }
            }
            var rct = new Table("@last opened", "first opened", "[user", "!status", "<flags", "*file", "=where");
            foreach (var r in rows.OrderBy(r => r.T))
            {
                var fl = Rules.Flags(r.L.Target);
                var extra = string.Join(", ", new[] { r.L.Where, (r.T - r.First).TotalMinutes > 2 ? "first opened " + r.First.ToString("yyyy-MM-dd HH:mm") : null }.Where(x => x != null));
                var f = c.F(r.L.Target);
                rct.Add(Log.T(r.T), (r.T - r.First).TotalMinutes > 2 ? Log.T(r.First) : "-", r.User, f.Status, Rules.FlagCol(fl), f.Path, r.L.Where);
                c.Event(r.T, "OPN", r.L.Target, "opened" + (r.L.Where != null ? " " + r.L.Where : ""));
                if ((r.T - r.First).TotalMinutes > 2) c.Event(r.First, "OPN", r.L.Target, "first opened" + (r.L.Where != null ? " " + r.L.Where : ""));
                if (r.L.DriveType == 5 && Regex.IsMatch(r.L.Target, @"\.(exe|scr|com|bat|cmd|lnk|js|vbs|msi|hta)$", Util.RX))
                    c.Find(r.T, $"program opened from a CD/DVD or mounted ISO: {Rules.Fix(r.L.Target)}", null, Rules.InfoFlag("!disk-image"));
            }
            rct.WriteTo(c.Out);
        }

        // ---------------- WebCache (Explorer/IE/old Edge): file:/// entries ----------------
        void WebCache()
        {
            c.Out.Sub(Rules.Whitelist ? "Files opened, from WebCache: executables, scripts, archives, documents" : "Files opened, from WebCache",
                "Explorer and Internet Explorer record opened local files as file:/// entries.");
            var rows = new List<(DateTime T, string User, string Path)>();
            foreach (var p in c.Profiles)
            {
                var db = Path.Combine(p.Path, @"AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat");
                if (!File.Exists(db)) continue;
                try
                {
                    using (var e = Ese.OpenCopy(c, db, "V01", Path.Combine(c.Temp, "webcache_" + p.User)))
                    {
                        var containers = e.Rows("Containers", "ContainerId", "Name").ToList();
                        foreach (var ct in containers.Where(r => (r["Name"] as string ?? "").StartsWith("History", StringComparison.OrdinalIgnoreCase) || (r["Name"] as string ?? "").StartsWith("MSHist", StringComparison.OrdinalIgnoreCase)))
                            foreach (var r in e.Rows("Container_" + Convert.ToInt64(ct["ContainerId"]), "Url", "AccessedTime", "ModifiedTime"))
                            {
                                var url = r["Url"] as string ?? "";
                                int i = url.IndexOf("file:///", StringComparison.OrdinalIgnoreCase);
                                if (i < 0) continue;
                                var t = Util.FtTime(Convert.ToInt64(r["AccessedTime"] ?? 0L));
                                if (t == null || t < c.Since) continue;
                                string path; try { path = Uri.UnescapeDataString(url.Substring(i + 8)).Replace('/', '\\'); } catch { path = url.Substring(i + 8); }
                                if (Rules.Whitelist && !Risky.IsMatch(path) && !Docs.IsMatch(path)) continue;
                                rows.Add((t.Value, p.User, path));
                            }
                    }
                }
                catch (Exception e) { c.Err.Add("WebCache " + p.User + ": " + e.Message); }
            }
            rows = rows.GroupBy(r => r.Path + "|" + r.T.ToString("yyyyMMddHHmm"), Util.IC).Select(g => g.First()).ToList();
            // many entries of one user with the same second: WebCache wrote them at once (sync, compaction), not when each file was opened
            var batch = WebCacheBatches(rows.Select(r => (r.T, r.User, r.Path)));
            var wct = new Table("@time", "[user", "!status", "=details", "<flags", "*file");
            foreach (var r in rows.OrderBy(r => r.T))
            {
                var f = c.F(r.Path);
                var n = batch.TryGetValue(BatchKey(r.T, r.User), out var bn) ? bn : 0;
                var note = n > 0 ? $"WebCache batch of {n} entries, not the open time" : "-";
                wct.Add(Log.T(r.T), r.User, f.Status, note, Rules.FlagCol(Rules.Flags(r.Path)), f.Path);
                if (Aggr.On && Rules.Flags(r.Path).Count == 0)
                {
                    if (WebDocs.IsMatch(r.Path) && !Risky.IsMatch(r.Path)) wct.Aggr("documents opened (pdf, Office, text)");
                    else if (n > 0 && rows.Any(o => o.Path.Equals(r.Path, StringComparison.OrdinalIgnoreCase) && !batch.ContainsKey(BatchKey(o.T, o.User))))
                        wct.Aggr("WebCache batch entries of files listed with their own open time");
                }
                if (!(Risky.IsMatch(r.Path) || !Rules.Whitelist)) continue;
                // a batch time only when the file has no real open time of its own
                if (n > 0 && rows.Any(o => o.Path.Equals(r.Path, StringComparison.OrdinalIgnoreCase) && !batch.ContainsKey(BatchKey(o.T, o.User)))) continue;
                c.Event(r.T, "OPN", r.Path, n > 0 ? "opened (WebCache); " + note : "opened (WebCache)");
            }
            wct.WriteTo(c.Out);
        }

        static string BatchKey(DateTime t, string user) => (user ?? "") + "|" + t.ToString("yyyyMMddHHmmss");

        /// <summary>(pure) WebCache batches: 5 or more different files of one user with the same second, by BatchKey, with their count.</summary>
        internal static Dictionary<string, int> WebCacheBatches(IEnumerable<(DateTime T, string User, string Path)> rows) =>
            rows.GroupBy(r => BatchKey(r.T, r.User), StringComparer.OrdinalIgnoreCase)
                .Select(g => (g.Key, N: g.Select(r => r.Path).Distinct(StringComparer.OrdinalIgnoreCase).Count()))
                .Where(x => x.N >= 5).ToDictionary(x => x.Key, x => x.N, StringComparer.OrdinalIgnoreCase);

        // ---------------- disk images mounted ----------------
        void Images()
        {
            c.Out.Sub("Disk images mounted (ISO, IMG, VHD)", "Malware is often delivered in ISO/IMG files to skip the download warning (Mark of the Web).");
            var ev = Ev.Query("Microsoft-Windows-VHDMP-Operational", null, c.Since, 5000, c.Err);
            if (ev.Count == 0) ev = Ev.Query("Microsoft-Windows-VHDMP/Operational", null, c.Since, 5000, c.Err);
            var rows = new List<(DateTime? T, string Path)>();
            foreach (var e in ev)
            {
                var msg = Ev.Msg(e);
                var m = Regex.Match(msg, @"([a-z]:\\[^""<>|]*?\.(iso|img|vhdx?))", Util.RX);
                if (m.Success && !Regex.IsMatch(msg, @"unsurfac|dismount|removed|detach|offline", Util.RX)) rows.Add((e.TimeCreated?.ToUniversalTime(), m.Groups[1].Value));
                e.Dispose();
            }
            var imgs = rows.Where(r => r.T.HasValue).GroupBy(r => r.Path, Util.IC).Select(g => (Path: g.Key, Last: g.Max(r => r.T.Value), First: g.Min(r => r.T.Value), N: g.Count())).ToList();
            var it = new Table("@last mounted", "first mounted", "times", "!status", "*image");
            foreach (var r in imgs.OrderBy(r => r.Last))
            {
                var f = c.F(r.Path, false);
                it.Add(Log.T(r.Last), Log.T(r.First), r.N.ToString(), f.Status, f.Path);
                c.Event(r.First, "ISO", r.Path, "disk image mounted", noHash: true);
                if (r.N > 1) c.Event(r.Last, "ISO", r.Path, "disk image mounted", noHash: true);
                bool user = Regex.IsMatch(r.Path, @"\.(iso|img)$", Util.RX) || !Regex.IsMatch(r.Path, @"\\AppData\\|\\ProgramData\\|^[a-z]:\\(Windows|Program Files)", Util.RX);
                if (user) c.Find(r.Last, $"disk image mounted{(r.N > 1 ? $" ({r.N}x)" : "")}: {Rules.Fix(r.Path)}", null, Rules.InfoFlag("!disk-image"));
            }
            it.WriteTo(c.Out);
        }

        // ---------------- archive tools ----------------
        void Archivers()
        {
            c.Out.Sub("Archive tools: archives opened and extraction folders", "time = when the list last changed; entry: newest first");
            var at = new Table("@time", "[user", "[tool", "*list");
            foreach (var h in c.Hives)
            {
                void List(string tool, string sub, Func<RegistryKey, List<string>> read, string what)
                {
                    try
                    {
                        using (var k = h.Root.OpenSubKey(sub))
                        {
                            if (k == null) return;
                            var l = read(k).Where(x => !string.IsNullOrWhiteSpace(x)).ToList();
                            if (l.Count == 0) return;
                            var t = Native.LastWrite(k);
                            at.Add(Log.T(t), h.User, tool, what);
                            foreach (var x in l) at.More("entry", c.FF(x, false));
                            c.Event(t, "ARC", null, text: $"{c.U(h.User)}{tool}: newest of the {what}: {Rules.Fix(l[0])}");
                        }
                    }
                    catch (Exception e) { c.Err.Add(tool + " " + h.User + ": " + e.Message); }
                }
                List<string> Numbered(RegistryKey k) => k.GetValueNames().Where(n => Regex.IsMatch(n, @"^\d+$")).OrderBy(n => int.Parse(n)).Select(n => Convert.ToString(k.GetValue(n))).ToList();
                List<string> Multi(RegistryKey k, string v) => k.GetValue(v) is byte[] b ? Encoding.Unicode.GetString(b).Split('\0').ToList() : new List<string>();
                List("WinRAR", @"Software\WinRAR\ArcHistory", Numbered, "archives opened");
                List("WinRAR", @"Software\WinRAR\DialogEditHistory\ExtrPath", Numbered, "extraction folders");
                List("7-Zip", @"Software\7-Zip\Compression", k => Multi(k, "ArcHistory"), "archives created");
                List("7-Zip", @"Software\7-Zip\Extraction", k => Multi(k, "PathHistory"), "extraction folders");
                List("7-Zip", @"Software\7-Zip\FM", k => Multi(k, "FolderHistory"), "folders browsed");
            }
            at.WriteTo(c.Out);
        }
    }
}
