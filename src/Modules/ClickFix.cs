using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

namespace Spor.Modules
{
    /// <summary>
    /// ClickFix / FileFix / fake captcha traces, per user (all profiles, also users not logged in):
    ///  - Run dialog history (Win+R, RunMRU): all entries, newest first; time = when the newest entry was typed
    ///  - Explorer address bar (TypedPaths, FileFix): only entries that are commands, by keyword or by shape (a typed path never has
    ///    quotes, pipes, switches or long space padding before a # fake path). -nowhitelist: all entries.
    ///  - PowerShell console history (PSReadLine): lines that download or run code or look obfuscated (last HistoryMax),
    ///    plus the last HistoryTail lines unfiltered. PSReadLine never saves lines containing password/token/apikey/secret/asplaintext,
    ///    so an attacker can keep a pasted command out of the file: an empty or harmless history does not prove nothing was pasted.
    /// </summary>
    class ClickFix : IModule
    {
        public string Id => "clickfix";
        public string Name => "CLICKFIX";
        public string Description => "Run dialog, Explorer address bar, PowerShell history";

        // command interpreters, download/execute patterns, URLs, WebDAV/public-IP UNC paths, captcha/verification text
        static readonly Regex Sus = new Regex(@"powershell|pwsh|mshta|curl|wget|bitsadmin|certutil|msiexec|rundll32|regsvr32|wscript|cscript|conhost|forfiles|cmd(\.exe)?[""' ]+/[ck]|\b(iwr|irm|iex)\b|invoke-(webrequest|restmethod|expression)|downloadstring|downloadfile|frombase64|\s-e(nc|ncodedcommand)?\s+[a-z0-9+/=]{20}|https?://(?!(?:localhost|127(?:\.\d{1,3}){3}|\[::1\])(?:[:/]|$))|\\\\[^\\\s]+@(ssl|\d+)|davwwwroot|\\\\(?!(10|127)\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)\d{1,3}(\.\d{1,3}){3}\\|captcha|verif|robot|human|ray id|cloudflare|(\w\^){3,}", Util.RX);

        // PowerShell history: commands that download or run code, and common obfuscation (backticks in words, 'a'+'b', [char] codes,
        // reversed strings, gcm i*x, $pshome[4], any -EncodedCommand spelling, long Base64)
        static Regex PsSus => Rules.PsSus;

        // TypedPaths: things a typed path never contains (FileFix pads the command with spaces and hides it behind a # fake path)
        static readonly Regex Shape = new Regex(@"[""|`]|\$\(|\s{4,}|\s#|\s[/\p{Pd}][a-z]", Util.RX);

        public void Execute(Ctx c)
        {
            var hives = c.Hives;
            c.Out.Comment("Fake captcha / ClickFix pages make the user paste a command into the Run dialog (Win+R), the Explorer address bar");
            c.Out.Comment("(FileFix) or PowerShell. !suspicious = command that downloads or runs code, or looks obfuscated.");

            c.Out.Sub("Run dialog history (newest first)", "time = when the newest entry was typed (only stored for the newest one)");
            var rt = new Table("@time", "[user", "order", "<flags", "*command");
            foreach (var h in hives)
            {
                try
                {
                    using (var k = h.Root.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"))
                    {
                        if (k == null) continue;
                        var t = Native.LastWrite(k); int n = 0;
                        foreach (var ch in (Convert.ToString(k.GetValue("MRUList")) ?? ""))
                        {
                            var v = Convert.ToString(k.GetValue(ch.ToString())) ?? "";
                            if (v.Length == 0) continue;
                            v = Regex.Replace(v, @"\\1$", ""); n++;
                            bool sus = Sus.IsMatch(v);
                            c.Observe("cmd", v, n == 1 ? t : null, "Run dialog " + c.U(h.User) + v);
                            rt.Add(n == 1 ? Log.T(t) : "-", h.User, n.ToString(), sus ? "!suspicious" : "-", v);
                            if (n == 1) c.Event(t, "RUN", null, text: c.U(h.User) + "Run dialog: " + v, flags: sus ? new List<string> { "!suspicious" } : null);
                            // the newest entry in the time window is in the SUMMARY through its timeline line; the others here
                            if (sus && (n != 1 || !(t >= c.Since))) c.Find(n == 1 ? t : null, "Run dialog " + c.U(h.User) + v, null, new List<string> { "!suspicious" });
                        }
                    }
                }
                catch (Exception e) { c.Err.Add("RunMRU " + h.User + ": " + e.Message); }
            }
            rt.WriteTo(c.Out);

            c.Out.Sub(Rules.Whitelist ? "Explorer address bar: entries that are commands, not paths" : "Explorer address bar: all entries",
                "A typed path never has quotes, pipes, switches, or long space padding before a # fake path (FileFix).\ntime = when the newest entry (url1) was typed");
            var at = new Table("@time", "[user", "entry", "<flags", "*typed");
            var counts = new List<string>();
            foreach (var h in hives)
            {
                try
                {
                    using (var k = h.Root.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths"))
                    {
                        if (k == null) continue;
                        var t = Native.LastWrite(k);
                        var all = k.GetValueNames().Where(n => Regex.IsMatch(n, @"^url\d+$", Util.RX)).OrderBy(n => int.Parse(Regex.Replace(n, @"\D", ""))).ToList();
                        int bad = 0;
                        foreach (var n in all)
                        {
                            var v = Convert.ToString(k.GetValue(n)) ?? "";
                            bool s = Sus.IsMatch(v) || Shape.IsMatch(v);
                            if (s) { bad++; c.Find(n == "url1" ? t : null, "Explorer address bar " + c.U(h.User) + v, null, new List<string> { "!suspicious" }); }
                            if (s || !Rules.Whitelist) at.Add(n == "url1" ? Log.T(t) : "-", h.User, n, s ? "!suspicious" : "-", v);
                        }
                        if (all.Count > 0) counts.Add($"{h.User}: {all.Count} entries, {bad} suspicious");
                        // the suspicious entries are SUMMARY lines of their own (with the text): the timeline line without the flag
                        if (bad > 0) c.Event(t, "ADR", null, text: c.U(h.User) + "Explorer address bar: newest entry typed");
                    }
                }
                catch (Exception e) { c.Err.Add("TypedPaths " + h.User + ": " + e.Message); }
            }
            if (counts.Count > 0) c.Out.Comment(string.Join("; ", counts));
            at.WriteTo(c.Out);

            int max = c.Opt.HistoryMax, tail = c.Opt.HistoryTail;
            bool any = false;
            foreach (var p in c.Profiles)
            {
                var dir = Path.Combine(p.Path, @"AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine");
                string[] fs;
                try { fs = Directory.Exists(dir) ? Directory.GetFiles(dir, "*_history.txt") : new string[0]; } catch { continue; }
                foreach (var f in fs)
                {
                    try
                    {
                        var lines = Util.AllLines(f); any = true;
                        var hits = Enumerable.Range(0, lines.Count).Where(i => PsSus.IsMatch(lines[i])).ToList();
                        var t = File.GetLastWriteTimeUtc(f);
                        var same = SameLines(lines);
                        // one Autodetect value per distinct command; read-only checks (a helper looking for a family's files) are no
                        // known malware: they get a comment after the listing instead
                        var checks = new List<(int Line, string Families)>();
                        foreach (var i in same.Keys.OrderBy(i => i))
                        {
                            if (ReadOnlyCheck(lines[i]))
                            {
                                var fams = Autodetect.Patterns.Match("cmd", lines[i]).Select(m => m.Family).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
                                if (fams.Count > 0) checks.Add((i, string.Join(", ", fams)));
                                continue;
                            }
                            var where = "line " + (i + 1) + (same[i].Count > 0 ? " (also " + string.Join(", ", same[i].Select(x => x + 1)) + ")" : "");
                            c.Observe("cmd", lines[i], t, $"PowerShell history {c.U(p.User)}{Path.GetFileName(f)} {where}: {Rules.Fix(Util.Clip(lines[i]))}");
                        }
                        c.Out.Sub($"PowerShell console history: {c.U(p.User)}{Path.GetFileName(f)}",
                            $"{f}: {lines.Count} lines, {hits.Count} suspicious, last written {Log.T(t)} UTC.\n" +
                            "All suspicious lines, then the last " + tail + " lines. PowerShell never saves lines with password/token/apikey/secret,\n" +
                            "so attackers can keep a pasted command out: an empty or harmless history does not prove nothing was pasted.");
                        c.Event(t, "PSH", null, text: $"{c.U(p.User)}PowerShell history {Path.GetFileName(f)} written ({hits.Count} suspicious lines of {lines.Count})");
                        // the SUMMARY line with the suspicious commands themselves (the first few) on command: sub-lines
                        if (hits.Count > 0)
                            c.Find(t, $"PowerShell history {c.U(p.User)}{Path.GetFileName(f)}", $"{hits.Count} suspicious lines", new List<string> { "!suspicious" },
                                   hits.Select(i => lines[i].Trim()).Distinct(StringComparer.Ordinal).Take(5).Select(s => ("command", Rules.Fix(Util.Clip(s, 200)))).ToList());
                        // a command typed again is one row: the first time in each part, the other line numbers on an also: sub-line
                        var ht = new Table("@line", "[part", "<flags", "*command");
                        void Row(int i, string part, string flag, string text)
                        {
                            ht.Add((i + 1).ToString(), part, flag, text);
                            var others = Occurrences(same, lines, i).Where(x => x != i).ToList();
                            if (others.Count > 0) ht.More("also", (others.Count == 1 ? "line " : "lines ") + string.Join(", ", others.Select(x => x + 1)));
                        }
                        var shown = new HashSet<string>(StringComparer.Ordinal);
                        foreach (var i in hits) if (shown.Add(lines[i].Trim())) Row(i, "suspicious", "!suspicious", lines[i].Trim());
                        shown.Clear();
                        for (int i = Math.Max(0, lines.Count - tail); i < lines.Count; i++)
                            if (lines[i].Trim().Length == 0 || shown.Add(lines[i].Trim()))
                                Row(i, "last", PsSus.IsMatch(lines[i]) ? "!suspicious" : "-", lines[i].TrimEnd());
                        ht.WriteTo(c.Out);
                        if (checks.Count > 0) c.Out.Comment(CheckHint(checks.Select(x => (x.Line + 1, x.Families)).ToList()));
                    }
                    catch (Exception e) { c.Err.Add("PowerShell history " + f + ": " + e.Message); }
                }
            }
            if (!any) { c.Out.Sub("PowerShell console history"); c.Out.None(); }
        }

        /// <summary>
        /// (pure) Identical history lines (trimmed; blank lines left out): the first line of each text -> the later lines with the same
        /// text (0-based).
        /// </summary>
        internal static Dictionary<int, List<int>> SameLines(IList<string> lines)
        {
            var first = new Dictionary<string, int>(StringComparer.Ordinal);
            var res = new Dictionary<int, List<int>>();
            for (int i = 0; i < lines.Count; i++)
            {
                var s = (lines[i] ?? "").Trim();
                if (s.Length == 0) continue;
                if (first.TryGetValue(s, out var j)) res[j].Add(i);
                else { first[s] = i; res[i] = new List<int>(); }
            }
            return res;
        }

        /// <summary>
        /// (pure) The comment after a history listing for read-only lines that name a known family's traces (1-based line numbers):
        /// "History line 19 only checks for traces of known malware (VS Code bootstrap loader): ...".
        /// </summary>
        internal static string CheckHint(List<(int Line, string Families)> checks)
        {
            var one = checks.Count == 1;
            var what = one ? checks[0].Families : string.Join("; ", checks.Select(x => $"{x.Line}: {x.Families}"));
            return $"History line{(one ? "" : "s")} {string.Join(", ", checks.Select(x => x.Line))} only check{(one ? "s" : "")} for traces of known malware " +
                   $"({what}): read-only, like a helper's check, so no known-malware finding.";
        }

        /// <summary>(pure) Every line (0-based) with the same text as line i, i included, in order.</summary>
        internal static List<int> Occurrences(Dictionary<int, List<int>> same, IList<string> lines, int i)
        {
            var s = (lines[i] ?? "").Trim();
            if (s.Length == 0) return new List<int> { i };
            foreach (var kv in same)
                if (lines[kv.Key].Trim() == s) return new[] { kv.Key }.Concat(kv.Value).ToList();
            return new List<int> { i };
        }

        // commands that only read: files, registry, processes, services, Defender state; and the pipeline cmdlets that format or filter
        static readonly Regex ReadVerb = new Regex(
            @"^(Test-Path|Get-Item|Get-ItemProperty|Get-ItemPropertyValue|Get-ChildItem|gci|dir|ls|Get-Content|gc|cat|type|Get-FileHash|Get-Acl|" +
            @"Get-CimInstance|gcim|Get-WmiObject|gwmi|Get-Process|gps|ps|Get-Service|gsv|Get-ScheduledTask|Get-ScheduledTaskInfo|Get-NetTCPConnection|" +
            @"Resolve-DnsName|Get-DnsClientCache|Get-MpPreference|Get-MpComputerStatus|Get-MpThreatDetection|Get-MpThreat|Get-Date|Get-Location|pwd|" +
            @"Select-Object|select|Where-Object|where|\?|Sort-Object|sort|Format-\w+|ft|fl|fw|Measure-Object|measure|Group-Object|group|" +
            @"Select-String|sls|Out-String|Out-Host|Write-Output|Write-Host|echo)(?=$|[\s(])", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

        /// <summary>
        /// (pure) A history line that only reads: every statement and pipeline part starts with a read-only command (Test-Path,
        /// Get-ItemProperty, Get-Content, Get-CimInstance, Select-Object, Where-Object, ...), or the line is a comment. Nothing that
        /// downloads, runs or decodes code (Rules.PsSus) and nothing that writes (Add-Content, Set-*, Remove-*, ...). Helpers paste such
        /// lines to look for a family's files: they name the family's paths without being the malware.
        /// </summary>
        internal static bool ReadOnlyCheck(string line)
        {
            var s = (line ?? "").Trim().TrimEnd('`').Trim();
            if (s.Length == 0) return false;
            if (s.StartsWith("#")) return true;
            if (PsSus.IsMatch(s) || s.Contains("$(") || s.Contains("& ") || s.StartsWith("&") || s.StartsWith(".")) return false;
            var parts = TopLevelParts(s);
            if (parts == null || parts.Count == 0 || !parts.All(p => ReadVerb.IsMatch(p.TrimStart('(', ' ')))) return false;
            // commands inside ( ) and { } too: Test-Path (iwr ...) runs iwr; quoted text ('Program Files (x86)') is no command.
            // A redirection (> file) writes; a method call ($_.Delete(), [IO.File]::WriteAllText(...)) can do anything.
            var unquoted = Regex.Replace(s, @"'[^']*'|""(?:`.|[^""`])*""", "''");
            if (unquoted.Contains(">") || MethodCall.IsMatch(unquoted)) return false;
            return Inner.Matches(unquoted).Cast<Match>().All(m => ReadVerb.IsMatch(m.Groups[1].Value));
        }

        static readonly Regex Inner = new Regex(@"[({]\s*([A-Za-z][\w-]*)", RegexOptions.CultureInvariant);
        static readonly Regex MethodCall = new Regex(@"(\.|::)\w+\s*\(", RegexOptions.CultureInvariant);

        /// <summary>
        /// (pure) The statements and pipeline parts of a PowerShell line, split at |, ;, &amp;&amp; and || outside quotes, braces,
        /// brackets and parentheses; a trailing # comment is dropped. null if quotes or brackets do not close.
        /// </summary>
        internal static List<string> TopLevelParts(string s)
        {
            var parts = new List<string>();
            var cur = new System.Text.StringBuilder();
            int depth = 0; char quote = '\0';
            for (int i = 0; i < s.Length; i++)
            {
                char ch = s[i];
                if (quote != '\0')
                {
                    cur.Append(ch);
                    if (ch == '`' && quote == '"' && i + 1 < s.Length) { cur.Append(s[++i]); continue; }
                    if (ch == quote) quote = '\0';
                    continue;
                }
                if (ch == '\'' || ch == '"') { quote = ch; cur.Append(ch); continue; }
                if (ch == '{' || ch == '(' || ch == '[') depth++;
                else if (ch == '}' || ch == ')' || ch == ']') { if (--depth < 0) return null; }
                else if (depth == 0 && ch == '#' && (i == 0 || char.IsWhiteSpace(s[i - 1]))) break;   // a comment to the end of the line
                else if (depth == 0 && (ch == '|' || ch == ';' || (ch == '&' && i + 1 < s.Length && s[i + 1] == '&')))
                {
                    if (i + 1 < s.Length && s[i + 1] == ch) i++;   // && and ||
                    var part = cur.ToString().Trim();
                    if (part.Length > 0) parts.Add(part);
                    cur.Clear();
                    continue;
                }
                cur.Append(ch);
            }
            if (quote != '\0' || depth != 0) return null;
            var last = cur.ToString().Trim();
            if (last.Length > 0) parts.Add(last);
            return parts;
        }
    }
}
