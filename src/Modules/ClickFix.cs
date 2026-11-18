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
        static readonly Regex Sus = new Regex(@"powershell|pwsh|mshta|curl|wget|bitsadmin|certutil|msiexec|rundll32|regsvr32|wscript|cscript|conhost|forfiles|cmd(\.exe)?[""' ]+/[ck]|\b(iwr|irm|iex)\b|invoke-(webrequest|restmethod|expression)|downloadstring|downloadfile|frombase64|\s-e(nc|ncodedcommand)?\s+[a-z0-9+/=]{20}|https?://|\\\\[^\\\s]+@(ssl|\d+)|davwwwroot|\\\\(?!(10|127)\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)\d{1,3}(\.\d{1,3}){3}\\|captcha|verif|robot|human|ray id|cloudflare|(\w\^){3,}", Util.RX);

        // PowerShell history: commands that download or run code, and common obfuscation (backticks in words, 'a'+'b', [char] codes,
        // reversed strings, gcm i*x, $pshome[4], any -EncodedCommand spelling, long Base64)
        static readonly Regex PsSus = new Regex(@"(?<![|(])\b(iex|irm|iwr)\b(?![|)])|invoke-(webrequest|restmethod|expression)|\.download(string|file|data)\s*\(|frombase64string\s*\(|net\.webclient|start-bitstransfer\s|\bbitsadmin(\.exe)?\s+/|certutil(\.exe)?\s.*-urlcache|\bmshta(\.exe)?\s+\S|(add|set)-mppreference|(curl|wget)(\.exe)?\s.*https?://|(^|\s)[/\p{Pd}]e[a-z]{0,13}\s+['""]?[a-z0-9+/=]{20}|(^|\s)[/\p{Pd}]w[a-z]{0,10}\s+h[a-z]*\b|\w`\w[^`]*\w`\w|['""][^'""\s]{1,8}['""]\s*\+\s*['""][^'""\s]{1,8}['""]|(\[char\]\s*(0x)?[0-9a-f]+.*){3}|\[\s*-1\s*\.\.\s*-?\d|\b(gcm|get-command|gal|get-alias)\s+[^\s|;]*\*|\$(env:\w+|pshome|shellid)\s*\[\s*\d|\$verbosepreference\.tostring\(\)\s*\[|\$executioncontext\.invokecommand|\[scriptblock\]::create|[a-z0-9+/]{100,}", Util.RX);

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
                            rt.Add(n == 1 ? Log.T(t) : "-", h.User, n.ToString(), sus ? "!suspicious" : "-", v);
                            if (n == 1) c.Event(t, "RUN", null, text: c.U(h.User) + "Run dialog: " + v, flags: sus ? new List<string> { "!suspicious" } : null);
                            if (sus) c.Find(n == 1 ? t : null, "Run dialog " + c.U(h.User) + v);
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
                            if (s) { bad++; c.Find(n == "url1" ? t : null, "Explorer address bar " + c.U(h.User) + v); }
                            if (s || !Rules.Whitelist) at.Add(n == "url1" ? Log.T(t) : "-", h.User, n, s ? "!suspicious" : "-", v);
                        }
                        if (all.Count > 0) counts.Add($"{h.User}: {all.Count} entries, {bad} suspicious");
                        if (bad > 0) c.Event(t, "ADR", null, text: c.U(h.User) + "Explorer address bar: newest entry typed", flags: new List<string> { "!suspicious" });
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
                        c.Out.Sub($"PowerShell console history: {c.U(p.User)}{Path.GetFileName(f)}",
                            $"{f}: {lines.Count} lines, {hits.Count} suspicious, last written {Log.T(t)} UTC.\n" +
                            "All suspicious lines, then the last " + tail + " lines. PowerShell never saves lines with password/token/apikey/secret,\n" +
                            "so attackers can keep a pasted command out: an empty or harmless history does not prove nothing was pasted.");
                        c.Event(t, "PSH", null, text: $"{c.U(p.User)}PowerShell history {Path.GetFileName(f)} written ({hits.Count} suspicious lines of {lines.Count})");
                        if (hits.Count > 0) c.Find(t, $"PowerShell history {c.U(p.User)}{Path.GetFileName(f)}: {hits.Count} suspicious lines");
                        var ht = new Table("@line", "[part", "<flags", "*command");
                        foreach (var i in hits) ht.Add((i + 1).ToString(), "suspicious", "!suspicious", lines[i].Trim());
                        for (int i = Math.Max(0, lines.Count - tail); i < lines.Count; i++)
                            ht.Add((i + 1).ToString(), "last", PsSus.IsMatch(lines[i]) ? "!suspicious" : "-", lines[i].TrimEnd());
                        ht.WriteTo(c.Out);
                    }
                    catch (Exception e) { c.Err.Add("PowerShell history " + f + ": " + e.Message); }
                }
            }
            if (!any) { c.Out.Sub("PowerShell console history"); c.Out.None(); }
        }
    }
}
