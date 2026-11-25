using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;

namespace Spor
{
    /// <summary>
    /// (pure) Reset and setup hooks: what Windows runs by itself after "Reset this PC" (C:\Recovery\OEM\ResetConfig.xml and the
    /// scripts it names), at the end of Setup (C:\Windows\Setup\Scripts\SetupComplete.cmd) and from an answer file (unattend.xml,
    /// autounattend.xml in Panther, Sysprep or the root of a drive). Malware puts its loader there to survive a reset or a clean
    /// install (WEEVILPROXY: a copy of its task, a .reg export of the task's TaskCache keys and a .cmd that restores them, run by
    /// ResetConfig.xml in BasicReset_AfterImageApply and FactoryReset_AfterImageApply; a hidden autounattend.xml with an encoded
    /// PowerShell command next to \sources\boot.wim on every drive). PC makers put legitimate scripts there too (AfterImageApply_*.cmd).
    /// The files come from untrusted disks: XML without DTDs and resolvers, text capped.
    /// </summary>
    static class ResetHooks
    {
        public const string HookFlag = "!reset-hook";
        public const string ConfigFlag = "!reset-config";

        /// <summary>The most text read from one hook file.</summary>
        public const int MaxText = 1024 * 1024;

        /// <summary>The most command lines shown per file.</summary>
        public const int MaxCommands = 5;

        /// <summary>An XML document from untrusted text: no DTD, no external entities, at most MaxText characters; null if malformed.</summary>
        public static XmlDocument Xml(string text)
        {
            if (string.IsNullOrWhiteSpace(text) || text.Length > MaxText) return null;
            var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = MaxText * 2L };
            try
            {
                var doc = new XmlDocument { XmlResolver = null };
                using (var r = XmlReader.Create(new StringReader(text), settings)) doc.Load(r);
                return doc;
            }
            catch (Exception) { return null; }
        }

        /// <summary>(phase, path) of each Run element of a ResetConfig.xml ("BasicReset_AfterImageApply", "C:\Recovery\OEM\x.cmd").</summary>
        public static List<(string Phase, string Path)> ResetRuns(string text)
        {
            var res = new List<(string, string)>();
            var doc = Xml(text);
            if (doc == null) return res;
            foreach (XmlNode run in doc.GetElementsByTagName("Run"))
            {
                var phase = run.Attributes?["Phase"]?.Value ?? "";
                var path = run.SelectNodes("*").Cast<XmlNode>().FirstOrDefault(n => n.LocalName == "Path")?.InnerText?.Trim() ?? "";
                if (phase.Length > 0 || path.Length > 0) res.Add((phase, path));
            }
            return res;
        }

        /// <summary>Lines that do nothing: comments, "@echo off", batch labels (":START"), setlocal / endlocal.</summary>
        static readonly Regex Comment = new Regex(@"^\s*(@?rem\b|::|#|@?echo\s+(off|on)\s*$|;|:[A-Za-z_][\w.-]*\s*$|@?(setlocal|endlocal)\b)", Util.RX);

        /// <summary>The lines of a script that act: no comments, no blank lines, no "@echo off", no labels.</summary>
        public static List<string> Commands(string text) =>
            Regex.Split(text ?? "", "\r?\n").Select(l => l.Trim()).Where(l => l.Length > 0 && !Comment.IsMatch(l)).ToList();

        /// <summary>(pure) The commands in the order shown: those that give a reason (Reasons) first, the rest as written.</summary>
        public static List<string> ShowOrder(IEnumerable<string> commands) =>
            (commands ?? Enumerable.Empty<string>()).Select((x, i) => (x, i)).OrderBy(p => Reasons(new[] { p.x }).Count > 0 ? 0 : 1).ThenBy(p => p.i).Select(p => p.x).ToList();

        static readonly Regex RegKey = new Regex(@"^\s*\[-?(HKEY_[A-Z_]+\\[^\]\r\n]{1,400})\]", RegexOptions.Multiline | RegexOptions.CultureInvariant);

        /// <summary>The keys a .reg file writes ("HKEY_LOCAL_MACHINE\SOFTWARE\...\TaskCache\Tree\x").</summary>
        public static List<string> RegKeys(string text) => RegKey.Matches(text ?? "").Cast<Match>().Select(m => m.Groups[1].Value).Distinct().ToList();

        /// <summary>A scheduled task's XML ("&lt;Task ... xmlns=.../windows/2004/02/mit/task"): a copy kept to be restored.</summary>
        public static bool IsTaskXml(string text) =>
            (text ?? "").IndexOf("schemas.microsoft.com/windows/2004/02/mit/task", StringComparison.OrdinalIgnoreCase) >= 0;

        /// <summary>The commands of an answer file: (where, command line) of RunSynchronousCommand, RunAsynchronousCommand,
        /// FirstLogonCommands / LogonCommands SynchronousCommand; autoLogonPassword: an AutoLogon password is set (never shown).</summary>
        public static List<(string Kind, string Command)> AnswerCommands(string text, out bool autoLogonPassword)
        {
            autoLogonPassword = false;
            var res = new List<(string, string)>();
            var doc = Xml(text);
            if (doc == null) return res;
            foreach (XmlNode n in doc.GetElementsByTagName("*"))
            {
                if (n.LocalName != "CommandLine" && n.LocalName != "Path") continue;
                var parent = n.ParentNode?.LocalName ?? "";
                var grand = n.ParentNode?.ParentNode?.LocalName ?? "";
                if (parent != "RunSynchronousCommand" && parent != "RunAsynchronousCommand" && parent != "SynchronousCommand") continue;
                var kind = grand.Length > 0 && parent == "SynchronousCommand" ? grand : parent;   // FirstLogonCommands, LogonCommands
                var cmd = (n.InnerText ?? "").Trim();
                if (cmd.Length > 0) res.Add((kind, cmd));
            }
            foreach (XmlNode n in doc.GetElementsByTagName("*"))
                if (n.LocalName == "Password" && n.ParentNode?.LocalName == "AutoLogon" && (n.InnerText ?? "").Trim().Length > 0) autoLogonPassword = true;
            return res;
        }

        static readonly Regex Encoded = new Regex(@"(?:^|\s)[/-](?:ec|e|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)\s+[""']?([A-Za-z0-9+/=]{8,})", Util.RX);

        /// <summary>The PowerShell command a "-EncodedCommand &lt;base64&gt;" (any abbreviation) carries (UTF-16), at most 200 characters; null without one.</summary>
        public static string Decoded(string command)
        {
            // only PowerShell's switch ("setup.exe /e Settings1" is another program's), at least 16 Base64 characters, text that reads
            if (!PowerShell.IsMatch(command ?? "")) return null;
            var m = Encoded.Match(command ?? "");
            if (!m.Success) return null;
            var b64 = m.Groups[1].Value;
            if (b64.Length < 16 || b64.Length > MaxText) return null;
            try
            {
                var text = Encoding.Unicode.GetString(Convert.FromBase64String(b64.PadRight((b64.Length + 3) / 4 * 4, '=')));
                if (text.Length == 0 || text.Count(ch => ch >= ' ' && ch < 0x7F || ch == '\t' || ch == '\r' || ch == '\n') < text.Length * 0.9) return null;
                text = Regex.Replace(text, @"\s+", " ").Trim();
                return text.Length > 200 ? text.Substring(0, 200) + "…" : text;
            }
            catch (FormatException) { return null; }
        }

        static readonly Regex PowerShell = new Regex(@"\b(powershell|pwsh)(\.exe)?\b", Util.RX);

        /// <summary>Paths into C:\Recovery\OEM itself: a reset script running the PC maker's own files there is no reason.</summary>
        static readonly Regex OwnFolder = new Regex(@"""?[A-Za-z]:\\Recovery\\OEM\\[^""\r\n]*""?", Util.RX);

        /// <summary>(text, more than max) of the start of a file: a hook padded beyond the limit keeps its commands at the top.</summary>
        public static (string Text, bool TooBig) Head(string path, int max = MaxText)
        {
            using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            {
                var b = new byte[(int)Math.Min(fs.Length, max)];
                int r = 0;
                while (r < b.Length) { int k = fs.Read(b, r, b.Length - r); if (k <= 0) break; r += k; }
                bool utf16 = r >= 2 && ((b[0] == 0xFF && b[1] == 0xFE) || (r >= 4 && b[1] == 0 && b[3] == 0));
                var text = (utf16 ? Encoding.Unicode.GetString(b, 0, r) : Encoding.UTF8.GetString(b, 0, r)).TrimStart('\uFEFF');
                return (text, fs.Length > max);
            }
        }

        /// <summary>
        /// Commands or registry text that bring a scheduled task back after a reset (its file in System32\Tasks, its TaskCache keys,
        /// schtasks /create, Register-ScheduledTask) or the old machine ID. Not "reg import" by itself: PC makers restore their settings so.
        /// </summary>
        static readonly Regex Restores = new Regex(@"\\System32\\Tasks\\|\bschtasks(\.exe)?\s+/create\b|\\TaskCache\\|OldMachineGuid|Register-ScheduledTask", Util.RX);

        /// <summary>(pure) A .reg file that writes a scheduled task's TaskCache keys or the old machine ID (not a PC maker's settings).</summary>
        public static bool RestoresTask(string regText) => Restores.IsMatch(regText ?? "");

        /// <summary>
        /// (pure) The reasons a hook runs code or restores something (empty: none): a command that downloads or runs code (Rules.PsSus,
        /// Rules.ArgsRunCode), an encoded command, one that writes a task or registry values back.
        /// </summary>
        public static List<string> Reasons(IEnumerable<string> commands)
        {
            var r = new List<string>();
            foreach (var c in commands ?? Enumerable.Empty<string>())
            {
                if (Decoded(c) != null && !r.Contains("encoded command")) r.Add("encoded command");
                // what the line's program is given (not the program itself), the PC maker's own files in C:\Recovery\OEM left out
                var args = Cmd.Args(c, _ => false);
                if (args.Length == 0)   // "powershell -File x.ps1": a program named without a path or .exe
                {
                    int sp = c.IndexOfAny(new[] { ' ', '\t' });
                    args = sp > 0 ? c.Substring(sp + 1) : "";
                }
                args = OwnFolder.Replace(args, " ");
                if ((Rules.PsSus.IsMatch(c) || Rules.ArgsRunCode(args)) && !r.Contains("runs code")) r.Add("runs code");
                if (Restores.IsMatch(c) && !r.Contains("restores a scheduled task or the machine ID")) r.Add("restores a scheduled task or the machine ID");
            }
            return r;
        }
    }
}
