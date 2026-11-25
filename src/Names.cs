using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

namespace Spor
{
    /// <summary>
    /// File names: random-looking names, lure names, and a signed program under a name not its own (!renamed-program).
    /// Conservative on purpose: a name with separators, a dictionary word or normal CamelCase words is never random.
    /// </summary>
    static class Names
    {
        public const string RenamedFlag = "!renamed-program";

        /// <summary>Words that make a name a real name, not a random one (lower case, at least 4 letters; matched anywhere in the name).</summary>
        static readonly string[] Known =
        {
            "setup", "install", "update", "launch", "client", "helper", "service", "player", "viewer", "manager", "tool", "driver", "game",
            "chrome", "edge", "firefox", "discord", "steam", "java", "python", "node", "micro", "windows", "google", "adobe", "office",
            "event", "emit", "host", "server", "agent", "start", "run", "main", "core", "app", "data", "file", "sync", "cloud", "update",
            "studio", "code", "debug", "test", "demo", "free", "zoom", "team", "word", "excel", "reader", "convert", "editor", "crash",
        };

        /// <summary>Words of lure names: documents, archives, installers and cracks.</summary>
        static readonly string[] Lure =
        {
            "invoice", "setup", "install", "update", "crack", "keygen", "document", "scan", "payment", "receipt", "order", "statement",
            "contract", "resume", "password", "patch", "activat", "bill", "salary", "bonus", "urgent", "delivery", "shipping", "photo",
            "img", "report", "agreement", "quotation", "proposal", "transfer", "remittance",
        };

        static readonly Regex CopySuffix = new Regex(@"(\s*\(\d{1,3}\)|[-_]\d{1,2}|\s+-\s+copy)$", Util.RX);
        static readonly Regex Tokens = new Regex(@"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+", RegexOptions.CultureInvariant);

        /// <summary>The name without folder, extension and copy suffix (" (1)", "-1", "_1", " - Copy").</summary>
        public static string Base(string name)
        {
            if (string.IsNullOrWhiteSpace(name)) return "";
            name = name.Trim().Replace('/', '\\');
            name = name.Substring(name.LastIndexOf('\\') + 1);
            var dot = name.LastIndexOf('.');
            if (dot > 0) name = name.Substring(0, dot);
            return CopySuffix.Replace(name, "").Trim();
        }

        /// <summary>
        /// Points for a random-looking name (higher = more random); 0 when it cannot be random: not 6-20 letters and digits only,
        /// or a known word in it. Signals: short CamelCase pieces ("ISW", "Wl", "PN"), few vowels, digits between letters, many case flips.
        /// </summary>
        public static int RandomScore(string name)
        {
            var n = Base(name);
            if (n.Length < 6 || n.Length > 20 || !n.All(char.IsLetterOrDigit) || n.Any(ch => ch > 127)) return 0;
            var lower = n.ToLowerInvariant();
            if (Known.Any(w => lower.Contains(w))) return 0;
            int score = 0;
            var tokens = Tokens.Matches(n).Cast<Match>().Select(m => m.Value).ToList();
            if (tokens.Count(t => char.IsLetter(t[0]) && t.Length <= 2) >= 2) score += 2;
            var letters = n.Where(char.IsLetter).ToList();
            if (letters.Count >= 5 && letters.Count(ch => "aeiouAEIOU".IndexOf(ch) >= 0) < letters.Count * 0.25) score += 1;
            score += Math.Min(2, Regex.Matches(n, @"(?<=[A-Za-z])\d+(?=[A-Za-z])").Count);
            int flips = 0;
            for (int i = 1; i < n.Length; i++)
                if (char.IsLetter(n[i - 1]) && char.IsLetter(n[i]) && char.IsUpper(n[i - 1]) != char.IsUpper(n[i])) flips++;
            if (flips >= 4) score += 1;
            return score;
        }

        public static bool IsRandom(string name) => RandomScore(name) >= 3;

        static readonly Regex Hex = new Regex(@"^[0-9A-F]+$", Util.RX);

        /// <summary>
        /// A folder of the path (not the file name) with a random-looking name (IsRandom), e.g. AppData\Local\Z0533B4Lo\MVg4zIU\clip\
        /// where a sideload kit put a validly signed host. Hex names (build ids such as VS Code's 2C33B50B16, hashes) do not count.
        /// </summary>
        public static bool RandomFolder(string path)
        {
            var parts = (path ?? "").Replace('/', '\\').Split('\\');
            for (int i = 1; i < parts.Length - 1; i++)   // parts[0] is the drive, the last part the file
                if (!Hex.IsMatch(parts[i]) && RandomScore(parts[i] + ".x") >= 3) return true;   // ".x": Base strips an extension, keep dots in the name
            return false;
        }

        public static bool IsLure(string name)
        {
            var lower = Base(name).ToLowerInvariant();
            return lower.Length > 0 && Lure.Any(w => lower.Contains(w));
        }

        /// <summary>
        /// The name a program was built under: the version resource's OriginalFilename, else InternalName, else the PDB file name.
        /// </summary>
        public static string Original(string originalName, string internalName, string pdb)
        {
            foreach (var x in new[] { originalName, internalName, pdb })
                if (Base(x).Length > 0) return x.Trim();
            return null;
        }

        /// <summary>
        /// !renamed-program (pure): the file name differs from the name the program was built under, and it is random-looking or a lure
        /// name (a document, setup or crack word that the original name does not have). One name inside the other (npp.8.6.Installer.x64
        /// for npp) is the same program, not renamed.
        /// </summary>
        public static bool RenamedProgram(string fileName, string originalName, string internalName, string pdb)
        {
            var orig = Base(Original(originalName, internalName, pdb));
            var file = Base(fileName);
            if (orig.Length == 0 || file.Length == 0 || file.Equals(orig, StringComparison.OrdinalIgnoreCase)) return false;
            var fl = file.ToLowerInvariant(); var ol = orig.ToLowerInvariant();
            if ((ol.Length >= 3 && fl.Contains(ol)) || (fl.Length >= 3 && ol.Contains(fl))) return false;
            return IsRandom(file) || (IsLure(file) && !IsLure(orig));
        }

        public const string RenamedPersistedFlag = "!renamed-persisted";

        /// <summary>
        /// (pure) A program started by persistence that is a signed program under another name, in a random-looking folder of a user
        /// profile or ProgramData: a loader's signed decoy (S_Pipe.exe = Adobe's Setup.exe in C:\Users\x\kgw7Hp\kOsW3u0gxT\clip\).
        /// The name differs from the original (not one inside the other) and a folder below the profile / ProgramData is random-looking
        /// (Squirrel's Update.exe in AppData\Local\Discord is not).
        /// </summary>
        public static bool RenamedPersisted(string path, string originalName, string internalName, string pdb)
        {
            var orig = Base(Original(originalName, internalName, pdb));
            var file = Base(Path.GetFileName(path ?? ""));
            if (orig.Length == 0 || file.Length == 0 || file.Equals(orig, StringComparison.OrdinalIgnoreCase)) return false;
            var fl = file.ToLowerInvariant(); var ol = orig.ToLowerInvariant();
            if ((ol.Length >= 3 && fl.Contains(ol)) || (fl.Length >= 3 && ol.Contains(fl))) return false;
            var m = System.Text.RegularExpressions.Regex.Match(path ?? "", @"^[A-Za-z]:\\(?:Users\\[^\\]+|ProgramData)\\(.+)\\[^\\]+$",
                                                                 System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            return m.Success && m.Groups[1].Value.Split('\\').Any(IsRandom);
        }

        /// <summary>RenamedPersisted for a program on disk (validly signed .exe), cached with the other name checks.</summary>
        public static bool RenamedPersisted(Ctx c, string path)
        {
            if (string.IsNullOrEmpty(path) || !path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) || !Rules.DrivePath.IsMatch(path)) return false;
            try
            {
                if (!File.Exists(path) || Rules.InTrustedLocation(path) || !Signature.Check(path).Valid) return false;
                var (orig, intern) = Signature.Names(path);
                var pdb = orig == null && intern == null ? Pe.Read(path).Pdb : null;
                return RenamedPersisted(path, orig, intern, pdb);
            }
            catch { return false; }
        }

        /// <summary>"original name X" from the version resource, else the PDB file name without ".pdb" ("original name EventEmitter (from the PDB path)").</summary>
        public static string OriginalNameText(string original, string internalName, string pdb) =>
            "original name " + (original ?? internalName ?? Path.GetFileNameWithoutExtension(pdb.Replace('/', '\\')) + " (from the PDB path)");

        /// <summary>
        /// The hint for a program on disk: validly signed, outside Windows and Program Files, renamed (see RenamedProgram). Null if not.
        /// Detail for its line: "original name X" (from the version resource or the PDB path).
        /// </summary>
        public static string RenamedDetail(Ctx c, string path)
        {
            if (string.IsNullOrEmpty(path) || !path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) || !Rules.DrivePath.IsMatch(path)) return null;
            if (c.Renamed.TryGetValue(path, out var d)) return d;
            d = null;
            try
            {
                if (File.Exists(path) && !Rules.InTrustedLocation(path) && Signature.Check(path).Valid)
                {
                    var (orig, intern) = Signature.Names(path);
                    var pdb = orig == null && intern == null ? Pe.Read(path).Pdb : null;
                    if (RenamedProgram(Path.GetFileName(path), orig, intern, pdb))
                        d = OriginalNameText(orig, intern, pdb);
                }
            }
            catch { }
            return c.Renamed[path] = d;
        }
    }
}
