using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace Spor
{
    /// <summary>
    /// Rules shared by all modules. Paths are matched without the drive letter ("\WINDOWS\...") unless noted.
    /// Whitelisting = Trusted locations, known-noise locations (per module), Windows servicing and inbox/Microsoft drivers.
    /// With -nowhitelist none of these hide anything; flags (!lolbin, !double-extension, ...) work the same either way.
    /// </summary>
    static class Rules
    {
        const RegexOptions O = Util.RX;

        public static bool Whitelist = true;

        /// <summary>User's own noise regex (-noise), appended to each module's noise list.</summary>
        public static string ExtraNoise = "";

        public static Regex Noise(string moduleNoise) =>
            new Regex(string.IsNullOrEmpty(ExtraNoise) ? moduleNoise : moduleNoise + "|" + ExtraNoise, O);

        /// <summary>Windows, Program Files, Windows upgrade/WinRE servicing folders, Defender platform.</summary>
        /// <remarks>Only on the system drive (see InTrustedLocation): users can create D:\Windows or D:\Program Files on other drives.
        /// $WINDOWS.~BT, $WINDOWS.~WS and $WinREAgent are not here: any user can create folders in C:\.</remarks>
        public static readonly Regex Trusted = new Regex(
            @"^\\(WINDOWS|PROGRAM FILES|PROGRAM FILES \(X86\)|PROGRAMDATA\\MICROSOFT\\WINDOWS DEFENDER\\PLATFORM)\\", O);

        /// <summary>Inside trusted folders, but where malware likes to sit.</summary>
        /// <remarks>Includes the folders inside Windows that normal users can write to (known from AppLocker bypasses).</remarks>
        public static readonly Regex Risky = new Regex(
            @"^\\WINDOWS\\(TEMP|TASKS|DEBUG|TRACING|SYSTEMTEMP|REGISTRATION\\CRMLOG|PLA\\(REPORTS|RULES|TEMPLATES)|SERVICEPROFILES\\[^\\]+\\APPDATA)\\" +
            @"|^\\WINDOWS\\(SYSTEM32|SYSWOW64)\\(TASKS|TASKS_MIGRATED|COM\\DMP|FXSTMP|SPOOL\\(DRIVERS\\COLOR|PRINTERS|SERVERS)|MICROSOFT\\CRYPTO\\RSA\\MACHINEKEYS|LOGFILES|WDI\\LOGFILES)\\" +
            @"|\\STARTUP\\", O);

        /// <summary>The system drive ("C:"); Windows and Program Files only count there.</summary>
        public static readonly string SystemDrive = (System.Environment.GetEnvironmentVariable("SystemDrive") ?? "C:").TrimEnd('\\');

        /// <summary>A full path in Windows / Program Files on the system drive, not in one of their user-writable folders.</summary>
        public static bool InTrustedLocation(string p)
        {
            var m = DrivePath.Match(p ?? "");
            return m.Success && m.Groups[1].Value.Equals(SystemDrive, System.StringComparison.OrdinalIgnoreCase)
                   && Trusted.IsMatch(m.Groups[2].Value) && !Risky.IsMatch(m.Groups[2].Value);
        }

        /// <summary>LOLBins: listed even in System32.</summary>
        public static readonly Regex Lol = new Regex(
            @"\\(REGASM|REGSVCS|MSBUILD|INSTALLUTIL|CSC|VBC|JSC|ADDINPROCESS(32)?|ASPNET_COMPILER|SCHTASKS|MSHTA|WSCRIPT|CSCRIPT|REGSVR32|RUNDLL32|CERTUTIL|CERTREQ|BITSADMIN|WMIC|POWERSHELL|POWERSHELL_ISE|PWSH|MSIEXEC|FORFILES|PCALUA|CMSTP|ODBCCONF|MSDT|HH|MAVINJECT|CONTROL|MSXSL|IEEXEC|PRESENTATIONHOST|SCRIPTRUNNER|SYNCAPPVPUBLISHINGSERVER|FINGER|EXTRAC32|EXPAND|DESKTOPIMGDOWNLOADER|WSL|BASH|CURL|INFDEFAULTINSTALL|REGINI|ATBROKER|DFSVC|MSCONFIG|WUAUCLT|XWIZARD|VERCLSID|CMD)\.EXE$", O);

        /// <summary>Path inside a folder named like a file, e.g. ab.exe\evil.dll or app.exe.local\x.dll.</summary>
        public static readonly Regex Disg = new Regex(@"\.(EXE|DLL|SCR|LOCAL)\\", O);

        /// <summary>Double extension, harmless then executable (name.pdf.exe, also padded with spaces).</summary>
        public static readonly Regex Dbl = new Regex(
            @"\.(PDF|DOCX?|DOTX?|XLSX?|XLSM|PPTX?|TXT|RTF|ODT|CSV|JPE?G|PNG|GIF|BMP|ICO|MP[34]|AVI|MKV|MOV|WAV|HTML?|INI|LOG)\s*\.(EXE|SCR|COM|BAT|CMD|PS1|VBS|VBE|JSE?|JSC|WSF|WSH|HTA|LNK|MSI|MSP|PIF|CPL|DLL|JAR|SCT|CHM|ISO|IMG)$", O);

        /// <summary>RTLO and other bidi override characters (shown as &lt;RLO&gt;).</summary>
        public static readonly Regex Bidi = new Regex("[\u202A-\u202E\u2066-\u2069]", O);

        /// <summary>
        /// Invisible or blank-looking characters (no-break and other spaces, zero-width characters, soft hyphen, Hangul fillers, the Braille
        /// blank, BOM, ...): names made of them look empty or like a normal name in Explorer. Shown as &lt;U+XXXX&gt;. Not the bidi
        /// characters (Bidi, shown as &lt;RLO&gt;).
        /// </summary>
        public static readonly Regex Invisible = new Regex(
            "[\u00A0\u00AD\u034F\u115F\u1160\u17B4\u17B5\u180E\u2000-\u200F\u2028\u2029\u202F\u205F-\u2064\u206A-\u206F\u2800\u3000\u3164\uFEFF\uFFA0\uFFF9-\uFFFB]", O);

        /// <summary>
        /// The invisible characters that never occur in normal names: zero-width space, word joiner and invisible operators, Hangul
        /// fillers, the Braille blank, BOM, Khmer / Mongolian invisible vowels and separators, interlinear annotation marks. Not the no-break
        /// space, ideographic space, zero-width (non-)joiner or the bidi marks: Persian, Japanese and web-page-titled names use them.
        /// Flagged !invisible-char everywhere; USB DRIVES flags every Invisible character.
        /// </summary>
        public static readonly Regex Hiding = new Regex("[ᅟᅠ឴឵᠎​⁠-⁤⠀ㅤ﻿ﾠ￹-￻]", O);

        /// <summary>A name hidden with characters: bidi override or characters that never occur in normal names (Hiding).</summary>
        public static bool OddChars(string s) => Bidi.IsMatch(s ?? "") || Hiding.IsMatch(s ?? "");

        /// <summary>Strips the per-version part of WinSxS-like folder names so noise keys collapse.</summary>
        public static readonly Regex SxsVersion = new Regex(@"_[\d.]+_(X64|X86|ARM64|NEUTRAL)_+[A-Z0-9]+", O);

        public static readonly Regex DrivePath = new Regex(@"^([a-z]:)(\\.*)$", O);

        /// <summary>
        /// Well-known publishers (resources/publishers.txt, or Spor.publishers.txt next to Spor.exe): with the whitelist on, timeline lines
        /// of files with a VALID signature from one of these (and no flags) are hidden and only counted; Electron apps they sign get no
        /// !runtime-loader check. Revoked/invalid/expired signatures never count.
        /// </summary>
        public static HashSet<string> TrustedSigners => trusted ?? (trusted = Util.DataFile(PublishersFile, ParsePublishers, out publishersSource));
        static HashSet<string> trusted;
        static string publishersSource;
        public const string PublishersFile = "Spor.publishers.txt";

        /// <summary>Where the publisher list comes from when it is not the built-in one (the override file's path), else null.</summary>
        public static string PublishersSource { get { var _ = TrustedSigners; return publishersSource; } }

        /// <summary>(pure) The signers of a publishers file: the first tab-separated column of each line; '#' lines are comments.</summary>
        internal static HashSet<string> ParsePublishers(string text)
        {
            var set = new HashSet<string>(System.StringComparer.OrdinalIgnoreCase);
            foreach (var raw in (text ?? "").Split('\n'))
            {
                var line = raw.TrimEnd('\r');
                if (line.TrimStart().StartsWith("#")) continue;
                var signer = line.Split('\t')[0].Trim();
                if (signer.Length > 0) set.Add(signer);
            }
            return set;
        }

        /// <summary>
        /// Defender definition update packages that Windows Update downloads and runs: C:\Windows\SoftwareDistribution\Download\Install\AM_Delta_Patch_1.2.3.4.exe.
        /// Only SYSTEM can write there, and they delete themselves, so a signature cannot be checked. Exact name and folder on the system drive.
        /// </summary>
        public static bool DefenderUpdate(string p) =>
            Regex.IsMatch(p ?? "", @"^([A-Z]:)\\WINDOWS\\SOFTWAREDISTRIBUTION\\DOWNLOAD\\INSTALL\\AM_DELTA_PATCH_\d+(\.\d+){3}\.EXE$", O)
            && p.Substring(0, 2).Equals(SystemDrive, System.StringComparison.OrdinalIgnoreCase);

        /// <summary>Interpreters and script hosts: signed by their publishers, but malware runs its scripts with them. Never hidden by signer.</summary>
        public static readonly Regex Interpreter = new Regex(
            @"\\(PYTHONW?|PYTHON3[\d.]*W?|PY|PYW|NODE|JAVAW?|JAVAWS|AUTOIT3(_X64)?|AUTOHOTKEY(U?(32|64))?|AUTOHOTKEY64|PERL|RUBYW?|PHP(-CGI)?|PWSH|BUN|DENO|TCLSH\d*|WISH\d*|LUAJIT|LUA\d*)\.EXE$", O);

        /// <summary>
        /// User-writable places where droppers put a signed decoy exe next to a malicious DLL (sideloading). Files there are never hidden by signer.
        /// Installed software lives deeper in AppData (AppData\Local\Programs\X\x.exe); the top two levels count as drop locations.
        /// </summary>
        public static bool DropLocation(string p)
        {
            var u = (p ?? "").ToUpperInvariant();
            if (Regex.IsMatch(u, @"\\(TEMP|TMP|DOWNLOADS|DESKTOP|USERS\\PUBLIC|PERFLOGS|RECYCLE\.BIN|\$RECYCLE\.BIN)\\") || u.Contains(@"\APPDATA\LOCAL\TEMP\")) return true;
            var m = Regex.Match(u, @"\\APPDATA\\(LOCAL|ROAMING|LOCALLOW)\\(.*)$");
            if (m.Success) return m.Groups[2].Value.Count(ch => ch == '\\') < 2;   // AppData\Roaming\x.exe or AppData\Roaming\Folder\x.exe
            m = Regex.Match(u, @"^[A-Z]:\\PROGRAMDATA\\(.*)$");
            if (m.Success) return m.Groups[1].Value.Count(ch => ch == '\\') < 2;
            return Regex.IsMatch(u, @"^[A-Z]:\\[^\\]+$");   // root of a drive
        }

        /// <summary>
        /// Arguments that make a trusted program untrusted: a file outside Windows/Program Files (or in Windows\Temp, Tasks, ...),
        /// a network path or URL, a script, encoded or hidden PowerShell. E.g. rundll32.exe C:\Users\x\AppData\evil.dll,Start.
        /// </summary>
        public static bool ArgsSuspicious(string args)
        {
            if (string.IsNullOrWhiteSpace(args)) return false;
            if (Regex.IsMatch(args, @"\\\\[^\\\s]+\\|https?://|ftp://|\.(ps1|psm1|vbs|vbe|js|jse|wsf|wsh|hta|bat|cmd|sct|py|pyw|au3|a3x|ahk|jar|scr|cpl|lnk|msi)\b|\s[-/]e(nc|ncodedcommand)?\s|frombase64|-w(indowstyle)?\s+h|iex\b|downloadstring|\bmshta\b", RegexOptions.IgnoreCase))
                return true;
            // a program or library outside Windows / Program Files (data paths like log files and folders are normal arguments)
            foreach (Match m in ArgPath.Matches(args))
            {
                var rel = m.Groups[1].Value.Substring(2);
                if (!InTrustedLocation(m.Groups[1].Value) && Regex.IsMatch(rel, @"\.(exe|dll|sys|scr|cpl|ocx|com|pif|drv|bat|cmd|ps1|psm1|vbs|vbe|js|jse|wsf|wsh|wsc|hta|sct|py|pyw|jar|msi|lnk|au3|a3x|ahk|tmp|dat|bin)$", RegexOptions.IgnoreCase)) return true;
            }
            return Regex.IsMatch(args, @"%(appdata|localappdata|temp|tmp|userprofile|public|programdata)%", RegexOptions.IgnoreCase);
        }

        /// <summary>
        /// A drive path in arguments (group 1): up to a quote, a comma, the next option, a blank after a program or script name
        /// ("C:\x\a.exe arg1": the program, not its arguments) or the end.
        /// </summary>
        static readonly Regex ArgPath = new Regex(
            @"(?<![\w])([a-z]:\\[^""<>|*?\r\n]+?)(?=""|,|\s+[-/]|\s*$|(?<=\.(?:exe|com|scr|pif|cpl|dll|msi|bat|cmd|ps1|vbs|vbe|js|jse|wsf|hta|py|pyw|jar))\s)",
            RegexOptions.IgnoreCase);

        /// <summary>cmd's "/c call &lt;target&gt;" (group 1 quoted, group 2 bare): what call runs.</summary>
        static readonly Regex CmdCallTarget = new Regex(@"[/-]c\s+""?call\s+(?:""([^""]+)""|(\S+))", RegexOptions.IgnoreCase);

        /// <summary>
        /// (pure) A launcher's target that runs as a process of its own: a program, or a script another program runs (wscript,
        /// powershell, mshta, ...). Not a batch file run by cmd itself (cmd /c call build.bat starts no process).
        /// </summary>
        public static bool LaunchesProcess(string launcher, string target)
        {
            if (Regex.IsMatch(target ?? "", @"\.(exe|com|scr|pif)$", O)) return true;
            if (Regex.IsMatch(target ?? "", @"\.(bat|cmd)$", O)) return !(launcher ?? "").EndsWith("\\cmd.exe", System.StringComparison.OrdinalIgnoreCase);
            return Modules.Files.Script.IsMatch(target ?? "");
        }

        /// <summary>Programs, scripts and shortcuts: the files SmartScreen and the "open file" warning check for Mark of the Web.</summary>
        public static bool ProgramFile(string p) =>
            Modules.Files.Exec.IsMatch(p ?? "") || Modules.Files.Script.IsMatch(p ?? "") || Regex.IsMatch(p ?? "", @"\.(lnk|url)$", O);

        /// <summary>
        /// !motw-removed: a new program, script or shortcut in a drop location whose Zone.Identifier says zone 0-2 (this computer, intranet,
        /// trusted) and has no URL. Browsers and Windows write zone 3/4 with a URL for internet files; droppers and some archive tools write a
        /// low zone on purpose to turn off SmartScreen and the download warnings. A missing stream is not a signal: most local files have none.
        /// </summary>
        public static bool MotwRemoved(string p, Zone z) =>
            z != null && z.Id.HasValue && z.Id.Value >= 0 && z.Id.Value <= 2 && !z.HasUrl && ProgramFile(p) && DropLocation(p);

        /// <summary>
        /// The script runtime a program ships with, from files next to or below it (relPaths: relative to the program's folder, at most two
        /// folders deep): "Ren'Py (Python)", "Python", "AutoIt", "Node.js", "Electron", "Java", "Lua"; null for none. Malware ships a legitimate
        /// runtime and keeps its code in data files, so the launcher's signature says nothing. Interpreters themselves (python.exe, ...) are
        /// not launchers: they are never hidden anyway (Interpreter).
        /// </summary>
        public static string ScriptRuntime(string exePath, IEnumerable<string> relPaths)
        {
            if (string.IsNullOrEmpty(exePath) || Interpreter.IsMatch(exePath)) return null;
            var rel = relPaths.Select(r => r.Replace('/', '\\').TrimStart('\\')).Where(r => r.Count(ch => ch == '\\') <= 2).ToList();
            bool Has(string rx) => rel.Any(r => Regex.IsMatch(r, rx, O));
            if (Has(@"(^|\\)librenpython[^\\]*\.dll$")) return "Ren'Py (Python)";
            if (Has(@"(^|\\)(python3[\d]*|libpython3[\d.]*)\.dll$") && Has(@"^(lib|renpy)\\|(^|\\)base_library\.zip$")) return "Python";
            if (Has(@"(^|\\)autoit3[^\\]*\.exe$") || Has(@"^[^\\]+\.a3x$")) return "AutoIt";
            if (Has(@"(^|\\)node\.exe$")) return "Node.js";
            if (Has(@"^resources\\app\.asar$")) return "Electron";
            if (Has(@"(^|\\)jre\\bin\\javaw?\.exe$") || Has(@"(^|\\)jvm\.dll$")) return "Java";
            if (Has(@"(^|\\)lua(jit)?[\d.]*\.dll$")) return "Lua";
            return null;
        }

        /// <summary>Files that hold a runtime's script code (compiled or packed): what a launcher really runs.</summary>
        public static readonly Regex ScriptContainer = new Regex(@"\.(rpa|rpyc|pyc|pyz|a3x|au3|asar|jar|js)$", O);

        /// <summary>Folders of the runtime itself (its standard library), not the app's scripts.</summary>
        public static readonly Regex RuntimeLibFolder = new Regex(@"(^|\\)(renpy|lib|__pycache__|node_modules|jre|site-packages|locales)\\", O);

        /// <summary>
        /// Proxy-execution launchers: Windows programs that start another program for the caller, so the real parent is hidden and
        /// some application-control rules are bypassed. Name of the launcher, and its arguments that start a program.
        /// </summary>
        public static readonly (string Name, Regex Args)[] ProxyLaunchers =
        {
            ("forfiles.exe", new Regex(@"(^|\s)[/-]c(\s|$)", O)),
            ("pcalua.exe", new Regex(@"(^|\s)-a(\s|$)", O)),
            ("conhost.exe", new Regex(@"--headless", O)),
            ("explorer.exe", new Regex(@"(^|[\s""])([a-z]:\\|\\\\)", O)),        // explorer.exe "C:\...\x.exe" (the shell itself has no path argument)
            ("cmd.exe", new Regex(@"[/-]c\s+""?call\s", O)),
            ("rundll32.exe", new Regex(@"url\.dll\s*,\s*(FileProtocolHandler|OpenURL)", O)),
            ("scriptrunner.exe", new Regex(@"-appvscript", O)),
            ("wmic.exe", new Regex(@"process\s+call\s+create", O)),
            ("mshta.exe", new Regex(@"\S", O)),
        };

        /// <summary>
        /// !proxy-exec (pure): a launcher among a program's parents, with arguments that start a program, while the program runs from
        /// outside Windows and Program Files. launcherCommandLine is the whole command line (the program part is skipped).
        /// </summary>
        public static bool ProxyExec(string launcherPath, string launcherCommandLine, string childPath) =>
            DrivePath.IsMatch(childPath ?? "") && !InTrustedLocation(childPath) && ProxyLaunch(launcherPath, launcherCommandLine);

        /// <summary>(pure) A proxy-execution launcher (ProxyLaunchers) whose command line starts a program for someone else.</summary>
        public static bool ProxyLaunch(string launcherPath, string commandLine)
        {
            if (string.IsNullOrEmpty(launcherPath)) return false;
            var name = launcherPath.Substring(launcherPath.LastIndexOf('\\') + 1);
            var args = LauncherArgs(commandLine, name);
            return ProxyLaunchers.Any(l => l.Name.Equals(name, System.StringComparison.OrdinalIgnoreCase) && l.Args.IsMatch(args));
        }

        /// <summary>
        /// (pure) The first file or folder outside Windows and Program Files that a proxy-execution launcher (ProxyLaunch) is pointed at:
        /// forfiles /p &lt;folder in Temp&gt; /c ..., pcalua -a &lt;program in Downloads&gt;, conhost --headless &lt;path&gt;, cmd /c call &lt;program&gt;.
        /// For cmd only what call runs (the first token after it), not the arguments that program gets. Null if none. Not the shell
        /// (explorer.exe): its path arguments mostly open folders and documents ("show in folder"), and a program it starts is
        /// !proxy-exec on its own line.
        /// </summary>
        public static string ProxyLaunchTarget(string image, string commandLine)
        {
            if (!ProxyLaunch(image, commandLine) || image.EndsWith("\\explorer.exe", System.StringComparison.OrdinalIgnoreCase)) return null;
            var name = image.Substring(image.LastIndexOf('\\') + 1);
            var args = LauncherArgs(commandLine, name);
            if (name.Equals("cmd.exe", System.StringComparison.OrdinalIgnoreCase))
            {
                var m = CmdCallTarget.Match(args);
                var target = m.Success ? (m.Groups[1].Success ? m.Groups[1].Value : m.Groups[2].Value).Trim() : "";
                return DrivePath.IsMatch(target) && !InTrustedLocation(target) ? target : null;
            }
            foreach (Match m in ArgPath.Matches(args))
                if (!InTrustedLocation(m.Groups[1].Value)) return m.Groups[1].Value;
            return null;
        }

        /// <summary>
        /// A folder that many unrelated programs and downloads share: a profile's Downloads, Desktop, Documents, Temp, the roots of
        /// AppData, Public, ProgramData, Windows\Temp, a drive root. Files next to a program there do not belong to it.
        /// </summary>
        public static bool SharedFolder(string dir) =>
            Regex.IsMatch((dir ?? "").TrimEnd('\\'),
                @"^[a-z]:(\\users\\[^\\]+\\(downloads|desktop|documents|appdata\\(local|roaming|locallow)(\\temp)?)|\\users\\public(\\(downloads|desktop|documents))?|\\programdata|\\windows\\temp)?$", O);

        /// <summary>
        /// (pure) A process creation event (Security 4688, Sysmon 1) for the timeline: a proxy-execution launcher pointed at a path outside
        /// Windows and Program Files (ProxyLaunchTarget); or the program or its parent is a LOLBin or interpreter, and the command line
        /// is suspicious, it is proxy execution, or the program runs from outside Windows and Program Files.
        /// </summary>
        public static bool ProcessEventKept(string image, string parentImage, string commandLine, bool proxyExec)
        {
            bool Host(string p) => !string.IsNullOrEmpty(p) && (Lol.IsMatch(p) || Interpreter.IsMatch(p));
            if (string.IsNullOrEmpty(image)) return false;
            if (ProxyLaunchTarget(image, commandLine) != null) return true;
            if (!Host(image) && !Host(parentImage)) return false;
            return proxyExec || ArgsSuspicious(LauncherArgs(commandLine, image.Substring(image.LastIndexOf('\\') + 1)))
                   || (DrivePath.IsMatch(image) && !InTrustedLocation(image));
        }

        /// <summary>
        /// The arguments of a Windows program's command line: after the quoted program, else after its own name ("wmic process call
        /// create C:\x.exe": Cmd.Args would cut at the first ".exe" anywhere in the line). A command line that starts with an option
        /// has no program part (forfiles starts cmd with "/c call ...").
        /// </summary>
        static string LauncherArgs(string commandLine, string name)
        {
            var s = (commandLine ?? "").TrimStart();
            if (s.StartsWith("/") || s.StartsWith("-")) return s;
            if (s.StartsWith("\"")) { int e = s.IndexOf('"', 1); return e > 0 ? s.Substring(e + 1) : ""; }
            var stem = System.IO.Path.GetFileNameWithoutExtension(name);
            var m = Regex.Match(s, @"^\S*?" + Regex.Escape(stem) + @"(\.exe)?(?=\s|$)", O);
            if (m.Success) return s.Substring(m.Length);
            int sp = s.IndexOf(' ');
            return sp > 0 ? s.Substring(sp) : "";
        }

        /// <summary>For the log: bidi characters as &lt;RLO&gt;, invisible characters as &lt;U+XXXX&gt; (e.g. &lt;U+00A0&gt; for a no-break space).</summary>
        public static string Fix(string s) =>
            Invisible.Replace(Bidi.Replace(s ?? "", "<RLO>"), m => "<U+" + ((int)m.Value[0]).ToString("X4") + ">");

        public const string InvisibleFlag = "!invisible-char";

        /// <summary>!RLO, !invisible-char, !double-extension, !in-folder-named-like-file, !lolbin. name: also test this file name for LOLBins.</summary>
        public static List<string> Flags(string p, string name = null)
        {
            var f = new List<string>();
            p = p ?? "";
            if (Bidi.IsMatch(p)) f.Add("!RLO");
            if (Hiding.IsMatch(p)) f.Add(InvisibleFlag);
            if (Dbl.IsMatch(p)) f.Add("!double-extension");
            if (Disg.IsMatch(p)) f.Add("!in-folder-named-like-file");
            if (Lol.IsMatch(p) || (name != null && Lol.IsMatch("\\" + name))) f.Add("!lolbin");
            if (LogSyntax.IsMatch(p)) f.Add("!log-syntax-in-name");
            return f;
        }

        /// <summary>A name that imitates the log's own syntax (" => ", a status in brackets) to mislead a reader or a parser.</summary>
        public static readonly Regex LogSyntax = new Regex(@" => |\[(gone|no access|unsigned|invalid signature|revoked signature|expired signature|volume not mounted|valid)\]", O);

        public static string FlagText(List<string> f) => f != null && f.Count > 0 ? "  " + string.Join(" ", f) : "";

        /// <summary>Flags as a table field: "!a !b" or "-".</summary>
        public static string FlagCol(IEnumerable<string> f) { var s = f == null ? "" : string.Join(" ", f.Distinct()); return s.Length > 0 ? s : "-"; }

        /// <summary>
        /// Hints: weak flags. They go to the SUMMARY only together with a strong flag on the same file or in the same folder
        /// (a renamed signed program alone is often harmless; next to a side-loaded DLL it is the host).
        /// </summary>
        public static readonly HashSet<string> Hints = new HashSet<string> { "!renamed-program" };

        /// <summary>Flags that go to the summary (a LOLBin run alone is normal on many PCs; hints only with a strong flag).</summary>
        public static List<string> Strong(List<string> f) => f.Where(x => x != "!lolbin" && !Hints.Contains(x)).ToList();

        public static List<string> HintsOf(List<string> f) => f.Where(Hints.Contains).ToList();

        public static readonly string[] FlagLegend =
        {
            "!lolbin = Windows tool that malware likes to use (normal on many PCs)",
            "!double-extension = e.g. invoice.pdf.exe",
            "!in-folder-named-like-file = e.g. x.exe\\evil.dll",
            "!RLO = right-to-left override character in the name (shown as <RLO>)",
            "!renamed-lolbin = Windows tool under another name",
            "!unsigned = driver without a valid signature",
            "!outside-driver-folders = driver loaded from outside System32\\drivers and the DriverStore",
            "!suspicious = command that downloads or runs code",
            "!kept-despite-warning = the browser warned, the user kept the file",
            "!defender-off = Defender protection turned off",
            "!defender-exclusion = Defender exclusion added or changed",
            "!not-removed = Defender could not remove a detection",
            "!log-cleared = event log cleared",
            "!hidden-account = account hidden from the sign-in screen",
            "!timestomped = file timestamps probably faked",
            "!com-hijack = per-user COM registration overrides the machine one",
            "!from-web = Store/MSIX app installed from a web page (App Installer / ms-appinstaller link), a known malware delivery",
            "!log-syntax-in-name = the path contains \" => \" or a status in brackets, made to look like log text",
            "!motw-removed = a program wrote Zone.Identifier with ZoneId 0-2 (local/intranet/trusted) and no URL on a new program file, which turns off SmartScreen and download warnings",
            "!sideload = unsigned DLL next to a validly signed program that imports it (DLL side-loading); the line names the program and any proxy evidence",
            "!proxy-exec = started through a Windows program that launches programs for others (forfiles /c, pcalua -a, conhost --headless, cmd /c call, ...), from outside Windows and Program Files; on the launcher's own 4688/SYSMON line: pointed at a program outside them that runs as its own process (not a batch file cmd runs)",
            "!padded = new file inflated with one repeated byte against scanner and sandbox size limits: a program (its overlay) or data next to a new program",
            "!runtime-loader = new launcher of a script runtime (Python/Ren'Py, AutoIt, Node.js, Electron unless signed by a well-known publisher, Java, Lua) with loader signs in its folder: padded or encrypted random-named data, a hidden file next to its scripts, a program it started, or a !motw-removed file near a run",
            "!known-malware = matches a pattern of a known malware family (Autodetect, resources/autodetect.txt); the line names the family",
            "!renamed-program = hint: a signed program under a random-looking or lure name that is not its original name (in SUMMARY only with a strong flag nearby)",
            "!invisible-char = invisible character in the name, shown as <U+XXXX>: anywhere one never used in names (zero-width space, Hangul filler, Braille blank, ...); on USB drives any (also no-break space)",
            "!usb-worm-lnk = shortcut on a drive that starts a script host, cmd, rundll32 or a file in a hidden folder, has no normal target, or is named like the drive or a hidden folder (USB worm)",
            "!disguised-icon = shortcut to a program or script that shows a folder, document or drive icon",
            "!autorun = autorun.inf that starts something, or a MountPoints2 shell command",
            "!hidden-system = hidden and system item on a removable drive (not a Windows folder), e.g. a fake RECYCLER folder",
            "!clsid-folder = folder named x.{GUID} or with a desktop.ini that sets a CLSID: Explorer shows it as something else",
            "!ads = alternate data stream (other than Zone.Identifier) on a file of a drive",
            "!explorer-hiding = Explorer settings tampered so hidden files cannot be shown (SHOWALL CheckedValue, NoFolderOptions)"
        };
    }
}
