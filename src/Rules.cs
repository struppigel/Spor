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

        /// <summary>Strips the per-version part of WinSxS-like folder names so noise keys collapse.</summary>
        public static readonly Regex SxsVersion = new Regex(@"_[\d.]+_(X64|X86|ARM64|NEUTRAL)_+[A-Z0-9]+", O);

        public static readonly Regex DrivePath = new Regex(@"^([a-z]:)(\\.*)$", O);

        /// <summary>
        /// Well-known publishers: with the whitelist on, timeline lines of files with a VALID signature from one of these (and no flags)
        /// are hidden and only counted. Revoked/invalid/expired signatures are never hidden.
        /// </summary>
        public static readonly HashSet<string> TrustedSigners = new HashSet<string>(new[] {
            "Microsoft Windows", "Microsoft Corporation", "Microsoft Windows Publisher",
            "Microsoft 3rd Party Application Component", "Google LLC", "Mozilla Corporation", "Brave Software, Inc.", "Opera Norway AS", "Vivaldi Technologies AS",
            "Apple Inc.", "Adobe Inc.", "Intel Corporation", "Advanced Micro Devices, Inc.", "NVIDIA Corporation", "Realtek Semiconductor Corp.",
            "Valve Corp.", "Valve", "Epic Games Inc.", "Discord Inc.", "Zoom Video Communications, Inc.", "Zoom Communications, Inc.", "Spotify AB",
            "Dropbox, Inc", "Dropbox, Inc.", "GitHub, Inc.", "Docker Inc", 
            "Lenovo", "Dell Inc", "HP Inc.", "Logitech Inc", "Logitech", "Anthropic, PBC", "Slack Technologies, LLC", "Notion Labs, Inc."
        }, System.StringComparer.OrdinalIgnoreCase);

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
            foreach (Match m in Regex.Matches(args, @"(?<![\w])([a-z]:\\[^""<>|*?\r\n]+?)(?=""|,|\s+[-/]|\s*$)", RegexOptions.IgnoreCase))
            {
                var rel = m.Groups[1].Value.Substring(2);
                if (!InTrustedLocation(m.Groups[1].Value) && Regex.IsMatch(rel, @"\.(exe|dll|sys|scr|cpl|ocx|com|pif|drv|bat|cmd|ps1|psm1|vbs|vbe|js|jse|wsf|wsh|wsc|hta|sct|py|pyw|jar|msi|lnk|au3|a3x|ahk|tmp|dat|bin)$", RegexOptions.IgnoreCase)) return true;
            }
            return Regex.IsMatch(args, @"%(appdata|localappdata|temp|tmp|userprofile|public|programdata)%", RegexOptions.IgnoreCase);
        }

        public static string Fix(string s) => Bidi.Replace(s ?? "", "<RLO>");

        /// <summary>!RLO, !double-extension, !in-folder-named-like-file, !lolbin. name: also test this file name for LOLBins.</summary>
        public static List<string> Flags(string p, string name = null)
        {
            var f = new List<string>();
            p = p ?? "";
            if (Bidi.IsMatch(p)) f.Add("!RLO");
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

        /// <summary>Flags that go to the summary (a LOLBin run alone is normal on many PCs).</summary>
        public static List<string> Strong(List<string> f) => f.Where(x => x != "!lolbin").ToList();

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
            "!log-syntax-in-name = the path contains \" => \" or a status in brackets, made to look like log text"
        };
    }
}
