using System;
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

        /// <summary>-aggressive (command line only): records marked by Table.Aggr are hidden instead of marked. See Aggr.</summary>
        public static bool Aggressive;

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
            // the SYSTEM account's profile: malware running as SYSTEM drops there (PavinLoader: ...\systemprofile\...\INetCache)
            @"|^\\WINDOWS\\(SYSTEM32|SYSWOW64)\\CONFIG\\SYSTEMPROFILE\\APPDATA\\" +
            @"|\\STARTUP\\", O);

        /// <summary>
        /// Windows Update's download and install folder (full path). Its packages and cabinets keep the times they were built with
        /// (whole seconds, older than the download), and its staged updaters are gone after the update: whitelist, not timestomping.
        /// </summary>
        /// <remarks>Only on the system drive: users can create D:\Windows\SoftwareDistribution.</remarks>
        public static bool InWindowsUpdateFolder(string p) =>
            p != null && p.StartsWith(SystemDrive + @"\Windows\SoftwareDistribution\", System.StringComparison.OrdinalIgnoreCase);

        static Regex Staging => global::Spor.Whitelist.Staging;   // resources/whitelist.txt, scope "staging"

        /// <summary>
        /// Where updaters stage their packages and delete them afterwards (Edge / Brave / Google Update Install\{GUID}, Windows Update,
        /// WinSxS servicing): known noise, also when the file is gone and its signature cannot be checked any more. Only in Windows and
        /// Program Files on the system drive (only admins write there); C:\$WinREAgent is not here, any user can create folders in C:\.
        /// </summary>
        public static bool InUpdaterStaging(string p) => InTrustedLocation(p) && Staging.IsMatch(DrivePath.Match(p).Groups[2].Value);

        /// <summary>The staging folder of a path InUpdaterStaging is true for ("C:\Windows\SoftwareDistribution\"), else null.</summary>
        public static string StagingRoot(string p)
        {
            if (!InUpdaterStaging(p)) return null;
            var m = DrivePath.Match(p);
            return m.Groups[1].Value + Staging.Match(m.Groups[2].Value).Value;
        }

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

        /// <summary>
        /// LOLBins whose copies malware runs from its own folders (PavinLoader's MSBuild.exe next to a .wsf, RegAsm.exe, ...), by
        /// original name, and the folders where Windows, the .NET Framework and Visual Studio keep them (path without the drive).
        /// </summary>
        static readonly (Regex Name, Regex Home)[] LolbinHomes =
        {
            (new Regex(@"^MSBUILD\.EXE$", O),
             new Regex(@"^\\WINDOWS\\(MICROSOFT\.NET\\FRAMEWORK(64|ARM64)?\\|WINSXS\\)|^\\PROGRAM FILES( \(X86\))?\\(MICROSOFT VISUAL STUDIO|MSBUILD)\\", O)),
            (new Regex(@"^(INSTALLUTIL|REGASM|REGSVCS|ADDINPROCESS(32)?|ASPNET_COMPILER)\.EXE$", O),
             new Regex(@"^\\WINDOWS\\(MICROSOFT\.NET\\FRAMEWORK(64|ARM64)?\\|WINSXS\\)", O)),
            (new Regex(@"^(WSCRIPT|CSCRIPT|MSHTA)\.EXE$", O),
             new Regex(@"^\\WINDOWS\\(SYSTEM32|SYSWOW64|SYSARM32|WINSXS)\\", O)),
        };

        /// <summary>True for a name LolbinCopy checks (MSBuild.exe, RegAsm.exe, wscript.exe, ...), in any case.</summary>
        public static bool CopiedLolbin(string name) => LolbinHomes.Any(h => h.Name.IsMatch((name ?? "").Trim()));

        /// <summary>
        /// The Windows folders PavinLoader drops its project folders into: in a profile (also the SYSTEM account's), and ProgramData's
        /// Caches. The drops module sweeps them (Modules/Drops.cs).
        /// </summary>
        public static readonly Regex WindowsCache = new Regex(
            @"\\APPDATA\\LOCAL\\MICROSOFT\\WINDOWS\\(WEBCACHE|EXPLORER|CACHES|INETCACHE|NOTIFICATIONS)\\" +
            @"|\\APPDATA\\ROAMING\\MICROSOFT\\(PROTECT|CRYPTO|WINDOWS\\THEMES|WINDOWS\\LIBRARIES)\\|^[A-Z]:\\PROGRAMDATA\\MICROSOFT\\WINDOWS\\CACHES\\", O);

        public const string LolbinCopyFlag = "!lolbin-copy";

        /// <summary>
        /// (pure) A copy of a LOLBin outside its usual folders (LolbinHomes), found by its original name (version resource) or else its
        /// file name: "copy of MSBuild.exe outside its usual folders; invalid signature; hidden; in a Windows cache folder", or null.
        /// A validly signed copy in Windows or Program Files is no finding (Visual Studio, build tools, bundled SDKs). sig = the signature
        /// status ("valid", "invalid", "unsigned", ...; null when unknown, e.g. the file is gone).
        /// </summary>
        public static string LolbinCopy(string path, string originalName, string sig, bool hidden)
        {
            var m = DrivePath.Match(path ?? "");
            if (!m.Success) return null;
            var leaf = path.Substring(path.LastIndexOf('\\') + 1);
            var name = CopiedLolbin(originalName) ? originalName.Trim() : CopiedLolbin(leaf) ? leaf : null;
            if (name == null) return null;
            var home = LolbinHomes.First(h => h.Name.IsMatch(name)).Home;
            bool sysDrive = m.Groups[1].Value.Equals(SystemDrive, System.StringComparison.OrdinalIgnoreCase);
            // its own folder: on the system drive, or validly signed on another one (Visual Studio installed on D:)
            if (home.IsMatch(m.Groups[2].Value) && (sysDrive || sig == "valid")) return null;
            if (sig == "valid" && InTrustedLocation(path)) return null;
            var parts = new List<string> { "copy of " + name + " outside its usual folders" };
            if (!string.Equals(name, leaf, System.StringComparison.OrdinalIgnoreCase)) parts[0] += " (named " + leaf + ")";
            if (sig != null && sig != "valid") parts.Add(sig == "unsigned" || sig == "no access" ? sig : sig + " signature");
            if (hidden) parts.Add("hidden");
            if (WindowsCache.IsMatch(path)) parts.Add("in a Windows cache folder");
            return string.Join("; ", parts);
        }

        /// <summary>Path inside a folder named like a file, e.g. ab.exe\evil.dll or app.exe.local\x.dll.</summary>
        public static readonly Regex Disg = new Regex(@"\.(EXE|DLL|SCR|LOCAL)\\", O);

        /// <summary>Double extension, harmless then executable (name.pdf.exe, also padded with spaces).</summary>
        public static readonly Regex Dbl = new Regex(
            @"\.(PDF|DOCX?|DOTX?|XLSX?|XLSM|PPTX?|TXT|RTF|ODT|CSV|JPE?G|PNG|GIF|BMP|ICO|MP[34]|AVI|MKV|MOV|WAV|HTML?|INI|LOG)\s*\.(EXE|SCR|COM|BAT|CMD|PS1|VBS|VBE|JSE?|JSC|WSF|WSH|HTA|LNK|MSI|MSP|PIF|CPL|JAR|SCT|CHM|ISO|IMG)$", O);   // not DLL: nobody double-clicks one (Windows.Data.Pdf.dll, Dapplo.Log.dll)

        /// <summary>Folders where Windows and Office name shortcuts after the file they open (report.pdf.lnk), and the Start Menu.</summary>
        public static readonly Regex LnkNormal = new Regex(@"\\MICROSOFT\\(WINDOWS|OFFICE)\\RECENT\\|\\START MENU\\", O);

        /// <summary>A double extension (Dbl), except a shortcut x.pdf.lnk in Recent or the Start Menu, which is normal Windows behaviour.</summary>
        public static bool DoubleExt(string p) =>
            p != null && Dbl.IsMatch(p) && !(p.EndsWith(".lnk", System.StringComparison.OrdinalIgnoreCase) && LnkNormal.IsMatch(p));

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

        /// <summary>Known vulnerable signed kernel drivers by file name (resources/vulndrivers.txt; Spor.vulndrivers.txt next to Spor.exe overrides).</summary>
        public static HashSet<string> VulnerableDrivers => vulnerable ?? (vulnerable = Util.DataFile(VulnerableDriversFile, ParsePublishers, out _));
        static HashSet<string> vulnerable;
        public const string VulnerableDriversFile = "Spor.vulndrivers.txt";
        public const string VulnerableDriverFlag = "!vulnerable-driver";
        public const string RandomNameFlag = "!random-name";

        /// <summary>(pure) A file in a program's install folder: Program Files (x86) or a folder in ProgramData (C:\ProgramData\Vendor\...).</summary>
        public static bool InInstallFolder(string p)
        {
            var m = Regex.Match(p ?? "", @"^[a-z]:\\(Program Files( \(x86\))?|ProgramData)\\([^\\]+)\\", O);
            // a vendor's folder, not a random-looking one malware made (C:\ProgramData\kfjqzx\)
            return m.Success && !Names.IsRandom(m.Groups[3].Value) && !RandomLowerName(m.Groups[3].Value.ToLowerInvariant());
        }

        /// <summary>(pure) A driver file that is a known vulnerable one (by name) or has a random-looking name (ksllxnqs.sys).</summary>
        internal static List<string> DriverFlags(string p, HashSet<string> vulnerableNames)
        {
            var f = new List<string>();
            if (string.IsNullOrEmpty(p) || !p.EndsWith(".sys", System.StringComparison.OrdinalIgnoreCase)) return f;
            var name = p.Substring(p.LastIndexOf('\\') + 1);
            if (vulnerableNames != null && vulnerableNames.Contains(name)) f.Add(VulnerableDriverFlag);
            // not Names.IsRandom: driver names are short codes with digits (rt640x64, e1d68x64, b57nd60a) that it takes for random
            if (RandomLowerName(System.IO.Path.GetFileNameWithoutExtension(name))) f.Add(RandomNameFlag);
            return f;
        }

        /// <summary>Letter pairs no real (English or technical) name has; q only before u.</summary>
        static readonly Regex RareBigram = new Regex(@"q(?!u)|vk|zk|kc|xn|jx|qx|fq|zx|vq|kz|wq|qk|jk|xj|zq|vz|gq|pq|xz", O);

        /// <summary>Four consonants in a row.</summary>
        static readonly Regex ConsonantRun = new Regex(@"[bcdfghjklmnpqrstvwxz]{4}", O);

        /// <summary>
        /// (pure) An all-lowercase name of 7-9 letters as cheat loaders and rootkits give their drivers (ksllxnqs, aavkswsq, lktrozkc,
        /// qhemhlne): at most two vowels, four consonants in a row and a letter pair real names never have. Checked against the 2,099
        /// driver names of the FenrisHub logs (November 2026): only the random ones; not nvlddmkm, dxgkrnl, qwavedrv, athpexnt, storqosflt.
        /// </summary>
        internal static bool RandomLowerName(string stem)
        {
            if (string.IsNullOrEmpty(stem) || stem.Length < 7 || stem.Length > 9 || !stem.All(ch => ch >= 'a' && ch <= 'z')) return false;
            return stem.Count(ch => "aeiouy".IndexOf(ch) >= 0) <= 2 && ConsonantRun.IsMatch(stem) && RareBigram.IsMatch(stem);
        }

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
            if (Regex.IsMatch(u, @"^[A-Z]:\\RECOVERY\\")) return true;   // what Windows runs after a reset (C:\Recovery\OEM): no program lives there
            return Regex.IsMatch(u, @"^[A-Z]:\\[^\\]+$");   // root of a drive
        }

        /// <summary>
        /// PowerShell and command text that downloads or runs code, and common obfuscation (backticks in words, 'a'+'b', [char] codes,
        /// reversed strings, gcm i*x, $pshome[4], any -EncodedCommand spelling, long Base64), Defender exclusions set by a command.
        /// The ClickFix module reads the PowerShell history with it; persistence (Run values, tasks, services) the arguments.
        /// </summary>
        public static readonly Regex PsSus = new Regex(@"(?<![|(])\b(iex|irm|iwr)\b(?![|)])|invoke-(webrequest|restmethod)|invoke-expression(?!\s+(""[^""$`(]*""|'[^'$`(]*')\s*$)|\.download(string|file|data)\s*\(|frombase64string\s*\(|net\.webclient|start-bitstransfer\s|\bbitsadmin(\.exe)?\s+/|certutil(\.exe)?\s.*-urlcache|certutil(\.exe)?\s.*-addstore\s.*\broot\b|\bmshta(\.exe)?\s+\S|(add|set)-mppreference|(curl|wget)(\.exe)?\s.*https?://(?!(?:localhost|127(?:\.\d{1,3}){3}|\[::1\])(?:[:/]|$))|(^|\s)[/\p{Pd}]e[a-z]{0,13}\s+['""]?[a-z0-9+/=]{20}|(^|\s)[/\p{Pd}]w[a-z]{0,10}\s+h[a-z]*\b|\w`\w[^`]*\w`\w|['""][^'""\s]{1,8}['""]\s*\+\s*['""][^'""\s]{1,8}['""]|(\[char\]\s*(0x)?[0-9a-f]+.*){3}|\[\s*-1\s*\.\.\s*-?\d|\b(gcm|get-command|gal|get-alias)\s+[^\s|;]*\*|\$(env:\w+|pshome|shellid)\s*\[\s*\d|\$verbosepreference\.tostring\(\)\s*\[|\$executioncontext\.invokecommand|\[scriptblock\]::create|[a-z0-9+/]{100,}", O);

        /// <summary>
        /// Arguments that make a trusted program untrusted: a file outside Windows/Program Files (or in Windows\Temp, Tasks, ...),
        /// a network path or URL, a script, encoded or hidden PowerShell. E.g. rundll32.exe C:\Users\x\AppData\evil.dll,Start.
        /// </summary>
        public static bool ArgsSuspicious(string args)
        {
            if (string.IsNullOrWhiteSpace(args)) return false;
            if (PsSus.IsMatch(args)) return true;   // irm | iex, [scriptblock]::Create, Add-MpPreference, -EncodedCommand, ...
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
        /// (pure) Arguments of a Windows tool or script interpreter in persistence that make it !suspicious: PowerShell that downloads or
        /// runs code (PsSus: irm | iex, [scriptblock]::Create, -EncodedCommand, Add-MpPreference, ...), a URL or a network path, or a
        /// script or program outside Windows and Program Files ("pythonw.exe C:\ProgramData\x\x.py"). Stricter than ArgsSuspicious,
        /// which also distrusts a vendor's own script in Program Files.
        /// </summary>
        public static bool ArgsRunCode(string args)
        {
            if (string.IsNullOrWhiteSpace(args)) return false;
            if (PsSus.IsMatch(args) || Regex.IsMatch(args, @"\\\\[^\\\s]+\\|https?://|ftp://", RegexOptions.IgnoreCase)) return true;
            foreach (Match m in ArgPath.Matches(args))
                if (!InTrustedLocation(m.Groups[1].Value)
                    && Regex.IsMatch(m.Groups[1].Value, @"\.(exe|dll|scr|cpl|com|pif|bat|cmd|ps1|psm1|vbs|vbe|js|jse|wsf|wsh|hta|sct|py|pyw|jar|au3|a3x|ahk)$", RegexOptions.IgnoreCase))
                    return true;
            return false;
        }

        static readonly Regex BrowserOrNode = new Regex(@"\\(msedge|chrome|brave|opera|vivaldi|node)\.exe$", O);

        /// <summary>
        /// (pure) A browser (or Node.js) driven by another program: remote debugging on and no window (--headless). Stealers and
        /// WEEVILPROXY (Puppeteer) read cookies and browse with the user's session this way; a developer's test run looks the same.
        /// </summary>
        public static bool HeadlessDebug(string program, string commandLine) =>
            BrowserOrNode.IsMatch(program ?? "") && Regex.IsMatch(commandLine ?? "", @"--remote-debugging-(port|pipe)\b", O)
            && Regex.IsMatch(commandLine ?? "", @"--headless\b", O);

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

        /// <summary>Where Windows keeps drivers: a driver elsewhere gets !outside-driver-folders.</summary>
        public static readonly Regex DriverFolder = new Regex(@"^[a-z]:\\windows\\(system32|syswow64)\\(drivers|driverstore)\\", O);

        public const string InterpreterOutsideFlag = "!interpreter-outside";

        /// <summary>
        /// (pure) A script interpreter (Rules.Interpreter: Python, Node.js, AutoIt, Java, ...) where none is installed: anywhere under the
        /// Windows folder (C:\Windows\System32\HealthCheck\node.exe), or in a drop location (Temp, Downloads, the top of AppData or
        /// ProgramData, ...) without an uninstaller in its folder (an all-users Anaconda in C:\ProgramData\anaconda3 has one).
        /// hasUninstaller tells whether a folder holds unins*.exe / Uninstall*.exe.
        /// </summary>
        public static bool InterpreterOutside(string p, string winDir, Func<string, bool> hasUninstaller)
        {
            if (string.IsNullOrEmpty(p) || !Interpreter.IsMatch(p)) return false;
            if (!string.IsNullOrEmpty(winDir) && p.StartsWith(winDir.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase))
            {
                // the Python launcher (C:\Windows\py.exe) and old Java copies sit right in Windows / System32: only a folder below counts
                var rel = p.Substring(winDir.TrimEnd('\\').Length + 1);
                return !Regex.IsMatch(rel, @"^((System32|SysWOW64)\\)?[^\\]+$", RegexOptions.IgnoreCase);
            }
            if (!DropLocation(p)) return false;
            var dir = System.IO.Path.GetDirectoryName(p);
            return dir == null || hasUninstaller == null || !hasUninstaller(dir);
        }

        /// <summary>A folder with an uninstaller (unins000.exe, Uninstall-Anaconda3.exe, uninstall.exe): a program was installed there.</summary>
        public static bool HasUninstaller(string dir)
        {
            try
            {
                return System.IO.Directory.Exists(dir) && (System.IO.Directory.EnumerateFiles(dir, "unins*.exe").Any()
                                                           || System.IO.Directory.EnumerateFiles(dir, "uninstall*.exe").Any());
            }
            catch { return false; }
        }

        /// <summary>(pure) A folder or file name in the path ending with a dot or a space: Windows' own APIs strip those, so only a program
        /// that bypasses them (\\?\ paths) makes one, and Explorer and many tools cannot open it (C:\ProgramData\prndata..\prn.exe).</summary>
        public static bool EdgePart(string p)
        {
            var m = DrivePath.Match(p ?? "");
            if (!m.Success) return false;
            // "." and ".." are the folder itself and its parent ("C:\Vendor\bin\..\app.exe" in a service's ImagePath), not names
            return m.Groups[2].Value.Split('\\').Any(part => part.Length > 0 && part != "." && part != ".." && (part.EndsWith(".") || part.EndsWith(" ")));
        }

        /// <summary>!RLO, !invisible-char, !double-extension, !in-folder-named-like-file, !lolbin. name: also test this file name for LOLBins.</summary>
        public static List<string> Flags(string p, string name = null)
        {
            var f = new List<string>();
            p = p ?? "";
            if (Bidi.IsMatch(p)) f.Add("!RLO");
            if (Hiding.IsMatch(p) || EdgePart(p)) f.Add(InvisibleFlag);
            f.AddRange(DriverFlags(p, VulnerableDrivers));
            if (DoubleExt(p)) f.Add("!double-extension");
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
        public static readonly HashSet<string> Hints = new HashSet<string> { "!renamed-program", AbusedTldFlag, RootProgramFlag };

        /// <summary>Hint: a program, script or shortcut in the root of a drive (USB worms put their copy and shortcuts there).</summary>
        public const string RootProgramFlag = "!root-program";

        /// <summary>A Windows accessory that loaded code from a user-writable folder or runs with arguments it never takes: malware runs in it.</summary>
        public const string InjectionHostFlag = "!injection-host";

        /// <summary>
        /// Windows programs malware starts and injects into (Akira Stealer: calc.exe as a Cloudflare tunnel, charmap.exe as a watchdog,
        /// dllhost.exe for its payload): in System32 / SysWOW64, or a bare name (a prefetch entry without its path).
        /// Not notepad: it opens any script a user edits, which its prefetch entry lists.
        /// </summary>
        static readonly Regex Accessory = new Regex(@"^(?:[A-Z]:\\WINDOWS\\(?:SYSTEM32|SYSWOW64)\\)?(CALC|CHARMAP|DLLHOST)\.EXE$", O);

        public static bool AccessoryHost(string p) => Accessory.IsMatch(p ?? "");

        /// <summary>Code an injected accessory loads from its malware's folder (a fake Python's library zip, a DLL).</summary>
        static readonly Regex InjectedCode = new Regex(@"\.(DLL|PYD|PYC|PY|PYW|ZIP|NODE|JS)$", O);

        /// <summary>
        /// (pure) A file a Windows accessory's prefetch entry loaded that shows code injected into it: code (InjectedCode) outside
        /// Windows and Program Files, not validly signed (signedOk: false also for a file that is gone). For dllhost.exe a DLL only
        /// from a drop location: as COM surrogate it hosts shell extensions, some of them unsigned in AppData.
        /// </summary>
        public static bool InjectedFile(string program, string loaded, bool signedOk)
        {
            if (!DrivePath.IsMatch(loaded ?? "") || InTrustedLocation(loaded) || !InjectedCode.IsMatch(loaded) || signedOk) return false;
            bool dllhost = (program ?? "").EndsWith("DLLHOST.EXE", System.StringComparison.OrdinalIgnoreCase);
            return !dllhost || !loaded.EndsWith(".DLL", System.StringComparison.OrdinalIgnoreCase) || DropLocation(loaded);
        }

        /// <summary>
        /// (pure) A running Windows accessory with arguments it never takes: calc.exe and charmap.exe take none, dllhost.exe only
        /// /Processid:{CLSID} (Akira Stealer: "calc.exe tunnel --url ...", "charmap.exe --wd", "dllhost.exe --obf-args").
        /// </summary>
        public static bool InjectionHostArgs(string path, string commandLine)
        {
            var m = Accessory.Match(path ?? "");
            if (!m.Success) return false;
            var args = Cmd.Args(commandLine ?? "").Trim();
            if (args.Length == 0) return false;
            return !m.Groups[1].Value.Equals("DLLHOST", System.StringComparison.OrdinalIgnoreCase)
                   || !Regex.IsMatch(args, @"^/Processid:\{[0-9A-F-]{36}\}\s*$", O);
        }

        /// <summary>A file whose signature was revoked or that was changed after signing (a patched or infected signed file).</summary>
        public const string InvalidSignatureFlag = "!invalid-signature";

        /// <summary>Hint: downloaded from a host under a cheap TLD malware campaigns favour (HostNames.AbusedTlds).</summary>
        public const string AbusedTldFlag = "!abused-tld";

        /// <summary>Flags that go to the summary (a LOLBin run alone is normal on many PCs; hints only with a strong flag).</summary>
        public static List<string> Strong(List<string> f) => f.Where(x => x != "!lolbin" && !Hints.Contains(x) && !Info.Contains(x)).ToList();

        /// <summary>
        /// Context flags: not evidence of malware, but what a helper needs to know about the case (a remote access tool was used, an
        /// account was created, Defender's history wiped). They put a finding in the SUMMARY, in time order with the others, and are no
        /// reason for anything else (no hint counts next to them, nothing is shown or hidden because of them).
        /// </summary>
        public static readonly HashSet<string> Info = new HashSet<string>
        {
            "!remote-access", "!account-change", "!history-deleted", "!disk-image", "!upload", "!new-service", "!task-deleted", "!startup-item",
            "!drop-group", "!reset-config", "!proxy", "!dev-mode", "!custom-root", "!settings-changed",
        };

        /// <summary>A flag list for one context finding.</summary>
        public static List<string> InfoFlag(string flag) => new List<string> { flag };

        public static List<string> HintsOf(List<string> f) => f.Where(Hints.Contains).ToList();

        public static readonly string[] FlagLegend =
        {
            "!lolbin = Windows tool that malware likes to use (normal on many PCs)",
            "!double-extension = e.g. invoice.pdf.exe",
            "!in-folder-named-like-file = e.g. x.exe\\evil.dll",
            "!RLO = right-to-left override character in the name (shown as <RLO>)",
            "!renamed-lolbin = Windows tool under another name",
            "!unsigned = driver, or program of an auto-start service or scheduled task outside trusted locations, without a valid signature",
            "!vulnerable-driver = a signed kernel driver known to be vulnerable (BYOVD: kdmapper, Defender killers); also installed by some tools (MSI Afterburner)",
            "!random-name = driver file with a random-looking name (ksllxnqs.sys)",
            "!remote-access = context: remote access tool, its logs or configuration, camera or microphone in use, a remote access host in the DNS cache",
            "!account-change = context: account created, put in a group, or an admin with a password that never signed in",
            "!history-deleted = context: Defender's detection history deleted",
            "!disk-image = context: disk image mounted, or a program opened from a CD/DVD or mounted ISO",
            "!upload = context: a program that is not validly signed sent 50 MB or more (SRUM)",
            "!new-service = context: a service or driver was installed (not one the whitelist hides)",
            "!task-deleted = context: a scheduled task was deleted",
            "!startup-item = context: a file in a Startup folder that is no shortcut, program or script",
            "!drop-group = context: a folder created together with a flagged loader folder (same seconds or same file names)",
            "!reset-config = context: a reset or setup hook (C:\\Recovery\\OEM, Setup\\Scripts, unattend.xml) written in the time window that does nothing suspicious (a reset or reinstall writes them too)",
            "!proxy = context: a proxy is set for web traffic",
            "!dev-mode = context: browser extension developer mode is on",
            "!custom-root = context: a self-signed root certificate that is not Windows' own (AV web shields, developer tools, or an older man-in-the-middle proxy)",
            "!settings-changed = context: Settings pages hidden by policy (pages malware hides get !settings-hidden)",
            "!reset-hook = what Windows runs after \"Reset this PC\", at the end of Setup or from an answer file runs code, restores a scheduled task or registry values, or (written in the time window) starts a program outside Windows; also a machine ID kept for after a reset (OldMachineGuid)",
            "!new-in-windows = program, module or script without a valid signature in a folder new below System32 / SysWOW64",
            "!local-proxy = web traffic goes through a proxy on this PC or the local network, or a proxy script (PAC): it can read and change everything (man-in-the-middle)",
            "!root-cert = a self-signed root certificate that is not Windows' own was added in the time window (lets a proxy read HTTPS)",
            "!settings-hidden = Settings pages hidden that malware hides: network-proxy, recovery, Windows Security, Windows Update, troubleshooting",
            "!unpacked-extension = browser extension loaded unpacked or from the command line, not from a store (patched wallet extensions are loaded so)",
            "!hidden-task = scheduled task set to hidden (not one of Windows') that runs a program outside trusted locations or not validly signed",
            "!invalid-signature = file changed after signing or with a revoked signature (a patched or infected signed file)",
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
            "!injection-host = Windows accessory (calc, charmap, dllhost) that loaded unsigned code from outside Windows and Program Files (Prefetch) or runs with arguments it never takes: malware injected into it",
            "!renamed-program = hint: a signed program under a random-looking or lure name that is not its original name (in SUMMARY only with a strong flag nearby)",
            "!abused-tld = hint: downloaded from a host under a cheap TLD malware campaigns favour (.lol, .top, .xyz, ...; in SUMMARY only with a strong flag nearby)",
            "!renamed-persisted = persistence starts a signed program under another name than its original, in a random-looking folder of a user profile or ProgramData (a loader's signed decoy)",
            "!interpreter-outside = script interpreter (Python, Node.js, AutoIt, Java, ...) in a Windows folder or a drop location without an uninstaller, started by persistence or running",
            "!defender-detected = Defender detected this file (or this process): every line of the file gets the flag",
            "!in-defender-exclusion = file without a valid signature in a folder Defender excludes, or an excluded program: Defender does not scan it",
            "!invisible-char = invisible character in the name, shown as <U+XXXX>: anywhere one never used in names (zero-width space, Hangul filler, Braille blank, ...); on USB drives any (also no-break space)",
            "!usb-worm-lnk = shortcut on a drive that starts a script host, cmd, rundll32 or a file in a hidden folder, has no normal target, or is named like the drive or a hidden folder (USB worm)",
            "!disguised-icon = shortcut to a program or script that shows a folder, document or drive icon",
            "!autorun = autorun.inf that starts something, or a MountPoints2 shell command",
            "!hidden-system = hidden and system item on a removable drive or USB disk (not a Windows folder), e.g. a fake RECYCLER folder",
            "!clsid-folder = folder named x.{GUID} or with a desktop.ini that sets a CLSID: Explorer shows it as something else",
            "!ads = alternate data stream (other than Zone.Identifier) on a file of a drive",
            "!root-program = hint: program, script or shortcut in the root of a drive (USB worms put their copy and shortcuts there; in SUMMARY only with a strong flag nearby)",
            "!explorer-hiding = Explorer settings tampered so hidden files cannot be shown (SHOWALL CheckedValue, NoFolderOptions)",
            "!lolbin-copy = copy of MSBuild, InstallUtil, RegAsm, RegSvcs, AddInProcess, aspnet_compiler, wscript, cscript or mshta (by original name) outside its usual folders, and not validly signed in Windows / Program Files",
            "!msi-script-action = cached Windows Installer package that installs into a LocalAppData folder and runs a script host, cmd, PowerShell or a script it installs as a custom action"
        };
    }
}
