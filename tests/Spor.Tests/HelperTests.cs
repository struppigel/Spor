using System;
using System.Collections.Generic;
using System.Linq;
using Spor.Modules;
using Xunit;

namespace Spor.Tests
{
    /// <summary>Location rules: trusted folders, drop locations, Defender update packages, program files.</summary>
    public class LocationRuleTests
    {
        static readonly string Sd = Rules.SystemDrive;
        // a drive that is not the system drive (Windows and Program Files only count there)
        static readonly string Other = Sd.Equals("Z:", StringComparison.OrdinalIgnoreCase) ? "Y:" : "Z:";

        [Theory]
        [InlineData(@"\Windows\System32\notepad.exe")]
        [InlineData(@"\Program Files\App\app.exe")]
        [InlineData(@"\Program Files (x86)\App\app.exe")]
        [InlineData(@"\ProgramData\Microsoft\Windows Defender\Platform\4.18.24090.11-0\MsMpEng.exe")]
        [InlineData(@"\WINDOWS\system32\DRIVERS\x.sys")]
        public void TrustedOnTheSystemDrive(string rel) => Assert.True(Rules.InTrustedLocation(Sd + rel));

        [Theory]
        [InlineData(@"\Windows\Temp\a.exe")]                              // user-writable inside Windows
        [InlineData(@"\Windows\Tasks\a.exe")]
        [InlineData(@"\Windows\System32\Tasks\x\a.exe")]
        [InlineData(@"\Windows\System32\spool\PRINTERS\a.dll")]
        [InlineData(@"\Windows\ServiceProfiles\LocalService\AppData\Local\a.exe")]
        [InlineData(@"\Users\anna\AppData\Roaming\a.exe")]
        [InlineData(@"\ProgramData\App\a.exe")]
        [InlineData(@"\$WINDOWS.~BT\Sources\a.exe")]                     // any user can create folders in C:\
        public void NotTrusted(string rel) => Assert.False(Rules.InTrustedLocation(Sd + rel));

        [Fact]
        public void WindowsOnAnotherDriveIsNotTrusted()
        {
            Assert.False(Rules.InTrustedLocation(Other + @"\Windows\System32\notepad.exe"));
            Assert.False(Rules.InTrustedLocation(Other + @"\Program Files\App\app.exe"));
            Assert.False(Rules.InTrustedLocation(@"Windows\System32\notepad.exe"));
            Assert.False(Rules.InTrustedLocation(null));
        }

        [Theory]
        [InlineData(@"C:\Users\anna\AppData\Local\Temp\x\a.exe", true)]
        [InlineData(@"C:\Users\anna\Downloads\x\a.exe", true)]
        [InlineData(@"C:\Users\anna\Desktop\a.exe", true)]
        [InlineData(@"C:\Users\Public\a.exe", true)]
        [InlineData(@"C:\$Recycle.Bin\S-1-5-21-1\a.exe", true)]
        [InlineData(@"C:\Users\anna\AppData\Roaming\a.exe", true)]               // top two levels of AppData
        [InlineData(@"C:\Users\anna\AppData\Roaming\Folder\a.exe", true)]
        [InlineData(@"C:\Users\anna\AppData\LocalLow\Folder\a.dll", true)]
        [InlineData(@"C:\Users\anna\AppData\Local\Programs\App\a.exe", false)]   // installed software sits deeper
        [InlineData(@"C:\ProgramData\a.exe", true)]
        [InlineData(@"C:\ProgramData\Folder\a.exe", true)]
        [InlineData(@"C:\ProgramData\Vendor\App\a.exe", false)]
        [InlineData(@"C:\a.exe", true)]                                           // root of a drive
        [InlineData(@"E:\a.exe", true)]
        [InlineData(@"C:\Program Files\App\a.exe", false)]
        [InlineData(@"C:\Windows\System32\a.exe", false)]
        [InlineData(null, false)]
        public void DropLocations(string path, bool drop) => Assert.Equal(drop, Rules.DropLocation(path));

        [Fact]
        public void DefenderUpdatePackagesOnlyByExactNameAndFolderOnTheSystemDrive()
        {
            var folder = @"\Windows\SoftwareDistribution\Download\Install\";
            Assert.True(Rules.DefenderUpdate(Sd + folder + "AM_Delta_Patch_1.421.123.0.exe"));
            Assert.True(Rules.DefenderUpdate(Sd + folder.ToUpperInvariant() + "am_delta_patch_1.421.123.0.EXE"));
            Assert.False(Rules.DefenderUpdate(Other + folder + "AM_Delta_Patch_1.421.123.0.exe"));
            Assert.False(Rules.DefenderUpdate(Sd + folder + "AM_Delta_Patch_1.421.exe"));         // four version parts
            Assert.False(Rules.DefenderUpdate(Sd + folder + "AM_Delta_Patch_1.421.123.0.exe.exe"));
            Assert.False(Rules.DefenderUpdate(Sd + @"\Users\anna\Downloads\AM_Delta_Patch_1.421.123.0.exe"));
            Assert.False(Rules.DefenderUpdate(null));
        }

        [Theory]
        [InlineData("a.exe", true)]
        [InlineData("a.msi", true)]
        [InlineData("a.ps1", true)]
        [InlineData("a.js", true)]
        [InlineData("a.lnk", true)]
        [InlineData("a.url", true)]
        [InlineData("a.pdf", false)]
        [InlineData("a.exe.txt", false)]
        [InlineData(null, false)]
        public void ProgramFiles(string path, bool program) => Assert.Equal(program, Rules.ProgramFile(path));
    }

    /// <summary>Arguments that make a trusted program untrusted (rundll32 C:\Users\...\evil.dll,Start).</summary>
    public class ArgsSuspiciousTests
    {
        [Theory]
        [InlineData(@"C:\Users\anna\AppData\Roaming\x\evil.dll,Start")]
        [InlineData(@"/c start https://example.com/a")]
        [InlineData(@"\\server\share\a.exe")]
        [InlineData(@"-nop -w hidden -c Get-Date")]
        [InlineData(@"-nop -windowstyle hidden -c Get-Date")]
        [InlineData(@"-nop -enc SQBFAFgA")]
        [InlineData(@"/c run.bat")]
        [InlineData(@"-File C:\Tools\a.ps1")]
        [InlineData(@"""C:\Users\anna\Downloads\x.exe"" /S")]
        [InlineData(@"%APPDATA%\x\a")]
        [InlineData(@"-c iex (New-Object Net.WebClient).DownloadString($u)")]
        public void Suspicious(string args) => Assert.True(Rules.ArgsSuspicious(args));

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        [InlineData(@"C:\Windows\System32\shell32.dll,Control_RunDLL")]       // a library in System32
        [InlineData(@"/log C:\Users\anna\AppData\Local\App\update.log")]       // a data file
        [InlineData(@"--type=renderer --lang=en-US")]
        [InlineData(@"-k netsvcs -p")]
        public void Normal(string args) => Assert.False(Rules.ArgsSuspicious(args));
    }

    /// <summary>Flag columns and texts.</summary>
    public class FlagTextTests
    {
        [Fact]
        public void FlagColumn()
        {
            Assert.Equal("-", Rules.FlagCol(null));
            Assert.Equal("-", Rules.FlagCol(new string[0]));
            Assert.Equal("!a !b", Rules.FlagCol(new[] { "!a", "!b", "!a" }));
        }

        [Fact]
        public void FlagTextAfterAnEntry()
        {
            Assert.Equal("", Rules.FlagText(null));
            Assert.Equal("", Rules.FlagText(new List<string>()));
            Assert.Equal("  !a !b", Rules.FlagText(new List<string> { "!a", "!b" }));
        }

        [Fact]
        public void HintsAreTheWeakFlags()
        {
            var f = new List<string> { "!lolbin", "!renamed-program", "!sideload" };
            Assert.Equal(new[] { "!renamed-program" }, Rules.HintsOf(f));
            Assert.Equal(new[] { "!sideload" }, Rules.Strong(f));
        }

        [Fact]
        public void ModuleNoiseIsCaseInsensitive()
        {
            Assert.Matches(Rules.Noise(@"\\googleupdate\.exe$"), @"C:\Program Files\Google\Update\GoogleUpdate.EXE");
        }

        [Theory]
        [InlineData(@"C:\x\a.exe [unsigned]", true)]
        [InlineData(@"C:\x\a.exe [invalid signature]", true)]
        [InlineData(@"C:\x\a.exe [revoked signature]", true)]
        [InlineData(@"C:\x\a.exe [expired signature]", true)]
        [InlineData(@"C:\x\a.exe [valid]", false)]
        [InlineData(@"C:\x\a.exe [gone]", false)]
        [InlineData(null, false)]
        public void BadSignatureStatus(string status, bool bad) => Assert.Equal(bad, Ctx.BadSig(status));
    }

    /// <summary>Signature: which files carry one, and how a result is written.</summary>
    public class SignatureTextTests
    {
        [Theory]
        [InlineData("a.exe", true)]
        [InlineData("A.DLL", true)]
        [InlineData("a.sys", true)]
        [InlineData("a.msix", true)]
        [InlineData("a.ps1", false)]
        [InlineData("a.exe.txt", false)]
        [InlineData(null, false)]
        public void SignableFiles(string path, bool signable) => Assert.Equal(signable, Signature.Applies(path));

        [Fact]
        public void DescribeLeavesOutMissingParts()
        {
            Assert.Equal("unsigned", Signature.Describe(new Signature.Result()));
            Assert.Equal("unsigned", Signature.Describe(new Signature.Result { Signer = "X", Thumbprint = "AB" }));   // unsigned: nothing else
            Assert.Equal("valid; signer Contoso Ltd; thumbprint AB12",
                         Signature.Describe(new Signature.Result { Status = "valid", Signer = "Contoso Ltd", Thumbprint = "AB12" }));
            Assert.Equal("invalid; note hash mismatch", Signature.Describe(new Signature.Result { Status = "invalid", Reason = "hash mismatch" }));
            Assert.Equal("valid; signer S; thumbprint T; note revocation not checked",
                         Signature.Describe(new Signature.Result { Status = "valid", Signer = "S", Thumbprint = "T", Reason = "revocation not checked" }));
        }

        [Fact]
        public void PackagedAppFiles()
        {
            Assert.True(Package.IsPackaged(@"C:\Program Files\WindowsApps\App_1.0.0.0_x64__8wekyb3d8bbwe\app.exe"));
            Assert.True(Package.IsPackaged(@"D:\WindowsApps\App_1.0.0.0_x64__8wekyb3d8bbwe\x\a.dll"));
            Assert.False(Package.IsPackaged(@"C:\Program Files\WindowsApps\App_1.0.0.0_x64__8wekyb3d8bbwe"));   // the folder itself
            Assert.False(Package.IsPackaged(@"C:\Program Files\App\app.exe"));
            Assert.False(Package.IsPackaged(null));
        }
    }

    /// <summary>Small text helpers: event message fields, URLs, file times, names, plurals.</summary>
    public class TextHelperTests
    {
        [Fact]
        public void EventMessageField()
        {
            var msg = "Microsoft Defender Antivirus has detected malware.\r\n Name: Trojan:Win32/Example\r\n Path: file:_C:\\a.exe \r\n Action:\r\n";
            Assert.Equal("Trojan:Win32/Example", Ev.Field(msg, "Name"));
            Assert.Equal("Trojan:Win32/Example", Ev.Field(msg, "name"));
            Assert.Equal(@"file:_C:\a.exe", Ev.Field(msg, "Path"));
            Assert.Equal("", Ev.Field(msg, "Action"));
            Assert.Null(Ev.Field(msg, "Severity"));
            Assert.Null(Ev.Field(null, "Name"));
        }

        [Theory]
        [InlineData("https://example.com/a.exe", true)]
        [InlineData("http://example.com", true)]
        [InlineData("about:internet", false)]
        [InlineData("  ABOUT:blank", false)]
        [InlineData("", false)]
        [InlineData("   ", false)]
        [InlineData(null, false)]
        public void RealUrls(string url, bool real) => Assert.Equal(real, Zone.RealUrl(url));

        [Fact]
        public void FileTimes()
        {
            var t = new DateTime(2026, 11, 21, 9, 0, 38, DateTimeKind.Utc);
            long ft = t.ToFileTimeUtc();
            Assert.Equal(t, Util.FtTime(ft));
            Assert.Equal(t, Util.FtTime((object)ft));
            Assert.Equal(t, Util.FtTime(BitConverter.GetBytes(ft)));
            Assert.Null(Util.FtTime(0L));
            Assert.Null(Util.FtTime(-1L));
            Assert.Null(Util.FtTime((object)0));
            Assert.Null(Util.FtTime(new byte[4]));
            Assert.Null(Util.FtTime("2026-11-21"));
            Assert.Null(Util.FtTime(long.MaxValue));   // out of range: null, not an exception
        }

        [Fact]
        public void LeafPluralBytes()
        {
            Assert.Equal("b.exe", Util.Leaf(@"C:\a\b.exe"));
            Assert.Equal("b.exe", Util.Leaf("b.exe"));
            Assert.Equal("", Util.Leaf(@"C:\a\"));
            Assert.Equal("1 file", Util.Plural(1, "file", "files"));
            Assert.Equal("0 files", Util.Plural(0, "file", "files"));
            Assert.Equal("2 files", Util.Plural(2, "file", "files"));
            Assert.Equal("5 bytes", Cmd.Bytes(5));
        }

        [Fact]
        public void BuiltInDataFiles()
        {
            Assert.Equal("", Util.Embedded("Spor.no-such-file.txt"));
            // no override next to Spor.exe in the test run: the built-in file
            var text = Util.DataFile(Rules.PublishersFile, s => s, out var source);
            Assert.Null(source);
            Assert.Equal(Util.Embedded(Rules.PublishersFile), text);
            Assert.Null(Rules.PublishersSource);
            Assert.Contains("Microsoft Windows", Rules.TrustedSigners);
            Assert.Contains("microsoft corporation", Rules.TrustedSigners);   // case-insensitive
            Assert.DoesNotContain("Windows itself", Rules.TrustedSigners);    // the note column is not a signer
        }
    }

    /// <summary>Names and host names: lure words, the name a program was built under, IDs in host names.</summary>
    public class NameHelperTests
    {
        [Theory]
        [InlineData("Invoice_2026.exe", true)]
        [InlineData(@"C:\Users\anna\Downloads\Setup (1).exe", true)]
        [InlineData("KEYGEN.exe", true)]
        [InlineData("notepad.exe", false)]
        [InlineData("", false)]
        [InlineData(null, false)]
        public void LureNames(string name, bool lure) => Assert.Equal(lure, Names.IsLure(name));

        [Fact]
        public void OriginalNameOrder()
        {
            Assert.Equal("orig.exe", Names.Original("orig.exe", "internal", @"C:\b\x.pdb"));
            Assert.Equal("internal.exe", Names.Original(null, " internal.exe ", @"C:\b\x.pdb"));
            Assert.Equal("internal.exe", Names.Original("  ", "internal.exe", null));
            Assert.Equal(@"C:\b\x.pdb", Names.Original(null, null, @"C:\b\x.pdb"));
            Assert.Null(Names.Original(null, "", null));
        }

        [Theory]
        [InlineData("0a1b2c3d4e5f", true)]                          // a MAC address
        [InlineData("abcdefabcdef", false)]                         // 12 hex letters without a digit: a word
        [InlineData("0123456789abcdef0123456789abcdef", true)]      // 32 hex
        [InlineData("3f2504e0-4f89-11d3-9a0c-0305e82c3301", true)]  // a GUID
        [InlineData("3f2504e04f8911d39a0c0305e82c3301", true)]
        [InlineData("k3j4h5g6f7d8s9a0", true)]                      // base32-like, a quarter digits and letters
        [InlineData("wwwgooglecomabcd", false)]                     // letters only
        [InlineData("rr10---sn-4g5e6nzl", false)]                   // a CDN node name
        [InlineData("www", false)]
        [InlineData("", false)]
        [InlineData(null, false)]
        public void IdLabels(string label, bool id) => Assert.Equal(id, HostNames.IsId(label));
    }

    /// <summary>Side-loading: imports Windows resolves itself; USB shortcuts that start something.</summary>
    public class ImportAndShortcutTests
    {
        [Fact]
        public void IgnoredImports()
        {
            var known = new HashSet<string>(new[] { "kernel32.dll" }, Util.IC);
            Assert.True(Sideload.Ignored("api-ms-win-core-file-l1-1-0.dll", null));
            Assert.True(Sideload.Ignored("EXT-MS-win-x.dll", null));
            Assert.True(Sideload.Ignored("", null));
            Assert.True(Sideload.Ignored(null, null));
            Assert.True(Sideload.Ignored("KERNEL32.dll", known));
            Assert.False(Sideload.Ignored("version.dll", known));
            Assert.False(Sideload.Ignored("version.dll", null));
        }

        [Theory]
        [InlineData(@"E:\x\a.exe", true)]
        [InlineData(@"E:\x\a.vbs", true)]
        [InlineData(@"C:\Windows\System32\cmd.exe", true)]
        [InlineData(@"C:\Windows\explorer.exe", true)]
        [InlineData(@"C:\Windows\System32\rundll32.exe", true)]
        [InlineData(@"E:\docs\report.pdf", false)]
        [InlineData(@"E:\docs\", false)]
        [InlineData("", false)]
        [InlineData(null, false)]
        public void RunnableShortcutTargets(string target, bool runnable) => Assert.Equal(runnable, Usb.Runnable(target));
    }

    /// <summary>!double-extension: report.pdf.lnk is normal where Windows and Office write shortcuts named after the file they open.</summary>
    public class DoubleExtensionTests
    {
        [Theory]
        [InlineData(@"C:\Users\anna\Downloads\invoice.pdf.exe", true)]
        [InlineData(@"C:\Users\anna\Downloads\invoice.pdf.lnk", true)]
        [InlineData(@"C:\Users\anna\Downloads\Recent\invoice.pdf.lnk", true)]                             // a folder named Recent is not enough
        [InlineData(@"C:\Users\anna\AppData\Roaming\Microsoft\Office\Recent\invoice.pdf.exe", true)]       // only shortcuts are exempt
        [InlineData(@"C:\Users\anna\AppData\Roaming\Microsoft\Office\Recent\Library_Final.pptx.LNK", false)]
        [InlineData(@"C:\Users\anna\AppData\Roaming\Microsoft\Windows\Recent\report.docx.lnk", false)]
        [InlineData(@"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Readme.txt.lnk", false)]
        [InlineData(@"\VOLUME{01d0-1234abcd}\USERS\ANNA\APPDATA\ROAMING\MICROSOFT\OFFICE\RECENT\X.PPTX.LNK", false)]   // Prefetch's form
        public void Flag(string path, bool flagged) => Assert.Equal(flagged, Rules.Flags(path).Contains("!double-extension"));
    }

    /// <summary>Backdated files (old whole-second times, recent NTFS change time): installer batches vs. single files.</summary>
    public class BackdatedTests
    {
        static readonly DateTime At = new DateTime(2026, 10, 28, 16, 49, 0, DateTimeKind.Utc);
        const string Jdk = @"C:\Users\anna\AppData\Local\Programs\Eclipse Adoptium\jdk-25.0.5.8-hotspot\";

        /// <summary>
        /// An MSI writes the JDK's signed programs and one unsigned jrt-fs.jar within seconds: one batch of all of them, so the jar is
        /// not a lone backdated file (Spor 0.7.1 dropped the signed files before batching and flagged the jar !timestomped).
        /// </summary>
        [Fact]
        public void SignedFilesOfAnInstallAreInTheBatch()
        {
            var files = new[] { (Jdk + @"bin\java.exe", 0), (Jdk + @"bin\javaw.exe", 1), (Jdk + @"bin\server\jvm.dll", 2), (Jdk + @"lib\jrt-fs.jar", 36) };
            var b = Files.Batches(files, f => f.Item1, f => At.AddSeconds(f.Item2));
            Assert.Single(b);
            Assert.Equal(4, b[0].Count);
        }

        [Fact]
        public void FarApartOrOtherTreesAreSeparate()
        {
            var files = new[]
            {
                (@"C:\Users\anna\AppData\Roaming\Evil\a.exe", 0), (@"C:\Users\anna\AppData\Roaming\Evil\b.exe", 120),   // 2 minutes apart
                (@"C:\ProgramData\Blackmagic Design\DaVinci Resolve\Support\x.exe", 0), (@"C:\ProgramData\Other\y.exe", 0),
            };
            Assert.Equal(4, Files.Batches(files, f => f.Item1, f => At.AddSeconds(f.Item2)).Count);
        }

        [Theory]
        [InlineData(@"\Windows\SoftwareDistribution\Download\0ceda8a1727e2aa3\Metadata\Deployment.cab", true)]
        [InlineData(@"\WINDOWS\softwaredistribution\Download\Install\AM_Delta_Patch_1.463.364.0.exe", true)]
        [InlineData(@"\Windows\SoftwareDistributionX\a.exe", false)]
        [InlineData(@"\Users\anna\SoftwareDistribution\a.exe", false)]
        public void WindowsUpdateFolderOnTheSystemDrive(string rel, bool inside)
        {
            Assert.Equal(inside, Rules.InWindowsUpdateFolder(Rules.SystemDrive + rel));
            var other = Rules.SystemDrive.Equals("Z:", StringComparison.OrdinalIgnoreCase) ? "Y:" : "Z:";
            Assert.False(Rules.InWindowsUpdateFolder(other + rel));
        }
    }

    public class SoftwareTextTests
    {
        [Theory]
        [InlineData("Antigravity 2.32.1", "2.32.1", "Antigravity 2.32.1")]
        [InlineData("Malwarebytes version 5.8.1.409", "5.8.1.409", "Malwarebytes version 5.8.1.409")]
        [InlineData("Google Chrome", "157.0.8103.79", "Google Chrome 157.0.8103.79")]
        [InlineData("Eclipse Temurin JDK with Hotspot 25.0.5+8 (x64)", "25.0.5.8", "Eclipse Temurin JDK with Hotspot 25.0.5+8 (x64) 25.0.5.8")]
        [InlineData("App 12.3", "2.3", "App 12.3 2.3")]                 // only the whole version counts
        [InlineData("App 1.2.3", "1.2", "App 1.2.3 1.2")]
        [InlineData("Xbox Service", "", "Xbox Service")]
        public void VersionOnlyOnce(string name, string version, string text) => Assert.Equal(text, Software.NameVersion(name, version));

        [Theory]
        [InlineData(@"C:/Riot Games/Riot Client/", @"C:\Riot Games\Riot Client")]
        [InlineData("\"C:\\Program Files\\App\\\"", @"C:\Program Files\App")]
        [InlineData(" C:\\Games\\x\\ ", @"C:\Games\x")]
        [InlineData(@"\", "")]
        [InlineData(null, "")]
        public void InstallFolders(string value, string folder) => Assert.Equal(folder, Software.InstallFolder(value));

        [Fact]
        public void StoreOperationsOfOneInstallAreOneText()
        {
            Assert.Equal("provision", Software.OpName("ProvisionPackageOperation"));
            Assert.Equal("add", Software.OpName("Add"));
            Assert.Equal("Store app provision, add, register: Malwarebytes.AntiMalware_5.0.0.115_neutral__fjscb452b7c5t (Malwarebytes Anti-Malware), from file:///C:/WINDOWS/TEMP/mb_BEC2.tmp",
                Software.StoreText(new List<string> { "provision", "add", "register" }, "Malwarebytes.AntiMalware_5.0.0.115_neutral__fjscb452b7c5t", "Malwarebytes Anti-Malware", "file:///C:/WINDOWS/TEMP/mb_BEC2.tmp"));
        }
    }

    public class DefenderItemTests
    {
        /// <summary>A command line Defender detected (ClickFix) can contain "; ": it stays one resource: item.</summary>
        [Fact]
        public void CommandLineWithSemicolonsIsOneItem()
        {
            var r = Security.Resources(@"CmdLine:_C:\Program Files\Git\bin\bash.exe -c a; b; } || true; process: C:\Program Files\Git\bin\bash.exe, pid:5:1; C:\x\y.exe");
            Assert.Equal(new[] { ("resource", @"CmdLine:_C:\Program Files\Git\bin\bash.exe -c a; b; } || true"), ("process", @"C:\Program Files\Git\bin\bash.exe, pid:5:1"), ("file", @"C:\x\y.exe") }, r);
        }

        /// <summary>Defender logs a detection again when it finds another file: one SUMMARY line with every file.</summary>
        [Fact]
        public void SameFindingAgainAddsItsSubLines()
        {
            using (var c = new Ctx(new Options()))
            {
                var t = DateTime.UtcNow.AddHours(-1);
                c.Find(t, "Defender detected: X", new List<(string Key, string Value)> { ("file", @"C:\a.html") });
                c.Find(t.AddMilliseconds(300), "Defender detected: X", new List<(string Key, string Value)> { ("file", @"C:\b.html"), ("file", @"C:\a.html") });
                Assert.Equal(new[] { ("file", @"C:\a.html"), ("file", @"C:\b.html") }, c.FindingMore["Defender detected: X"]);
            }
        }
    }

    public class NativeMessagingTests
    {
        const string Cmd = @"C:\WINDOWS\system32\cmd.exe";
        const string Pipes = @" < \\.\pipe\chrome.nativeMessaging.in.1688307a2c675a72 > \\.\pipe\chrome.nativeMessaging.out.1688307a2c675a72";

        [Fact]
        public void TheBrowsersCommandLineNamesTheHost() =>
            Assert.Equal(@"C:\Program Files\Malwarebytes\Anti-Malware\mbambgnativemsg.exe", Processes.NativeMessagingHost(Cmd,
                Cmd + @" /d /s /c """"C:\Program Files\Malwarebytes\Anti-Malware\mbambgnativemsg.exe"" chrome-extension://ihcjicgdanjaechkgeegckofjjedodee/ --parent-window=0""" + Pipes));

        [Theory]
        [InlineData(@" /d /s /c """"C:\Program Files\x\host.exe"" chrome-extension://ihcjicgdanjaechkgeegckofjjedodee/ --parent-window=0 & calc.exe""")]   // more commands
        [InlineData(@" /d /s /c """"C:\Program Files\x\host.exe"" chrome-extension://ihcjicgdanjaechkgeegckofjjedodee/"" & calc.exe")]
        [InlineData(@" /c powershell -enc AAAA")]
        public void OtherCommandLinesAreNot(string args) => Assert.Null(Processes.NativeMessagingHost(Cmd, Cmd + args + Pipes));

        [Fact]
        public void OnlyForCmd() => Assert.Null(Processes.NativeMessagingHost(@"C:\Windows\System32\conhost.exe",
            @"conhost.exe /d /s /c """"C:\Program Files\x\host.exe"" chrome-extension://ihcjicgdanjaechkgeegckofjjedodee/""" + Pipes));
    }

    public class DownloadTextTests
    {
        [Fact]
        public void LongUrlsAreCut()
        {
            var shortUrl = "https://get.microsoft.com/installer/download/9NKSQGP7F2NH?cid=website_cta_psi";
            Assert.Equal(shortUrl, Downloads.LongUrl(shortUrl));
            var signed = "https://release-assets.githubusercontent.com/x?" + new string('a', 1200);
            Assert.Equal(251, Downloads.LongUrl(signed).Length);
            Assert.EndsWith("…", Downloads.LongUrl(signed));
            Assert.Null(Downloads.LongUrl(null));
        }

        /// <summary>WebCache writes many entries at once (sync): 5+ files of one user with the same second are a batch, not open times.</summary>
        [Fact]
        public void WebCacheBatches()
        {
            var t = new DateTime(2026, 11, 16, 3, 25, 29, DateTimeKind.Utc);
            var rows = Enumerable.Range(0, 6).Select(i => (t, "shawn", $@"C:\Users\shawn\Downloads\f{i}.zip"))
                .Concat(new[] { (t.AddSeconds(1), "shawn", @"C:\Users\shawn\Downloads\g.zip"), (t, "anna", @"C:\Users\anna\Downloads\h.zip") }).ToList();
            var b = Downloads.WebCacheBatches(rows);
            Assert.Single(b);
            Assert.Equal(6, b.Values.Single());
            Assert.Empty(Downloads.WebCacheBatches(rows.Take(4)));
        }
    }

    public class AmcacheNameTests
    {
        [Theory]
        [InlineData("setup.exe", "setup.exe")]
        [InlineData("msedge_proxy.exe", "msedge_proxy.exe")]          // 16 characters, whole
        [InlineData("cls-srep_x64.exe", "cls-srep_x64.exe")]
        [InlineData("onedriveupdaters", "onedriveupdaters…")]         // cut
        [InlineData("elevation_servic", "elevation_servic…")]
        [InlineData("onedrivepatcher.", "onedrivepatcher.…")]
        public void CutNamesGetAnEllipsis(string key, string name) => Assert.Equal(name, Amcache.KeyName(key));
    }

    public class UpdaterStagingTests
    {
        static readonly string Sd = Rules.SystemDrive;

        [Theory]
        [InlineData(@"\Program Files (x86)\Microsoft\EdgeUpdate\Install\{0E9F471D-FE8C-4A89-883A-DEF43FD7965A}\MicrosoftEdge_X64_158.0.4370.33.exe", @"\Program Files (x86)\Microsoft\EdgeUpdate\Install\{0E9F471D-FE8C-4A89-883A-DEF43FD7965A}\")]
        [InlineData(@"\Program Files (x86)\BraveSoftware\Update\Install\{B8042044-937D-446E-860D-B9044A5514FD}\brave_installer-delta-x64.exe", @"\Program Files (x86)\BraveSoftware\Update\Install\{B8042044-937D-446E-860D-B9044A5514FD}\")]
        [InlineData(@"\Windows\SoftwareDistribution\Download\Install\AM_Delta_Patch_1.463.364.0.exe", @"\Windows\SoftwareDistribution\")]
        [InlineData(@"\Windows\WinSxS\amd64_microsoft-windows-servicingstack_31bf3856ad364e35_10.0.26100.9703_none_a5009b9d7769c1f5\TiWorker.exe", @"\Windows\WinSxS\")]
        public void Staged(string rel, string root)
        {
            Assert.True(Rules.InUpdaterStaging(Sd + rel));
            Assert.Equal(Sd + root, Rules.StagingRoot(Sd + rel), StringComparer.OrdinalIgnoreCase);
        }

        [Theory]
        [InlineData(@"\$WinREAgent\Scratch\09B5A09E-7A01-4403-9986-BF518E6A02B7\DismHost.exe")]   // any user can create C:\ folders
        [InlineData(@"\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe")]         // the updater itself, not a staged package
        [InlineData(@"\Users\anna\AppData\Local\Microsoft\EdgeUpdate\Install\{0E9F471D-FE8C-4A89-883A-DEF43FD7965A}\x.exe")]
        [InlineData(@"\Windows\Temp\SoftwareDistribution\x.exe")]
        public void NotStaged(string rel) => Assert.False(Rules.InUpdaterStaging(Sd + rel));
    }

    /// <summary>Ctx.RealCase: the case on disk, gone parts keep theirs.</summary>
    public class RealCaseTests
    {
        /// <summary>
        /// A gone folder that was looked up before as a part of a file's path (Compatibility Assistant "more:" lines, SOFTWARE "folder:")
        /// keeps its path: the cache's null for the missing part made it print as "\" (Spor 0.7.1).
        /// </summary>
        [Fact]
        public void GoneFolderAfterAFileInItKeepsItsPath()
        {
            var root = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "SporRealCase" + Guid.NewGuid().ToString("N"));
            System.IO.Directory.CreateDirectory(root);
            try
            {
                using (var c = new Ctx(new Options()))
                {
                    var gone = root + @"\Grand Theft Auto V Legacy";
                    Assert.Equal(gone + @"\GTA5.exe", c.RealCase(gone + @"\GTA5.exe"));
                    Assert.Equal(gone, c.RealCase(gone));
                    Assert.Equal(gone, c.RealCase(gone.ToUpperInvariant().Replace(root.ToUpperInvariant(), root)));
                }
            }
            finally { System.IO.Directory.Delete(root, true); }
        }
    }
}
