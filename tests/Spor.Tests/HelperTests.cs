using System;
using System.Collections.Generic;
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
}
