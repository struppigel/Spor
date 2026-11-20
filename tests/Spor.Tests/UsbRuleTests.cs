using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Spor.Modules;
using Xunit;

namespace Spor.Tests
{
    /// <summary>The USB DRIVES rules: worm shortcuts, disguised icons, autorun.inf, CLSID folders, streams, device ids.</summary>
    public class UsbRuleTests
    {
        [Theory]
        [InlineData(@"%SystemRoot%\system32\SHELL32.dll", 3, "folder icon")]
        [InlineData(@"C:\Windows\System32\shell32.dll", 4, "folder icon")]
        [InlineData(@"shell32.dll", 7, "drive icon")]
        [InlineData(@"shell32.dll", 1, "document icon")]
        [InlineData(@"%SystemRoot%\System32\imageres.dll", 3, "folder icon")]
        [InlineData(@"E:\pics\cover.JPG", 0, "icon of a .jpg file")]
        [InlineData(@"C:\Program Files\App\app.exe", 0, null)]
        [InlineData(@"shell32.dll", 22, null)]
        [InlineData("", 0, null)]
        public void IconKind(string icon, int index, string kind) => Assert.Equal(kind, Usb.IconKind(icon, index));

        static Lnk L(string target, string args = null, string from = "link info") => new Lnk { Target = target, Args = args, TargetFrom = from };

        [Fact]
        public void WormShortcutStartsAHost()
        {
            var s = Usb.WormSigns("Photos.lnk", L(@"C:\Windows\System32\wscript.exe", "\"\u00A0\\run.vbs\""), "STICK", new[] { "\u00A0" });
            Assert.Contains("starts wscript.exe", s);
            Assert.Contains("points into hidden <U+00A0>", s);
        }

        [Fact]
        public void WormShortcutNamedLikeTheDrive()
        {
            var s = Usb.WormSigns("STICK.lnk", L(@"E:\_\x.exe"), "STICK", new[] { "_" });
            Assert.Contains("named like the drive label", s);
            Assert.Contains("points into hidden _", s);
        }

        [Fact]
        public void ItemListOnlyCountsWithARunnableTarget()
        {
            Assert.Contains("target only as item list (no link info)", Usb.WormSigns("x.lnk", L(@"E:\x\a.exe", null, "item list"), null, null));
            Assert.Empty(Usb.WormSigns("Report.lnk", L(@"E:\docs\report.pdf", null, "item list"), null, null));
        }

        [Fact]
        public void NormalShortcutIsNoWorm()
        {
            Assert.Empty(Usb.WormSigns("Setup.lnk", L(@"E:\Setup\setup.exe"), "STICK", new[] { "System Volume Information" }));
            Assert.Empty(Usb.WormSigns("Docs.lnk", L(@"E:\docs"), "STICK", new string[0]));
        }

        [Fact]
        public void HiddenWindowsFoldersAreNoWormSign() =>
            Assert.Empty(Usb.WormSigns("x.lnk", L(@"E:\System Volume Information\x.dat"), null, new[] { "System Volume Information" }));

        [Theory]
        [InlineData("Recycle Bin.{645FF040-5081-101B-9F08-00AA002F954E}", true)]
        [InlineData("x.{20D04FE0-3AEA-1069-A2D8-08002B30309D}", true)]
        [InlineData("{645FF040-5081-101B-9F08-00AA002F954E}", false)]
        [InlineData("Photos", false)]
        public void ClsidName(string name, bool yes) => Assert.Equal(yes, Usb.ClsidName(name));

        [Fact]
        public void DesktopIniClsid()
        {
            Assert.Equal("CLSID={645FF040-5081-101B-9F08-00AA002F954E}", Usb.DesktopIniClsid("[.ShellClassInfo]\r\nCLSID={645FF040-5081-101B-9F08-00AA002F954E}\r\n"));
            Assert.Null(Usb.DesktopIniClsid("[.ShellClassInfo]\r\nIconResource=C:\\Windows\\System32\\imageres.dll,-3\r\n"));
        }

        [Fact]
        public void AutorunInf()
        {
            var inf = Usb.ParseInf("; comment\r\n[AutoRun]\r\nopen=\u00A0\\x.exe\r\nshell\\open\\command=\u00A0\\x.exe\r\nshell\\open=Open\r\nicon=%SystemRoot%\\system32\\SHELL32.dll,4\r\n[other]\r\nopen=y.exe\r\n");
            Assert.Equal(("AutoRun", "open", "\u00A0\\x.exe"), inf[0]);   // the no-break space is the folder name: not trimmed
            var cmds = Usb.AutorunCommands(inf);
            Assert.Equal(new[] { "open", "shell\\open\\command" }, cmds.Select(x => x.Key));
            Assert.Equal("E:\\\u00A0\\x.exe", Usb.AutorunFile("E:\\", cmds[0].Command));
            Assert.Equal(@"E:\run\a b.exe", Usb.AutorunFile("E:\\", @"""run\a b.exe"" /s"));
            Assert.Equal(@"E:\x.exe", Usb.AutorunFile("E:\\", @"x.exe -q"));
        }

        [Fact]
        public void ArgumentFiles()
        {
            var disk = new HashSet<string>(new[] { "E:\\\u00A0\\x.exe", @"E:\run.vbs", @"C:\Tools\a.dll" }, System.StringComparer.OrdinalIgnoreCase);
            var found = Usb.ArgumentFiles("/c start \"\" \"\u00A0\\x.exe\" & wscript run.vbs & rundll32 C:\\Tools\\a.dll,Start & start explorer \"\u00A0\"",
                                          @"E:", null, @"E:\", disk.Contains);
            Assert.Equal(new[] { "E:\\\u00A0\\x.exe", @"E:\run.vbs", @"C:\Tools\a.dll" }, found);
            Assert.Empty(Usb.ArgumentFiles("/c echo hi", @"E:", null, @"E:\", disk.Contains));
        }

        [Fact]
        public void ArgWords() =>
            Assert.Equal(new[] { "/c", "start", "\u00A0\\x.exe", "a b.exe", "C:\\x.dll", "Start" },
                         Usb.ArgWords("/c start \"\" \"\u00A0\\x.exe\" & \"a b.exe\" C:\\x.dll,Start"));

        [Fact]
        public void AnsiAutorunKeepsTheNoBreakSpace()
        {
            var ansi = Encoding.Default.GetBytes("[autorun]\r\nopen=\u00A0\\x.exe\r\n");
            Assert.Contains("\u00A0\\x.exe", Usb.DecodeText(ansi));
            Assert.Equal("[a]\r\nk=\u00e4", Usb.DecodeText(Encoding.UTF8.GetBytes("[a]\r\nk=\u00e4")));
            Assert.Equal("[a]", Usb.DecodeText(Encoding.Unicode.GetPreamble().Concat(Encoding.Unicode.GetBytes("[a]")).ToArray()));
        }

        [Fact]
        public void Streams()
        {
            Assert.Empty(Usb.UnusualStreams(new[] { "Zone.Identifier", "SmartScreen" }));
            Assert.Equal(new[] { "payload" }, Usb.UnusualStreams(new[] { "Zone.Identifier", "payload" }));
        }

        [Fact]
        public void Attributes()
        {
            Assert.Equal("attributes hidden, system, folder", Usb.AttrText(FileAttributes.Hidden | FileAttributes.System | FileAttributes.Directory));
            Assert.Equal("attributes normal", Usb.AttrText(FileAttributes.Normal));
        }

        [Fact]
        public void DeviceIds()
        {
            const string id = @"USBSTOR#Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_1.00#4C530001231115104383&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}";
            Assert.Equal("SanDisk Cruzer Blade", Usb.UsbName(id));
            Assert.Equal("4C530001231115104383", Usb.UsbSerial(id));
            Assert.Equal("4C530001231115104383", Usb.UsbSerial(@"USBSTOR\Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_1.00\4C530001231115104383&0"));
            var e = Usb.Emd("_??_" + id + "STICK_1234567890");
            Assert.NotNull(e);
            Assert.Equal("STICK", e.Value.Label);
            Assert.Equal("499602D2", e.Value.Serial);
            Assert.Null(Usb.Emd("something else"));
        }

        static readonly System.DateTime Connected = new System.DateTime(2026, 11, 20, 10, 0, 0);

        [Fact]
        public void UsbDriveBySerialAlways()
        {
            var vols = new Dictionary<string, string> { ["499602D2"] = "STICK" };
            var letters = new Dictionary<string, (string, System.DateTime?)>(System.StringComparer.OrdinalIgnoreCase);
            Assert.Equal("on USB drive STICK (serial 499602D2)",
                         Correlate.UsbDriveOf(@"\VOLUME{01d9a1b2c3d4e5f6-499602d2}\_\X.EXE", Connected.AddDays(-30), vols, letters));
            Assert.Null(Correlate.UsbDriveOf(@"C:\x.exe", Connected, vols, letters));
        }

        /// <summary>By letter only after the last connect of the device that has the letter now: before, E: may have been another drive.</summary>
        [Fact]
        public void UsbDriveByLetterAfterConnect()
        {
            var vols = new Dictionary<string, string>();
            var letters = new Dictionary<string, (string, System.DateTime?)>(System.StringComparer.OrdinalIgnoreCase) { ["E:"] = ("STICK", Connected) };
            Assert.Equal("on USB drive E: STICK", Correlate.UsbDriveOf(@"e:\_\x.exe", Connected.AddHours(1), vols, letters));
            Assert.Equal("on USB drive E: STICK", Correlate.UsbDriveOf(@"e:\_\x.exe", Connected.AddMinutes(-1), vols, letters));   // key time lag
            Assert.Null(Correlate.UsbDriveOf(@"e:\setup.exe", Connected.AddDays(-21), vols, letters));
            letters["E:"] = ("STICK", null);
            Assert.Null(Correlate.UsbDriveOf(@"e:\_\x.exe", Connected.AddHours(1), vols, letters));   // connect time unknown
        }
    }
}
