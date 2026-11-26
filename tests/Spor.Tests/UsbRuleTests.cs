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

        [Theory]
        [InlineData("x.exe", 0, false, true)]
        [InlineData("STICK.lnk", 0, false, true)]
        [InlineData("a.vbs", 0, false, true)]
        [InlineData("setup.url", 0, false, true)]
        [InlineData("Usb Safe Protect.exe", 0, false, true)]
        [InlineData("x.exe", 1, false, false)]        // E:\Photos\x.exe: not in the root
        [InlineData("x.exe", 0, true, false)]         // a folder named x.exe
        [InlineData("autorun.inf", 0, false, false)]
        [InlineData("cat.jpg", 0, false, false)]
        [InlineData("pagefile.sys", 0, false, false)]
        [InlineData("hiberfil.sys", 0, false, false)]
        public void RootProgram(string name, int depth, bool dir, bool flagged) => Assert.Equal(flagged, Usb.RootProgram(name, depth, dir));

        [Fact]
        public void RootProgramIsAHint()
        {
            Assert.Contains(Usb.RootFlag, Rules.Hints);
            Assert.Empty(Rules.Strong(new List<string> { Usb.RootFlag }));
            Assert.Contains(Rules.FlagLegend, l => l.StartsWith(Usb.RootFlag + " = hint:"));
        }

        const FileAttributes Hidden = FileAttributes.Hidden | FileAttributes.Directory;
        const FileAttributes Plain = FileAttributes.Directory;

        [Fact]
        public void SystemDriveEntersOnlyInvisibleNamedRootFolders()
        {
            Assert.False(Usb.EnterFolder(false, true, DriveType.Fixed, 0, "OEM", Hidden));
            Assert.False(Usb.EnterFolder(false, true, DriveType.Fixed, 0, "Intel", Hidden | FileAttributes.System));
            Assert.False(Usb.EnterFolder(false, true, DriveType.Fixed, 0, "Games", Plain));
            Assert.True(Usb.EnterFolder(false, true, DriveType.Fixed, 0, "\u00A0", Hidden));
            Assert.True(Usb.EnterFolder(false, true, DriveType.Fixed, 0, "\u206C\u206C", Plain));
            Assert.True(Usb.EnterFolder(false, true, DriveType.Fixed, 0, "data ", Plain));   // name ends with a space
            Assert.True(Usb.EnterFolder(false, true, DriveType.Fixed, 1, "logs", Plain));    // inside an entered folder
        }

        const FileAttributes HS = FileAttributes.Hidden | FileAttributes.System;

        [Fact]
        public void HiddenSystemOnSticksAndAllUsbDisks()
        {
            // a stick (deep) and a 1 TB USB disk (not deep, on USB): a worm's hidden system folder is flagged on both
            Assert.True(Usb.HiddenSystem(true, true, 0, "\u00A0", @"E:\" + "\u00A0", HS | FileAttributes.Directory));
            Assert.True(Usb.HiddenSystem(false, true, 0, "\u206C\u206C", @"D:\" + "\u206C\u206C", HS | FileAttributes.Directory));
            Assert.True(Usb.HiddenSystem(false, true, 1, "x.exe", @"D:\" + "\u206C\u206C" + @"\x.exe", HS));
            Assert.True(Usb.HiddenSystem(false, true, 0, "RECYCLER", @"D:\RECYCLER", HS | FileAttributes.Directory));
            // a fixed disk inside the PC: never
            Assert.False(Usb.HiddenSystem(false, false, 0, "\u00A0", @"D:\" + "\u00A0", HS | FileAttributes.Directory));
            // only hidden, or Windows' own
            Assert.False(Usb.HiddenSystem(false, true, 0, "photos", @"D:\photos", FileAttributes.Hidden | FileAttributes.Directory));
            Assert.False(Usb.HiddenSystem(false, true, 0, "System Volume Information", @"D:\System Volume Information", HS | FileAttributes.Directory));
            Assert.False(Usb.HiddenSystem(true, true, 1, "x.dat", @"E:\$RECYCLE.BIN\x.dat", HS));
            // a USB disk that was a PC's system disk keeps Windows' root folders; on a stick they are still odd
            Assert.False(Usb.HiddenSystem(false, true, 0, "Recovery", @"D:\Recovery", HS | FileAttributes.Directory));
            Assert.True(Usb.HiddenSystem(true, true, 0, "Recovery", @"E:\Recovery", HS | FileAttributes.Directory));
        }

        [Fact]
        public void OtherDrivesEnterAsBefore()
        {
            Assert.True(Usb.EnterFolder(false, false, DriveType.Fixed, 0, "OEM", Hidden));
            Assert.False(Usb.EnterFolder(false, false, DriveType.Fixed, 0, "Games", Plain));
            Assert.False(Usb.EnterFolder(false, false, DriveType.Fixed, 0, "System Volume Information", Hidden | FileAttributes.System));
            Assert.True(Usb.EnterFolder(true, false, DriveType.Removable, 0, "Games", Plain));
            Assert.False(Usb.EnterFolder(false, false, DriveType.Network, 0, "\u00A0", Hidden));
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

        static byte[] H(string hex) => Usb.FieldBytes(hex.Replace(" ", ""));

        [Fact]
        public void MountedKeysOfFixedDisks()
        {
            // MBR: disk signature (as on disk) + partition offset 1 MiB
            Assert.Equal("mbr:182E07C3", Usb.MountedKey(H("182E07C3 0000100000000000")));
            // GPT: "DMIO:ID:" + the partition GUID
            Assert.Equal("gpt:F45956707A38554DB87215913E8CCDEE", Usb.MountedKey(H("444D494F3A49443A F45956707A38554DB87215913E8CCDEE")));
            // a removable drive's value is its device path, no key
            Assert.Null(Usb.MountedKey(Encoding.Unicode.GetBytes(@"_??_USBSTOR#Disk&Ven_Generic&Prod_Flash_Disk&Rev_8.07#52BF6B&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}")));
            Assert.Null(Usb.MountedKey(H("00000000 0000100000000000")));
            Assert.Null(Usb.MountedKey(null));
        }

        /// <summary>DRIVE_LAYOUT_INFORMATION_EX as event 1006 writes it: 48-byte header, then 144 bytes per partition.</summary>
        static byte[] Layout(int style, byte[] signature, params byte[][] partIds)
        {
            var b = new byte[48 + 144 * partIds.Length];
            System.BitConverter.GetBytes(style).CopyTo(b, 0);
            System.BitConverter.GetBytes(partIds.Length).CopyTo(b, 4);
            signature?.CopyTo(b, 8);
            for (int p = 0; p < partIds.Length; p++) partIds[p].CopyTo(b, 48 + 144 * p + 48);
            return b;
        }

        [Fact]
        public void DiskKeysFromTheEvent()
        {
            Assert.Equal(new[] { "mbr:182E07C3" }, Usb.DiskKeys(Layout(0, H("182E07C3")), null));
            var gpt = Layout(1, null, H("FA91E5DD812BDD478B8403349E9F83F2"), H("F45956707A38554DB87215913E8CCDEE"));
            Assert.Equal(new[] { "gpt:FA91E5DD812BDD478B8403349E9F83F2", "gpt:F45956707A38554DB87215913E8CCDEE" }, Usb.DiskKeys(gpt, null));
            // no signature in the layout: the MBR's (offset 440, with the 55 AA end mark)
            var mbr = new byte[512];
            H("95EF1600").CopyTo(mbr, 440);
            mbr[510] = 0x55; mbr[511] = 0xAA;
            Assert.Equal(new[] { "mbr:95EF1600" }, Usb.DiskKeys(Layout(0, null, new byte[0][]), mbr));
            Assert.Empty(Usb.DiskKeys(Layout(0, null), new byte[512]));   // no signature anywhere
            Assert.Empty(Usb.DiskKeys(new byte[10], null));                // too short to be a layout
            Assert.Empty(Usb.DiskKeys(null, null));
        }

        [Fact]
        public void TheSameDiskKeyOnBothSides()
        {
            var id = H("F967CE7F4ACAA34AB739CCA021568163");
            var mounted = new byte[24];
            Encoding.ASCII.GetBytes("DMIO:ID:").CopyTo(mounted, 0);
            id.CopyTo(mounted, 8);
            Assert.Contains(Usb.MountedKey(mounted), Usb.DiskKeys(Layout(1, null, id), null));
        }

        [Fact]
        public void FieldBytes()
        {
            Assert.Equal(new byte[] { 0x18, 0x2E }, Usb.FieldBytes("182e"));
            Assert.Equal(new byte[] { 1, 2 }, Usb.FieldBytes(new byte[] { 1, 2 }));
            Assert.Null(Usb.FieldBytes("xyz"));
            Assert.Null(Usb.FieldBytes("123"));
            Assert.Null(Usb.FieldBytes(null));
        }

        [Fact]
        public void ParentSerial()
        {
            Assert.Equal("NA9LV5LQ", Usb.ParentSerial(@"USB\VID_0BC2&PID_2343\NA9LV5LQ"));
            Assert.Null(Usb.ParentSerial(@"USB\VID_0BC2&PID_2343\6&1a2b3c4d&0&2"));   // Windows made the id up: no serial
            Assert.Null(Usb.ParentSerial(@"PCI\VEN_1C5C&DEV_1959\4&1799ec7b&0&0030"));
        }

        [Fact]
        public void SetupApiLogsOldestFirst()
        {
            Assert.Equal(new[] { "setupapi.dev.20250329_003008.log", "setupapi.dev.20261024_215731.log", "setupapi.dev.log" },
                         Usb.SetupApiOrder(new[] { "setupapi.dev.log", "setupapi.dev.20261024_215731.log", "SETUPAPI.DEV.LOG.txt", "setupapi.dev.20250329_003008.log" }));
            Assert.Empty(Usb.SetupApiOrder(new string[0]));
        }

        [Fact]
        public void OneSerialManyModels()
        {
            // a USB-SATA bridge gives every disk the serial 20171120: the event's model picks the device
            Assert.True(Usb.SameModel("ST1000LM 035-1RK172", "ST1000LM 035-1RK172 USB Device", "ST1000LM 035-1RK172"));
            Assert.False(Usb.SameModel("ST1000LM 035-1RK172", "ST1000LM 035-1RK172 USB Device", "Generic ATA/ATAPI Device"));
            Assert.True(Usb.SameModel("Generic ATA/ATAPI Device", "Generic ATA/ATAPI Device USB Device", "Generic ATA/ATAPI Device"));
            Assert.False(Usb.SameModel("SanDisk Cruzer Blade", null, ""));
        }
    }
}
