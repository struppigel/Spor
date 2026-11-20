using System;
using System.IO;
using System.Linq;
using System.Reflection;
using Xunit;

namespace Spor.Tests
{
    /// <summary>
    /// The .lnk parser on shortcuts Windows makes (WScript.Shell): target, arguments, icon, window state, volume, the PC that made it;
    /// and the target from the item list alone, as crafted worm shortcuts have it.
    /// </summary>
    public class LnkTests
    {
        static byte[] MakeShortcut(string target, string args, string icon, int window)
        {
            var path = Path.Combine(Path.GetTempPath(), "spor_test_" + Guid.NewGuid().ToString("N") + ".lnk");
            var shellType = Type.GetTypeFromProgID("WScript.Shell");
            var shell = Activator.CreateInstance(shellType);
            try
            {
                var lnk = shellType.InvokeMember("CreateShortcut", BindingFlags.InvokeMethod, null, shell, new object[] { path });
                var t = lnk.GetType();
                t.InvokeMember("TargetPath", BindingFlags.SetProperty, null, lnk, new object[] { target });
                t.InvokeMember("Arguments", BindingFlags.SetProperty, null, lnk, new object[] { args });
                if (!string.IsNullOrEmpty(icon)) t.InvokeMember("IconLocation", BindingFlags.SetProperty, null, lnk, new object[] { icon });
                t.InvokeMember("WindowStyle", BindingFlags.SetProperty, null, lnk, new object[] { window });
                t.InvokeMember("Description", BindingFlags.SetProperty, null, lnk, new object[] { "test description" });
                t.InvokeMember("Save", BindingFlags.InvokeMethod, null, lnk, null);
                return File.ReadAllBytes(path);
            }
            finally { try { File.Delete(path); } catch { } }
        }

        static readonly string Cmd = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe");

        [Fact]
        public void WindowsShortcut()
        {
            var b = MakeShortcut(Cmd, "/c start \"\" \"\u00A0\\x.exe\"", @"%SystemRoot%\system32\SHELL32.dll,3", 7);
            var l = Lnk.Parse(b);
            Assert.NotNull(l);
            Assert.Equal(Cmd, l.Target, StringComparer.OrdinalIgnoreCase);
            Assert.Equal("link info", l.TargetFrom);
            Assert.Equal("/c start \"\" \"\u00A0\\x.exe\"", l.Args);
            Assert.Equal(3, l.IconIndex);
            Assert.EndsWith("SHELL32.dll,3", l.Icon, StringComparison.OrdinalIgnoreCase);
            Assert.Equal(7, l.ShowCmd);
            Assert.Equal("test description", l.Description);
            Assert.Equal(3, l.DriveType);
            Assert.Equal(Native.VolumeSerial(Path.GetPathRoot(Cmd)), l.VolumeSerial);
            Assert.Equal(Environment.MachineName, l.Machine, StringComparer.OrdinalIgnoreCase);
            Assert.Equal(Cmd, l.IdListTarget, StringComparer.OrdinalIgnoreCase);
        }

        /// <summary>The same shortcut without its LinkInfo: the target comes from the item list.</summary>
        [Fact]
        public void ItemListOnly()
        {
            var b = MakeShortcut(Cmd, "/c echo", "", 1);
            uint flags = BitConverter.ToUInt32(b, 20);
            Assert.True((flags & 3) == 3, "Windows writes an item list and link info");
            int li = 76 + 2 + BitConverter.ToUInt16(b, 76);
            int size = BitConverter.ToInt32(b, li);
            var cut = b.Take(li).Concat(b.Skip(li + size)).ToArray();
            BitConverter.GetBytes(flags & ~2u).CopyTo(cut, 20);
            var l = Lnk.Parse(cut);
            Assert.Equal(Cmd, l.Target, StringComparer.OrdinalIgnoreCase);
            Assert.Equal("item list", l.TargetFrom);
            Assert.Equal("/c echo", l.Args);
            Assert.Null(l.VolumeSerial);
        }

        [Fact]
        public void BrokenInputDoesNotThrow()
        {
            var b = MakeShortcut(Cmd, "/c echo", "", 1);
            for (int n = 0; n < b.Length; n += 7) Lnk.Parse(b.Take(n).ToArray());   // truncated anywhere
            var junk = (byte[])b.Clone();
            for (int i = 76; i < junk.Length; i += 3) junk[i] = 0xFF;
            Lnk.Parse(junk);
            Assert.Null(Lnk.Parse(new byte[10]));
        }

        [Fact]
        public void UrlFile()
        {
            var u = Spor.UrlFile.Parse("[InternetShortcut]\r\nURL=file:///E:/%C2%A0/x.exe\r\nIconFile=C:\\Windows\\System32\\shell32.dll\r\nIconIndex=4\r\n");
            Assert.Equal("file:///E:/%C2%A0/x.exe", u.Url);
            Assert.Equal(4, u.IconIndex);
        }
    }
}
