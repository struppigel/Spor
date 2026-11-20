using System;
using System.Linq;
using Xunit;

namespace Spor.Tests
{
    /// <summary>Script-runtime launchers and !runtime-loader.</summary>
    public class RuntimeTests
    {
        const string Dir = @"C:\Users\anna\Downloads\Game\";

        [Theory]
        [InlineData("Ren'Py (Python)", @"lib\py3-windows-x86_64\librenpython.dll", @"lib\py3-windows-x86_64\libpython3.9.dll", @"renpy\main.py", @"data\x.rpa")]
        [InlineData("Python", @"python312.dll", @"Lib\os.py", @"app\main.pyc")]
        [InlineData("Python", @"_internal\python312.dll", @"_internal\base_library.zip")]   // PyInstaller onedir
        [InlineData("AutoIt", @"AutoIt3.exe", @"script.a3x")]
        [InlineData("AutoIt", @"payload.a3x")]
        [InlineData("Node.js", @"node.exe", @"app\index.js")]
        [InlineData("Electron", @"resources\app.asar", @"ffmpeg.dll")]
        [InlineData("Java", @"jre\bin\javaw.exe", @"app.jar")]
        [InlineData("Lua", @"lua54.dll", @"main.lua")]
        public void Runtimes(string kind, params string[] files) => Assert.Equal(kind, Rules.ScriptRuntime(Dir + "Launcher.exe", files));

        [Fact]
        public void APlainPythonInstallIsNoLauncher()
        {
            // python.exe is the interpreter itself (never hidden anyway), not a launcher with scripts as data
            Assert.Null(Rules.ScriptRuntime(@"C:\Users\anna\AppData\Local\Programs\Python\Python313\python.exe",
                                            new[] { "python313.dll", @"Lib\os.py", "pythonw.exe" }));
        }

        [Fact]
        public void AGameWithoutRuntimeMarkersIsNoLauncher()
        {
            Assert.Null(Rules.ScriptRuntime(Dir + "Game.exe", new[] { "UnityPlayer.dll", @"Game_Data\data.unity3d", @"Game_Data\Managed\Assembly-CSharp.dll" }));
            // a Python DLL without the standard library next to it (an app embedding Python for plugins)
            Assert.Null(Rules.ScriptRuntime(Dir + "Editor.exe", new[] { "python3.dll", "editor.dll" }));
        }

        [Fact]
        public void MarkersDeeperThanTwoFoldersDoNotCount()
        {
            Assert.Null(Rules.ScriptRuntime(Dir + "Tool.exe", new[] { @"a\b\c\node.exe" }));
        }

        [Theory]
        [InlineData(@"C:\Users\anna\Downloads", true)]
        [InlineData(@"C:\Users\anna\Desktop\", true)]
        [InlineData(@"C:\Users\anna\AppData\Local\Temp", true)]
        [InlineData(@"C:\Users\anna\AppData\Roaming", true)]
        [InlineData(@"C:\ProgramData", true)]
        [InlineData(@"C:\Users\Public\Downloads", true)]
        [InlineData(@"C:\", true)]
        [InlineData(@"C:\Users\anna\Downloads\Game", false)]
        [InlineData(@"C:\Users\anna\AppData\Local\Temp\tmp-1-abc", false)]
        [InlineData(@"C:\Users\anna\AppData\Roaming\Vendor", false)]
        public void SharedFolders(string dir, bool shared) => Assert.Equal(shared, Rules.SharedFolder(dir));

        [Fact]
        public void ProxyLaunchesAsChildren()
        {
            // a child that is a proxy launcher counts even inside Windows; conhost without --headless does not
            Assert.True(Rules.ProxyLaunch(@"C:\Windows\System32\forfiles.exe", @"forfiles /p C:\x /m a.exe /c ""cmd /c call @path"""));
            Assert.False(Rules.ProxyLaunch(@"C:\Windows\System32\conhost.exe", @"\??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1"));
            Assert.False(Rules.ProxyLaunch(@"C:\Windows\System32\WerFault.exe", @"C:\Windows\system32\WerFault.exe -u -p 1234 -s 56"));
        }

        [Fact]
        public void Entropy()
        {
            var random = new byte[65536]; new Random(1).NextBytes(random);
            Assert.True(Util.Entropy(random) > 7.9);
            Assert.Equal(0, Util.Entropy(new byte[4096]));
            Assert.True(Util.Entropy(System.Text.Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat("the quick brown fox jumps over the lazy dog ", 100)))) < 5);
        }

        static RuntimeFolder Folder(bool isNew) => new RuntimeFolder { Launcher = Dir + "Setup.exe", New = isNew };

        [Fact]
        public void ANewFolderWithALoaderSignIsFlagged()
        {
            var r = Folder(true);
            r.DotFiles.Add(Dir + @"data\.VD6");
            r.Padded.Add(Dir + @"data\big.bin");
            Assert.Equal(new[] { @"padded file C:\Users\anna\Downloads\Game\data\big.bin", @"hidden file C:\Users\anna\Downloads\Game\data\.VD6 next to its scripts" },
                         Correlate.Signals(r));
        }

        [Fact]
        public void AChildOrALoweredZoneNearARunIsASign()
        {
            var r = Folder(true);
            r.Children.Add((@"C:\Users\anna\AppData\Local\Temp\x\h.exe", Run1));
            r.MotwNearRun.Add((@"C:\Users\anna\AppData\Local\Temp\x\h.exe", Run1));
            Assert.Equal(2, Correlate.Signals(r).Count);
        }

        static readonly DateTime Run1 = new DateTime(2026, 11, 20, 3, 33, 41, DateTimeKind.Utc), Run2 = new DateTime(2026, 11, 20, 7, 59, 42, DateTimeKind.Utc);

        [Fact]
        public void EachRunGetsItsOwnNotes()
        {
            // the lab run: two runs four hours apart, each wrote its own payload folder and started forfiles
            var r = Folder(true);
            const string Forfiles = @"C:\Windows\System32\forfiles.exe", A = @"C:\Users\anna\AppData\Local\Temp\tmp-20656-a\x.exe", B = @"C:\Users\anna\AppData\Local\Temp\tmp-79694-b\x.exe";
            r.Children.Add((Forfiles, Run1));
            r.Children.Add((Forfiles, Run2));
            r.MotwNearRun.Add((A, Run1));
            r.MotwNearRun.Add((B, Run2));
            r.Children.Add((@"C:\Users\anna\AppData\Local\Temp\y.exe", null));   // no run known: the first line
            var notes = Correlate.RunNotes(r);
            Assert.Equal(new DateTime?[] { null, Run1, Run2 }, notes.Select(n => n.Run));
            Assert.Equal(new[] { @"started C:\Users\anna\AppData\Local\Temp\y.exe" }, notes[0].Notes);
            Assert.Equal(new[] { "started " + Forfiles, "!motw-removed file " + A + " written within 2 minutes of this run" }, notes[1].Notes);
            Assert.Equal(new[] { "started " + Forfiles, "!motw-removed file " + B + " written within 2 minutes of this run" }, notes[2].Notes);
            // the decision still sees them all, once each
            Assert.Equal(new[] { "started " + Forfiles, @"started C:\Users\anna\AppData\Local\Temp\y.exe",
                                 "!motw-removed file " + A + " written within 2 minutes of a run", "!motw-removed file " + B + " written within 2 minutes of a run" },
                         Correlate.Signals(r));
            // no notes for a folder that is not new
            r.New = false;
            Assert.Empty(Correlate.RunNotes(r));
        }

        [Fact]
        public void ARuntimeAloneIsNotFlagged()
        {
            // legitimate games and tools look the same: no sign, no flag
            Assert.Empty(Correlate.Signals(Folder(true)));
        }

        [Fact]
        public void AnOldFolderIsNotFlagged()
        {
            var r = Folder(false);
            r.RandomData.Add(Dir + "vP0YuDGhS91a.0b");
            Assert.Empty(Correlate.Signals(r));
        }

        [Fact]
        public void RandomDataFileNames()
        {
            Assert.True(Names.IsRandom("vP0YuDGhS91a.0b"));
            Assert.False(Names.IsRandom("archive.rpa"));
        }
    }
}
