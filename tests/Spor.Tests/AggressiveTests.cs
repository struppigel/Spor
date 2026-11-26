using System;
using System.Collections.Generic;
using System.Linq;
using Spor.Modules;
using Xunit;

namespace Spor.Tests
{
    /// <summary>
    /// The aggressive whitelist (-aggressive, command line only): normal logs mark what it would hide with " ~", -aggressive hides it.
    /// The near-miss paths are from real infections (RenLoader, PavinLoader, the Adobe-signed S_Pipe sideload kit): they must stay.
    /// </summary>
    [Collection("static rules")]
    public class AggressiveTests
    {
        // ---- command line

        [Fact]
        public void OnlyTheCommandLineTurnsItOn()
        {
            Assert.False(new Options().Aggressive);   // the window builds its options from the defaults
            Assert.True(Program.Parse(new[] { "-aggressive" }).Aggressive);
            Assert.False(Program.Parse(new[] { "-scan" }).Aggressive);
        }

        [Fact]
        public void NotWithoutTheWhitelist() =>
            Assert.Throws<ArgumentException>(() => Program.Parse(new[] { "-aggressive", "-nowhitelist" }));

        // ---- Table: mark or hide

        static List<string> Write(bool aggressive, Action<Table> fill, params string[] cols) => Write(aggressive, fill, null, cols);

        static List<string> Write(bool aggressive, Action<Table> fill, Func<string, bool> keep, params string[] cols)
        {
            var before = Rules.Aggressive;
            try
            {
                Rules.Aggressive = aggressive;
                var t = new Table(cols.Length > 0 ? cols : new[] { "@time", "<flags", "*item" });
                fill(t);
                var log = new Log();
                t.WriteTo(log);
                Aggr.Finish(log.Lines, 0, keep, aggressive);
                return log.Lines;
            }
            finally { Rules.Aggressive = before; }
        }

        static void Two(Table t)
        {
            t.Add("2026-11-01 10:00:00", "", @"C:\a\keep.exe");
            t.More("program", "x");
            t.Add("2026-11-01 10:00:01", "", @"C:\a\noise.exe");
            t.More("program", "y");
            t.Aggr("noise files");
        }

        [Fact]
        public void NormalLogsMarkTheLineAtTheVeryEnd()
        {
            var l = Write(false, Two);
            Assert.Contains(@"2026-11-01 10:00:01 C:\a\noise.exe ~", l);
            Assert.Contains(@"    program: y", l);   // sub-lines of a marked record stay unmarked
            Assert.Contains(@"2026-11-01 10:00:00 C:\a\keep.exe", l);
            Assert.DoesNotContain(l, x => x.StartsWith("(Hidden by -aggressive", StringComparison.Ordinal));
        }

        [Fact]
        public void AggressiveHidesTheRecordWithItsSubLinesAndCountsIt()
        {
            var l = Write(true, Two);
            Assert.DoesNotContain(l, x => x.Contains("noise.exe") || x == "    program: y");
            Assert.Contains(@"2026-11-01 10:00:00 C:\a\keep.exe", l);
            Assert.Contains("(Hidden by -aggressive: noise files (1).)", l);
        }

        [Fact]
        public void TheMarkComesAfterTheFlags()
        {
            var l = Write(false, t => { t.Add("2026-11-01 10:00:00", "!lolbin", @"C:\Windows\System32\cmd.exe"); t.Aggr("x"); });
            Assert.Contains(@"2026-11-01 10:00:00 C:\Windows\System32\cmd.exe <==== !lolbin ~", l);
        }

        [Theory]
        [InlineData("!sideload")]
        [InlineData("!lolbin !unsigned")]
        [InlineData("!remote-access")]   // context flags too
        public void AFlaggedRecordIsNeverMarked(string flags)
        {
            var normal = Write(false, t => { t.Add("2026-11-01 10:00:00", flags, @"C:\a\x.exe"); t.Aggr("x"); });
            Assert.DoesNotContain(normal, x => Aggr.IsMarked(x));
            var aggressive = Write(true, t => { t.Add("2026-11-01 10:00:00", flags, @"C:\a\x.exe"); t.Aggr("x"); });
            Assert.Contains(aggressive, x => x.Contains(@"C:\a\x.exe"));
        }

        [Fact]
        public void SubLinesCanBeMarkedOnTheirOwn()
        {
            void Fill(Table t)
            {
                t.Add("2026-11-01 10:00:00", "", @"E:\Game\Game.exe");
                t.More("loaded", @"E:\Game\renpy\common\00start.rpy", "engine files");
                t.More("loaded", @"E:\Game\game\libwin.rpa");
            }
            var normal = Write(false, Fill);
            Assert.Contains(@"    loaded: E:\Game\renpy\common\00start.rpy ~", normal);
            Assert.Contains(@"    loaded: E:\Game\game\libwin.rpa", normal);
            var aggressive = Write(true, Fill);
            Assert.DoesNotContain(aggressive, x => x.Contains("00start.rpy"));
            Assert.Contains(@"    loaded: E:\Game\game\libwin.rpa", aggressive);
            Assert.Contains("(Hidden by -aggressive: engine files (1).)", aggressive);
        }

        [Fact]
        public void AllHiddenLeavesOnlyTheCount()
        {
            var l = Write(true, t => { t.Add("2026-11-01 10:00:00", "", @"C:\a\x.exe"); t.Aggr("x"); });
            Assert.Equal(new[] { "(Hidden by -aggressive: x (1).)" }, l);
        }

        [Fact]
        public void WithoutTheWhitelistNothingIsMarked()
        {
            var before = Rules.Whitelist;
            try
            {
                Rules.Whitelist = false;
                var l = Write(false, Two);
                Assert.DoesNotContain(l, x => Aggr.IsMarked(x));
            }
            finally { Rules.Whitelist = before; }
        }

        [Fact]
        public void UnmarkedDropsMarkedRecordsAndSubLines()
        {
            var lines = new[]
            {
                @"2026-11-01 C:\a\noise.exe ~", @"    program: C:\a\inner.exe",
                @"2026-11-01 C:\a\keep.exe", @"    loaded: C:\a\noise.dll ~", @"    loaded: C:\a\keep.dll",
            };
            Assert.Equal(new[] { @"2026-11-01 C:\a\keep.exe", @"    loaded: C:\a\keep.dll" }, Aggr.Unmarked(lines).ToArray());
        }

        // ---- FILES and AMCACHE FILES

        [Theory]
        [InlineData(@"N:\Films\x.mkv", true, true, "media, subtitle, image and Recycle Bin index files")]
        [InlineData(@"N:\$RECYCLE.BIN\S-1-5-21-1\$IABC123.exe", true, true, "media, subtitle, image and Recycle Bin index files")]
        [InlineData(@"C:\Users\a\AppData\Local\x\y.dll", true, false, "files only hidden lines name")]
        [InlineData(@"C:\Users\a\AppData\Local\x\y.dll", true, true, null)]
        [InlineData(@"C:\Users\a\AppData\Local\x\y.dll", false, false, null)]   // no line names it: a module had a reason to check it
        [InlineData(@"C:\Users\a\Downloads\invoice.pdf.exe", true, false, null)]   // flagged: !double-extension
        [InlineData(@"N:\Films\x.ts", true, false, "files only hidden lines name")]   // TypeScript, not a film
        // enchanted-flame: random-named files in System32\drivers that only FILES lists
        [InlineData(@"C:\Windows\System32\drivers\7EDMSHzxJx8ucVea", true, false, null)]
        [InlineData(@"C:\Windows\System32\drivers\GwCKsOVgMq2QFnlb", false, false, null)]
        [InlineData(@"C:\Users\a\AppData\Local\Z0533B4Lo\MVg4zIU\clip\S_Pipe.exe", true, false, null)]
        public void FilesEntries(string key, bool namedByAny, bool namedByUnmarked, string why) =>
            Assert.Equal(why, Scanner.FileAggr(key, namedByAny, namedByUnmarked, false));

        [Fact]
        public void AMarkedFileStaysInFiles() => Assert.Null(Scanner.FileAggr(@"N:\Films\x.mkv", true, false, true));   // Defender detected it

        // ---- the end of the scan decides (Aggr.Finish)

        static void Docs(Table t)
        {
            t.Add("2026-11-25 03:53:12", "", @"C:\Users\Fadi pc\Desktop\saved\masq.txt");
            t.Aggr("documents opened");
            t.Add("2026-11-25 03:53:13", "", @"C:\Users\Fadi pc\Dropbox\notes.txt");
            t.Aggr("documents opened");
        }

        static bool NextToADetection(string text) => text.Contains(@"\Desktop\saved\");   // stands for Ctx.MarksOf / SUMMARY

        [Fact]
        public void AMarkALaterModuleContradictsGoes()
        {
            var normal = Write(false, Docs, NextToADetection);
            Assert.Contains(@"2026-11-25 03:53:12 C:\Users\Fadi pc\Desktop\saved\masq.txt", normal);   // unmarked
            Assert.Contains(@"2026-11-25 03:53:13 C:\Users\Fadi pc\Dropbox\notes.txt ~", normal);
            var aggressive = Write(true, Docs, NextToADetection);
            Assert.Contains(@"2026-11-25 03:53:12 C:\Users\Fadi pc\Desktop\saved\masq.txt", aggressive);
            Assert.DoesNotContain(aggressive, l => l.Contains("notes.txt"));
            Assert.Contains("(Hidden by -aggressive: documents opened (1).)", aggressive);
            Assert.DoesNotContain(aggressive, l => l.Contains("\u0001"));
        }

        [Fact]
        public void DataThatEndsLikeTheMarkIsWrittenOtherwise()
        {
            var l = Write(true, t =>
            {
                t.Add("2026-11-01 10:00:00", "", @"E:\Films\x ~");
                t.More("command", "cd ~");
                t.Add("2026-11-01 10:00:01", "", @"C:\a\noise.exe");
                t.Aggr("noise");
            });
            Assert.Contains(@"2026-11-01 10:00:00 ""E:\Films\x ~""", l);   // quoted: not taken for a mark, not hidden
            Assert.Contains(@"    command: ""cd ~""", l);
            Assert.DoesNotContain(l, x => x.Contains("noise.exe"));
        }

        [Fact]
        public void OnlyTheValueThatEndsTheLineIsQuoted()
        {
            var l = Write(false, t =>
            {
                t.Add("2026-11-01 10:00:00", "", @"E:\Films\x ~", "[unsigned]", "~");   // a lone "~" detail ends the line
                t.Add("2026-11-01 10:00:01", "", @"E:\Films\y ~", "-", "size 3");        // " ~" in the middle: unchanged
            }, "@time", "<flags", "*item", "=status", "=details");
            Assert.Contains(@"2026-11-01 10:00:00 E:\Films\x ~ => [unsigned]; ""~""", l);
            Assert.Contains(@"2026-11-01 10:00:01 E:\Films\y ~ => size 3", l);
            Assert.DoesNotContain(l, Aggr.IsMarked);
        }

        [Theory]
        [InlineData("command: cd ~", @"command: ""cd ~""")]
        [InlineData("command: ~", @"command: ""~""")]
        [InlineData("command: cd ~/x", "command: cd ~/x")]
        [InlineData("program: C:\\PROGRA~1\\x.exe", "program: C:\\PROGRA~1\\x.exe")]
        public void SubLineValues(string keyValue, string written) => Assert.Equal(written, Table.WrittenMore(keyValue));

        [Fact]
        public void OnlyLinesOfATableWithMarksAreMarks()
        {
            var lines = new List<string> { "(comment ~", @"2026-11-01 C:\x\y ~", Aggr.Start, "(line: x)", "", @"C:\a\n.exe ~", Aggr.EndOf(new[] { "noise" }) };
            Aggr.Finish(lines, 0, null, true);
            Assert.Equal(new[] { "(comment ~", @"2026-11-01 C:\x\y ~", "(Hidden by -aggressive: noise (1).)" }, lines);
        }

        [Fact]
        public void DecideFirstHideLast()
        {
            var a = new Log(); var t = new Table("@time", "<flags", "*item");
            Docs(t); t.WriteTo(a);
            var lines = a.Lines;
            Aggr.Finish(lines, 0, NextToADetection, false, final: false);   // before FILES: decided, the marks and Start / End stay
            Assert.Contains(lines, l => l.EndsWith(@"masq.txt", StringComparison.Ordinal));
            Assert.Contains(lines, l => l.EndsWith(@"notes.txt ~", StringComparison.Ordinal));
            Assert.Equal(2, lines.Count(Aggr.IsSentinel));
            Assert.Equal(new[] { @"2026-11-25 03:53:12 C:\Users\Fadi pc\Desktop\saved\masq.txt" },
                         Aggr.Unmarked(lines).Where(l => l.Contains(@":\")).ToArray());   // what FILES counts as shown
            Aggr.Finish(lines, 0, null, true);   // the end: hidden, with the reason of the mark that was left
            Assert.Contains("(Hidden by -aggressive: documents opened (1).)", lines);
            Assert.DoesNotContain(lines, Aggr.IsSentinel);
            Assert.DoesNotContain(lines, l => l.Contains("notes.txt"));
        }

        [Fact]
        public void ARepeatKeepsItsMark()
        {
            var normal = Write(false, t =>
            {
                t.Add("2026-11-20 02:12:04", "", @"C:\Users\Fadi pc\Downloads\saved.zip");
                t.Add("2026-11-20 02:12:04", "", @"C:\Users\Fadi pc\Downloads\saved.zip");
                t.Aggr(Aggr.Dup("the same file downloaded again from the same host"));
            }, _ => true);
            Assert.Equal(1, normal.Count(Aggr.IsMarked));   // the first line shows it; the repeat stays marked although SUMMARY names the file
        }

        [Fact]
        public void TheReasonsSurviveLinesCopiedBetweenLogs()
        {
            var a = new Log(); var t = new Table("@time", "<flags", "*item");
            Docs(t); t.WriteTo(a);
            var b = new List<string> { "x", "" };
            b.AddRange(a.Lines);   // as Scanner.Append does
            Aggr.Finish(b, 0, null, true);
            Assert.Equal(new[] { "x", "", "(Hidden by -aggressive: documents opened (2).)" }, b);
        }

        [Fact]
        public void PathCandidatesEndAtEveryBlank()
        {
            var c = Aggr.PathCandidates(@"2026-11-20 [PF] C:\Users\Fadi pc\Desktop\saved\RobRunAIO.exe [gone] => x").ToList();
            Assert.Contains(@"C:\Users\Fadi", c);
            Assert.Contains(@"C:\Users\Fadi pc\Desktop\saved\RobRunAIO.exe", c);
        }

        [Fact]
        public void BulkAmcacheFolders()
        {
            var msys = Enumerable.Range(0, Scanner.AmcacheBulk).Select(i => $@"C:\msys64\usr\bin\tool{i}.exe").ToList();
            var few = new[] { @"C:\Program Files (x86)\EaseUS\aliyun\a.dll", @"C:\Program Files (x86)\EaseUS\aliyun\b.dll" };
            var res = Scanner.AmcacheBulkFolders(msys.Concat(few), new HashSet<string>(), _ => false);
            Assert.Equal(Scanner.AmcacheBulk, res.Count);
            Assert.All(msys, k => Assert.Equal(@"Amcache-only files in C:\msys64\usr\bin\", res[k]));
            // one of them named by a line that stays: the folder stays
            Assert.Empty(Scanner.AmcacheBulkFolders(msys, new HashSet<string> { msys[3] }, _ => false));
            // a drop location or a random-named folder stays
            var temp = Enumerable.Range(0, Scanner.AmcacheBulk).Select(i => $@"C:\Users\a\AppData\Local\Temp\x\f{i}.dll");
            Assert.Empty(Scanner.AmcacheBulkFolders(temp, new HashSet<string>(), _ => false));
            var rnd = Enumerable.Range(0, Scanner.AmcacheBulk).Select(i => $@"C:\Users\a\AppData\Local\Z0533B4Lo\MVg4zIU\f{i}.dll");
            Assert.Empty(Scanner.AmcacheBulkFolders(rnd, new HashSet<string>(), _ => false));
        }

        // ---- random-named folders (normal whitelist gap: the Adobe-signed S_Pipe.exe sideload host)

        [Theory]
        [InlineData(@"C:\Users\x\AppData\Local\Z0533B4Lo\MVg4zIU\clip\S_Pipe.exe", true)]
        [InlineData(@"C:\Users\x\kgw7Hp\kOsW3u0gxT\clip\S_Pipe.exe", true)]
        [InlineData(@"C:\Users\x\AppData\Local\Programs\Microsoft VS Code\2C33B50B16\Code.exe", false)]   // hex build id
        [InlineData(@"C:\Users\x\AppData\Local\Discord\app-1.0.9268\Discord.exe", false)]
        [InlineData(@"C:\Program Files\WindowsApps\Microsoft.WindowsTerminal_1.24.12741.0_x64__8wekyb3d8bbwe\wt.exe", false)]
        [InlineData(@"C:\Users\x\AppData\Local\Wondershare\Wondershare Filmora\15.5.3.19914\FilmoraTray.exe", false)]
        [InlineData(@"C:\Users\x\AppData\Local\Z0533B4Lo.exe", false)]   // the file name is not a folder
        public void RandomFolder(string path, bool random) => Assert.Equal(random, Names.RandomFolder(path));

        // ---- PREFETCH loaded files

        [Theory]
        // Ren'Py's engine: the game's renpy\ and lib\pythonX\, from the game exe or the real exe in lib\py3-windows-*\
        [InlineData(@"E:\Games\Memories\Memories.exe", @"E:\Games\Memories\renpy\common\00start.rpyc", "python")]
        [InlineData(@"E:\Games\Memories\Memories.exe", @"E:\Games\Memories\lib\python3.9\encodings\__init__.pyc", "python")]
        [InlineData(@"E:\Games\Memories\lib\py3-windows-x86_64\Memories.exe", @"E:\Games\Memories\renpy\display\core.py", "python")]
        [InlineData(@"E:\Games\Memories\Memories.exe", @"E:\Games\Memories\lib\python3.9\site-packages\evil.py", null)]
        // RenLoader: what the lab must show stays (the archive, the padded runtime, the hidden data file, the payload in Temp)
        [InlineData(@"C:\Users\a\Downloads\x\Setup.exe", @"C:\Users\a\Downloads\x\game\libwin.rpa", null)]
        [InlineData(@"C:\Users\a\Downloads\x\Setup.exe", @"C:\Users\a\Downloads\x\data\libpython.rpmc", null)]
        [InlineData(@"C:\Users\a\Downloads\x\Setup.exe", @"C:\Users\a\Downloads\x\lib\py3-windows-x86_64\librenpython.dll", null)]
        [InlineData(@"C:\Users\a\Downloads\x\Setup.exe", @"C:\Users\a\AppData\Local\Temp\tmp-17353-SYyfVstcIxZS\OrrBcith7.exe", null)]
        [InlineData(@"C:\Python312\python.exe", @"C:\Python312\lib\python3.12\os.py", null)]   // an interpreter runs what it is given
        [InlineData(@"C:\Windows\System32\wimserv.exe", @"C:\$WinREAgent\Scratch\Mount\Windows\System32\x.dll", "winre")]
        [InlineData(@"C:\Users\a\Downloads\wimserv.exe", @"C:\$WinREAgent\Scratch\Mount\Windows\System32\x.dll", null)]
        [InlineData(@"C:\Program Files\Google\Chrome\Application\chrome.exe", @"C:\Users\a\AppData\Local\Temp\CHROMIUMCRX_CHROME_UNPACKER_BEGINUNZIPPING1_2\JS\BACKGROUND.JS", "crx")]
        [InlineData(@"C:\Users\a\Tools\Astro.exe", @"C:\Users\a\AppData\Local\Temp\.net\Astro\abc123\System.Private.CoreLib.dll", "unpack")]
        [InlineData(@"C:\Users\a\Tools\Astro.exe", @"C:\Users\a\AppData\Local\Temp\.net\Other\abc123\x.dll", null)]
        [InlineData(@"C:\Users\a\AppData\Local\Medal\current\Medal.exe", @"C:\Users\a\AppData\Local\Medal\recorder-1\recorder.dll", "app")]
        [InlineData(@"C:\Users\a\AppData\Local\Discord\app-1.0.9268\Discord.exe", @"C:\Users\a\AppData\Local\Discord\app-1.0.9268\modules\discord_desktop_core-1\discord_desktop_core\index.js", null)]
        [InlineData(@"C:\Users\a\AppData\Local\Discord\app-1.0.9268\Discord.exe", @"C:\Users\a\AppData\Local\Discord\app-1.0.9268\updater_launcher.exe", null)]   // token stealers
        [InlineData(@"C:\Users\a\Downloads\x\Setup.exe", @"C:\Users\a\Downloads\x\renpy\common\00start.rpy", "python")]   // the kind; LoadedAggr keeps it (lure name)
        public void LoadedFileKinds(string program, string loaded, string kind) => Assert.Equal(kind, Prefetch.LoadedKind(program, loaded));

        [Theory]
        [InlineData(@"D:\DownloadsHDD\1462-_WRC_GENERATIONS_THE_FIA_WRC_OFFICI_ARCHIVE_FREE_9011\SETUP.EXE", true)]   // RenLoader lures
        [InlineData(@"C:\Users\a\AppData\Local\Temp\01C9DE89-ECC1-4CC6-9288-670F85FD3A1C_ARCHIVE_WIN_2255.ZIP.A1C\SETUP.EXE", true)]
        [InlineData(@"J:\Misc\Misc Games\Project_[v1.2.0]_[uw_Archive_win_2058\Setup.exe", true)]
        [InlineData(@"C:\Users\a\Downloads\Emberbound-1.9.0-win\Emberbound.exe", true)]                                // a game run from Downloads
        [InlineData(@"C:\Games\F new\Emberbound-1.9.0-win\Emberbound.exe", false)]                                    // games
        [InlineData(@"E:\New folder\Memories-0.5.5-pc\Memories.exe", false)]
        public void RenLoaderRuntimesKeepTheirEngineFiles(string program, bool lure) => Assert.Equal(lure, Prefetch.LureRuntime(program));

        [Theory]
        [InlineData(@"C:\Users\a\AppData\Local\Discord\app-1.0.9268\Discord.exe", true)]
        [InlineData(@"C:\Users\a\AppData\Local\DiscordCanary\app-1.0.1\DiscordCanary.exe", true)]
        [InlineData(@"C:\Users\a\AppData\Roaming\BetterDiscord\data\x.dll", true)]
        [InlineData(@"C:\Users\a\AppData\Local\slack\app-4.53.280\slack.exe", false)]
        public void DiscordIsNeverMarked(string path, bool stealerTarget) => Assert.Equal(stealerTarget, Aggr.StealerTarget(path));

        // ---- TIMELINE bursts

        [Fact]
        public void FiveNewFilesWithinTenMinutesAreABurst()
        {
            var t0 = new DateTime(2026, 11, 1, 10, 0, 0);
            var items = Enumerable.Range(0, 5).Select(i => (t0.AddMinutes(2 * i), "app|signer")).ToList();
            Assert.Equal(5, Scanner.Bursts(items).Count);
            Assert.Empty(Scanner.Bursts(items.Take(4).ToList()));
            var spread = Enumerable.Range(0, 5).Select(i => (t0.AddMinutes(4 * i), "app|signer")).ToList();   // 16 minutes
            Assert.Empty(Scanner.Bursts(spread));
            var mixed = items.Select((x, i) => (x.Item1, i == 2 ? "other|signer" : x.Item2)).ToList();   // one of another app
            Assert.Empty(Scanner.Bursts(mixed));
            Assert.Empty(Scanner.Bursts(items.Select(x => (x.Item1, (string)null)).ToList()));   // not candidates
        }

        // ---- SOFTWARE

        [Fact]
        public void ProductCodesArePackedLikeWindowsInstallerDoes()
        {
            Assert.Equal("00002109110000000000000000F01FEC", Software.PackedGuid("{90120000-0011-0000-0000-0000000FF1CE}"));
            Assert.Null(Software.PackedGuid("not a guid"));
        }

        [Fact]
        public void AnUpdateAndTheRemovedVersionHaveTheSameNameBase() =>
            Assert.Equal(Software.NameBase("Microsoft .NET Runtime - 8.0.33 (x64)"), Software.NameBase("Microsoft .NET Runtime - 8.0.32 (x64)"));

        // ---- whitelist file

        [Fact]
        public void TheBuiltInFileHasTheAggressiveScopes()
        {
            var built = Whitelist.Parse(Util.Embedded(Whitelist.OverrideFile));
            Assert.NotEmpty(built.Of("aggr:pair"));
            Assert.NotEmpty(built.Of("aggr:staging"));
            Assert.Contains(built.Of("aggr:pair"), v => v.Contains("ONEDRIVE") && v.EndsWith("=> Microsoft Corporation"));
            Assert.DoesNotContain(built.Of("aggr:pair"), v => v.IndexOf("DISCORD", StringComparison.OrdinalIgnoreCase) >= 0);   // token stealers
        }

        [Theory]
        [InlineData("aggr:pair\t^\\\\USERS\\\\")]                       // no signer
        [InlineData("aggr:pair\t^\\\\(USERS\\\\ => Someone")]           // bad regex
        [InlineData("aggr:staging\t^\\\\(X")]
        public void ABrokenAggressiveLineThrows(string line) =>
            Assert.ThrowsAny<Exception>(() => Whitelist.Parse(line + "\r\n"));

        [Fact]
        public void StagingIsOnTheSystemDriveOnly()
        {
            Assert.True(Aggr.Staging(Rules.SystemDrive + @"\Windows\SystemTemp\GoogleUpdater_chrome_Unpacker_BeginUnzipping28820_34312283\UpdaterSetup.exe"));
            Assert.True(Aggr.Staging(Rules.SystemDrive + @"\Program Files\Common Files\microsoft shared\ClickToRun\Updates\16.0.20527.20150\OfficeClickToRun.exe"));
            Assert.False(Aggr.Staging(@"Q:\Windows\SystemTemp\GoogleUpdater_chrome_Unpacker_BeginUnzipping1_2\UpdaterSetup.exe"));
            Assert.False(Aggr.Staging(Rules.SystemDrive + @"\Windows\SystemTemp\evil\UpdaterSetup.exe"));
        }

        [Fact]
        public void ThePairNeedsTheFileAndItsSigner() =>
            Assert.False(Aggr.Pair(@"C:\Users\nobody\AppData\Local\Microsoft\OneDrive\OneDrive.exe"));   // not on disk: no signature to check
    }

    [CollectionDefinition("static rules", DisableParallelization = true)]
    public class StaticRulesCollection { }
}
