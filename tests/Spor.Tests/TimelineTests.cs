using System;
using System.Collections.Generic;
using System.Linq;
using Xunit;

namespace Spor.Tests
{
    /// <summary>Timeline lines: which events of one file are one line, its time, and its merged details.</summary>
    public class TimelineTests
    {
        const string VsTemp = @"C:\Users\anna\AppData\Local\Temp\yey3hk14\";

        /// <summary>One file in folders that differ only in numbers or ids: one group.</summary>
        [Theory]
        [InlineData(@"C:\Users\a\AppData\Local\Discord\app-1.0.9267\Discord.exe", @"C:\Users\a\AppData\Local\Discord\app-1.0.9300\Discord.exe")]
        [InlineData(@"C:\Program Files\EA\EA Desktop\13.813.0.6326-1792559521\EADesktop.exe", @"C:\Program Files\EA\EA Desktop\13.827.2.6342-1794635423\EADesktop.exe")]
        [InlineData(@"C:\Windows\Temp\{3558506C-BFA8-49C4-BF95-665A8929F14D}\.cr\vc_redist.x64.exe", @"C:\Windows\Temp\{FDA43EC1-BAF8-4F17-B13B-FCCE17B7C3E2}\.cr\vc_redist.x64.exe")]
        [InlineData(@"C:\lab\20261103-075951-1\run.exe", @"C:\lab\20261104-101010-2\run.exe")]
        [InlineData(@"C:\Users\a\AppData\Local\Programs\Microsoft VS Code\a44adf7f53\x\vsce-sign.exe", @"C:\Users\a\AppData\Local\Programs\Microsoft VS Code\69047191fc\x\vsce-sign.exe")]
        [InlineData(VsTemp + @"Microsoft.Net.8.0.Runtime.811E9382F7C0D322A19E\aspnetcore-runtime-x64.zip", VsTemp + @"Microsoft.Net.10.0.Runtime.30D124C19BCC397E60A2\aspnetcore-runtime-x64.zip")]
        [InlineData(VsTemp + @"Microsoft.Net.8.0.WindowsDesktop.Runtime.8D10AEB2000708243E0C\w.zip", VsTemp + @"Microsoft.Net.10.0.WindowsDesktop.Runtime.3348394A88A27D0E93BC\w.zip")]
        public void FoldersThatDifferOnlyInNumbersAreOneGroup(string a, string b) =>
            Assert.Equal(Scanner.Shape(a), Scanner.Shape(b), StringComparer.OrdinalIgnoreCase);

        /// <summary>
        /// Differently named folders with a random id are not one group, whether the id happens to have 6 digits in a row or not
        /// (Spor 0.7.1 put the cab1.cab of four Visual Studio packages on one line).
        /// </summary>
        [Theory]
        [InlineData(VsTemp + @"Microsoft.VisualStudio.MinShell.Shared.Msi.5277338BB25077D7590F\cab1.cab", VsTemp + @"Microsoft.VisualStudio.GitHubProtocolHandler.Msi.6725FA95520F1A897109\cab1.cab")]
        [InlineData(VsTemp + @"Microsoft.VisualStudio.FileHandler.Msi.040167F1CC8B0F1C8A76\cab1.cab", VsTemp + @"Microsoft.VisualStudio.VsWebProtocolSelector.Msi.8983E0359E2E9C7BD859\cab1.cab")]
        [InlineData(@"C:\Users\a\AppData\Local\Temp\5ed5c394-9271-42ee-9a14-487df8b1b262_DaVinci_Resolve_18.6.6.zip.262\x.exe", @"C:\Users\a\AppData\Local\Temp\4145fe86-3a38-4c30-a23e-23ebdb7f5167_FrostyModManager_1.0.7.zip.167\x.exe")]
        [InlineData(@"C:\Games\Far Cry 4\x.exe", @"C:\Games\Far Cry 5\x.exe")]
        public void DifferentlyNamedFoldersAreNotOneGroup(string a, string b) =>
            Assert.NotEqual(Scanner.Shape(a), Scanner.Shape(b), StringComparer.OrdinalIgnoreCase);

        const string Cmd = @"C:\Windows\System32\cmd.exe";
        static readonly DateTime At = new DateTime(2026, 11, 20, 7, 59, 40, DateTimeKind.Utc);

        static TEvent Ev(int seconds, string src, int? pid, string extra = null, params string[] flags) =>
            new TEvent { T = At.AddSeconds(seconds), Src = src, Path = Cmd, Pid = pid, Extra = extra, Flags = flags.Length > 0 ? flags.ToList() : null };

        [Fact]
        public void AFlaggedProcessKeepsItsOwnLine()
        {
            // the lab run: cmd /c call from forfiles (flagged), then a harmless cmd.exe 94 s later, BAM without a PID
            var lines = Scanner.Lines(new[]
            {
                Ev(0, "4688", 7696, "parent forfiles.exe", "!proxy-exec"), Ev(0, "PROC", 7696, "running, pid 7696, parent forfiles.exe"),
                Ev(94, "4688", 7448, "parent svchost.exe"), Ev(94, "PROC", 7448), Ev(94, "BAM", null),
            });
            Assert.Equal(2, lines.Count);
            Assert.Equal(new int?[] { 7696, 7696 }, lines[0].Select(e => e.Pid));
            Assert.Equal(new int?[] { 7448, 7448, null }, lines[1].Select(e => e.Pid));
            Assert.Equal(At, Scanner.LineTime(lines[0]));
        }

        [Fact]
        public void AFlaggedEventWithANewPidStartsALine()
        {
            var lines = Scanner.Lines(new[] { Ev(0, "4688", 1, "parent explorer.exe"), Ev(30, "4688", 2, null, "!proxy-exec") });
            Assert.Equal(2, lines.Count);
        }

        [Fact]
        public void UnflaggedProcessesStillMerge()
        {
            // the same program started by several processes within 2 minutes, nothing flagged: one line as before
            var lines = Scanner.Lines(new[] { Ev(0, "4688", 1), Ev(60, "PROC", 2), Ev(100, "BAM", null), Ev(200, "4688", 3) });
            Assert.Single(lines);
            // !lolbin and !known-malware do not count
            lines = Scanner.Lines(new[] { Ev(0, "4688", 1, null, "!lolbin"), Ev(30, "4688", 2, null, Autodetect.Flag) });
            Assert.Single(lines);
        }

        [Fact]
        public void EventsWithoutAPidJoinAFlaggedLine()
        {
            // file events and runs without a PID are the same program start
            var lines = Scanner.Lines(new[] { Ev(0, "NEW", null, null, "!motw-removed"), Ev(3, "4688", 5, null, "!proxy-exec"), Ev(4, "PF", null) });
            Assert.Single(lines);
        }

        [Fact]
        public void TwoMinutesApartAreTwoLines() =>
            Assert.Equal(2, Scanner.Lines(new[] { Ev(0, "PF", null), Ev(121, "PF", null) }).Count);

        [Fact]
        public void ALineIsAtItsFirstFlaggedEvent()
        {
            // flagged: when it happened (the first flagged event); unflagged: the latest event, as before
            var flagged = new List<TEvent> { Ev(0, "NEW", null), Ev(5, "PROC", 9, null, "!proxy-exec"), Ev(8, "4688", 9, null, "!proxy-exec"), Ev(20, "BAM", null) };
            Assert.Equal(At.AddSeconds(5), Scanner.LineTime(flagged));
            Assert.Equal(At.AddSeconds(20), Scanner.LineTime(new List<TEvent> { Ev(0, "NEW", null), Ev(20, "BAM", null, null, "!lolbin") }));
            // !known-malware counts here: the first time the file was seen
            Assert.Equal(At, Scanner.LineTime(new List<TEvent> { Ev(0, "NEW", null, null, Autodetect.Flag), Ev(9, "PROC", 3, null, Autodetect.Flag) }));
        }

        [Fact]
        public void ParentIsNotRepeated()
        {
            // PROC and 4688 of one process: "running, pid 2744, parent cmd.exe" + "parent cmd.exe; command line ..."
            Assert.Equal(new[] { "zone 0", "running, pid 2744, parent cmd.exe", "command line \"x.exe\"" },
                         Scanner.MergeDetails(new[] { "zone 0", "running, pid 2744, parent cmd.exe", null, "parent cmd.exe; command line \"x.exe\"", "zone 0" }));
        }

        [Fact]
        public void PartsOfOtherEventsAreLeftOutOnce()
        {
            Assert.Equal(new[] { "a", "b", "c" }, Scanner.MergeDetails(new[] { "a; b", "b; c" }));
            // a part of one event stays as it is, even repeated (a command line can contain "; ")
            Assert.Equal(new[] { "command line cmd /c echo x", "x", "x" }, Scanner.MergeDetails(new[] { "command line cmd /c echo x; x; x" }));
            // a different parent is kept
            Assert.Equal(new[] { "running, pid 1, parent a.exe", "parent b.exe" }, Scanner.MergeDetails(new[] { "running, pid 1, parent a.exe", "parent b.exe" }));
        }

        [Fact]
        public void PrefetchAndBamGoToTheNearestProcess()
        {
            // in module order: ExecEvidence adds BAM and PF before the 4688 events, Processes comes later
            var lines = Scanner.Lines(new[]
            {
                Ev(94, "BAM", null), Ev(93, "PF", null),
                Ev(0, "4688", 7696, "parent forfiles.exe", "!proxy-exec"), Ev(94, "4688", 7448, "parent svchost.exe"),
                Ev(0, "PROC", 7696, "running, pid 7696, parent forfiles.exe"), Ev(94, "PROC", 7448),
            });
            Assert.Equal(2, lines.Count);
            Assert.Equal(new[] { "4688", "PROC" }, lines[0].Select(e => e.Src));
            Assert.Equal(new[] { "4688", "BAM", "PF", "PROC" }, lines[1].Select(e => e.Src).OrderBy(s => s));
        }

        [Fact]
        public void AnSrumHourJoinsItsRun()
        {
            // the lab: NEW 03:33:50, PROC 03:33:52, SRUM's hour bucket 03:54:00; !known-malware on all of them
            var t = new DateTime(2026, 11, 20, 3, 33, 50, DateTimeKind.Utc);
            TEvent At(DateTime when, string src, int? pid) => new TEvent { T = when, Src = src, Path = Cmd, Pid = pid, Flags = new List<string> { Autodetect.Flag } };
            var lines = Scanner.Lines(new[] { At(t, "NEW", null), At(t.AddSeconds(2), "PROC", 5), At(t.AddMinutes(20).AddSeconds(10), "SRU", null) });
            Assert.Single(lines);
            Assert.Equal(t, Scanner.LineTime(lines[0]));
            // more than an hour away, or hours seen by SRUM alone: lines of their own, as before
            Assert.Equal(2, Scanner.Lines(new[] { At(t, "NEW", null), At(t.AddMinutes(90), "SRU", null) }).Count);
            Assert.Equal(2, Scanner.Lines(new[] { At(t, "SRU", null), At(t.AddHours(1), "SRU", null) }).Count);
        }

        [Fact]
        public void AFlagInTheFileNameDatesTheLineAtItsFirstEvent()
        {
            const string Lure = @"C:\Users\anna\Downloads\invoice.pdf.exe";
            var line = new List<TEvent> { new TEvent { T = At, Src = "NEW", Path = Lure }, new TEvent { T = At.AddSeconds(50), Src = "BAM", Path = Lure } };
            Assert.Equal(At, Scanner.LineTime(line));
        }

        [Fact]
        public void TheParentIsComparedWithinOneProcessIgnoringCase()
        {
            // PROC writes "Explorer.EXE", 4688 "explorer.exe": one process, one parent
            Assert.Equal(new[] { "running, pid 1, parent Explorer.EXE", "command line a" },
                         Scanner.MergeDetails(new (int?, string)[] { (1, "running, pid 1, parent Explorer.EXE"), (1, "parent explorer.exe; command line a") }));
            // another process's parent stays: pid 6 had its own command line
            Assert.Equal(new[] { "running, pid 5, parent cmd.exe", "parent cmd.exe", "command line x" },
                         Scanner.MergeDetails(new (int?, string)[] { (5, "running, pid 5, parent cmd.exe"), (6, "parent cmd.exe; command line x") }));
        }
    }
}
