using System;
using System.Collections.Generic;
using System.Linq;
using Xunit;

namespace Spor.Tests
{
    /// <summary>Timeline lines: which events of one file are one line, its time, and its merged details.</summary>
    public class TimelineTests
    {
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
    }
}
