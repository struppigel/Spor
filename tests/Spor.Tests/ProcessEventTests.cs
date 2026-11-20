using System.Linq;
using System.Text.RegularExpressions;
using Xunit;

namespace Spor.Tests
{
    /// <summary>Process creation events (4688, Sysmon 1) kept for the timeline, and the LEGEND layout of the new sources.</summary>
    public class ProcessEventTests
    {
        const string Temp = @"C:\Users\anna\AppData\Local\Temp\tmp-1-x\host.exe";

        [Fact]
        public void ProxyExecutionIsKept() =>
            Assert.True(Rules.ProcessEventKept(Temp, @"C:\Windows\System32\cmd.exe", Temp, proxyExec: true));

        [Fact]
        public void AnInterpreterWithAScriptIsKept() =>
            Assert.True(Rules.ProcessEventKept(@"C:\Windows\System32\wscript.exe", @"C:\Windows\explorer.exe",
                                               @"""C:\Windows\System32\WScript.exe"" ""C:\Users\anna\Downloads\invoice.js""", false));

        [Fact]
        public void ALolbinStartingAProgramOutsideTrustedLocationsIsKept() =>
            Assert.True(Rules.ProcessEventKept(Temp, @"C:\Windows\System32\cmd.exe", Temp, false));

        [Fact]
        public void APlainProgramStartIsNot()
        {
            // explorer starting Notepad: neither is a LOLBin or interpreter
            Assert.False(Rules.ProcessEventKept(@"C:\Windows\System32\notepad.exe", @"C:\Windows\explorer.exe", "notepad.exe", false));
            // a user program started from Explorer
            Assert.False(Rules.ProcessEventKept(@"C:\Users\anna\AppData\Local\Programs\App\app.exe", @"C:\Windows\explorer.exe", "app.exe", false));
        }

        [Fact]
        public void ALolbinWithHarmlessArgumentsIsNot() =>
            Assert.False(Rules.ProcessEventKept(@"C:\Windows\System32\cmd.exe", @"C:\Windows\explorer.exe", @"C:\Windows\System32\cmd.exe /c dir", false));

        [Fact]
        public void LegendSourcesHaveTwoBlanksBeforeTheirMeaning()
        {
            // log readers split code and meaning at two or more blanks (SYSMON is 6 characters)
            var log = new Log();
            Scanner.Legend(log);
            var sources = log.Lines.SkipWhile(l => !l.StartsWith("Sources")).Skip(1).TakeWhile(l => l.Length > 0).ToList();
            Assert.Contains(sources, l => l.TrimStart().StartsWith("SYSMON"));
            Assert.All(sources, l => Assert.Matches(new Regex(@"^    \S+ {2,}\S"), l));
        }
    }
}
