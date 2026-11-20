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

        [Theory]
        // the RenLoader lab run: forfiles started by the dropper, pointed at its random Temp folder
        [InlineData(@"C:\Windows\System32\forfiles.exe", @"C:\Users\anna\Downloads\Game\Setup.exe",
                    @"forfiles.exe /p C:\Users\anna\AppData\Local\Temp\tmp-79694-fT9hO3C4f7Gp /m ehyISWlPN.exe /c ""cmd /c call @path""",
                    @"C:\Users\anna\AppData\Local\Temp\tmp-79694-fT9hO3C4f7Gp")]
        [InlineData(@"C:\Windows\System32\pcalua.exe", @"C:\Windows\explorer.exe", @"pcalua.exe -a C:\Users\anna\Downloads\x.exe", @"C:\Users\anna\Downloads\x.exe")]
        [InlineData(@"C:\Windows\System32\conhost.exe", @"C:\Windows\System32\svchost.exe", @"conhost.exe --headless C:\Users\anna\AppData\Roaming\x\run.cmd",
                    @"C:\Users\anna\AppData\Roaming\x\run.cmd")]
        // cmd started by forfiles: the command line has no program part
        [InlineData(@"C:\Windows\System32\cmd.exe", @"C:\Windows\System32\forfiles.exe", @"/c call ""C:\Users\anna\AppData\Local\Temp\tmp-1-x\a.exe""",
                    @"C:\Users\anna\AppData\Local\Temp\tmp-1-x\a.exe")]
        public void AProxyLauncherPointedOutsideTrustedLocationsIsKept(string image, string parent, string commandLine, string target)
        {
            Assert.Equal(target, Rules.ProxyLaunchTarget(image, commandLine));
            Assert.True(Rules.ProcessEventKept(image, parent, commandLine, false));
        }

        [Theory]
        // a launcher pointed at Windows only
        [InlineData(@"C:\Windows\System32\forfiles.exe", @"forfiles /p C:\Windows\Temp /c ""cmd /c echo""")]
        [InlineData(@"C:\Windows\System32\forfiles.exe", @"forfiles /p C:\Windows\Logs /m *.log /c ""cmd /c echo @file""")]
        // a LOLBin run with a user folder, but not as a launcher
        [InlineData(@"C:\Windows\System32\forfiles.exe", @"forfiles /p C:\Users\anna\Documents /m *.txt")]
        [InlineData(@"C:\Windows\System32\conhost.exe", @"\??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1")]
        // the shell opening a folder ("show in folder")
        [InlineData(@"C:\Windows\explorer.exe", @"""C:\Windows\explorer.exe"" /select,""C:\Users\anna\Downloads\a.zip""")]
        public void OtherLauncherRunsAreNot(string image, string commandLine)
        {
            Assert.Null(Rules.ProxyLaunchTarget(image, commandLine));
            Assert.False(Rules.ProcessEventKept(image, @"C:\Windows\explorer.exe", commandLine, false));
        }

        [Fact]
        public void ACmdStartedByForfilesIsAProxyLaunch() =>
            Assert.True(Rules.ProxyLaunch(@"C:\Windows\System32\cmd.exe", @"/c call ""C:\Users\anna\AppData\Local\Temp\tmp-1-x\a.exe"""));

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
