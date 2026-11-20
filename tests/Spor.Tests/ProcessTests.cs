using System;
using System.Collections.Generic;
using Spor.Modules;
using Xunit;

namespace Spor.Tests
{
    /// <summary>!proxy-exec and the parent chain of RUNNING PROCESSES.</summary>
    public class ProcessTests
    {
        const string Temp = @"C:\Users\anna\AppData\Local\Temp\tmp-1-x\host.exe";

        [Theory]
        [InlineData(@"C:\Windows\System32\forfiles.exe", @"forfiles.exe /p C:\Users\anna\AppData\Local\Temp\tmp-1-x /m host.exe /c ""cmd /c call @path""")]
        [InlineData(@"C:\Windows\System32\cmd.exe", @"C:\Windows\system32\cmd.exe /c call C:\Users\anna\AppData\Local\Temp\tmp-1-x\host.exe")]
        [InlineData(@"C:\Windows\System32\pcalua.exe", @"pcalua.exe -a C:\Users\anna\AppData\Local\Temp\tmp-1-x\host.exe")]
        [InlineData(@"C:\Windows\System32\conhost.exe", @"conhost.exe --headless C:\Users\anna\AppData\Local\Temp\tmp-1-x\host.exe")]
        [InlineData(@"C:\Windows\explorer.exe", @"C:\Windows\explorer.exe ""C:\Users\anna\AppData\Local\Temp\tmp-1-x\host.exe""")]
        [InlineData(@"C:\Windows\System32\rundll32.exe", @"rundll32.exe url.dll,FileProtocolHandler C:\Users\anna\AppData\Local\Temp\tmp-1-x\host.exe")]
        [InlineData(@"C:\Windows\System32\wbem\WMIC.exe", @"wmic process call create C:\Users\anna\AppData\Local\Temp\tmp-1-x\host.exe")]
        public void ProxyLaunchers(string launcher, string commandLine) => Assert.True(Rules.ProxyExec(launcher, commandLine, Temp));

        [Fact]
        public void TheShellWithoutArgumentsIsNot()
        {
            Assert.False(Rules.ProxyExec(@"C:\Windows\explorer.exe", @"C:\Windows\Explorer.EXE", Temp));
            Assert.False(Rules.ProxyExec(@"C:\Windows\explorer.exe", @"C:\Windows\explorer.exe /factory,{75dff2b7-6936-4c06-a8bb-676a7b00b24b} -Embedding", Temp));
        }

        [Fact]
        public void AChildInProgramFilesIsNot()
        {
            Assert.False(Rules.ProxyExec(@"C:\Windows\System32\cmd.exe", @"cmd.exe /c call ""C:\Program Files\Vendor\app.exe""", @"C:\Program Files\Vendor\app.exe"));
        }

        [Fact]
        public void PlainCmdAndForfilesWithoutCommandAreNot()
        {
            Assert.False(Rules.ProxyExec(@"C:\Windows\System32\cmd.exe", @"cmd.exe /c C:\Users\anna\run.bat", Temp));
            Assert.False(Rules.ProxyExec(@"C:\Windows\System32\forfiles.exe", @"forfiles /p C:\logs /m *.log /d -30", Temp));
        }

        static Processes.Proc P(int pid, int ppid, string path, int minute) =>
            new Processes.Proc { Pid = pid, Ppid = ppid, Path = path, Created = new DateTime(2026, 11, 20, 3, minute, 0, DateTimeKind.Utc) };

        [Fact]
        public void ChainNearestFirstUpToFourLevels()
        {
            var host = P(50, 40, Temp, 5);
            var all = new Dictionary<int, Processes.Proc>
            {
                [40] = P(40, 30, @"C:\Windows\System32\cmd.exe", 4),
                [30] = P(30, 20, @"C:\Windows\System32\forfiles.exe", 3),
                [20] = P(20, 10, @"C:\Users\anna\Downloads\x\Setup.exe", 2),
                [10] = P(10, 5, @"C:\Windows\explorer.exe", 1),
                [5] = P(5, 1, @"C:\Windows\System32\userinit.exe", 0),
            };
            var chain = Processes.Chain(host, all);
            Assert.Equal(new[] { 40, 30, 20, 10 }, chain.ConvertAll(a => a.Pid));
            Assert.Equal("parent cmd.exe (40) < forfiles.exe (30) < Setup.exe (20) < explorer.exe (10)", Processes.ChainText(chain));
        }

        [Fact]
        public void AReusedPidIsAnExitedParent()
        {
            // PID 40 now belongs to a process started after the child: the real parent is gone
            var host = P(50, 40, Temp, 5);
            var all = new Dictionary<int, Processes.Proc> { [40] = P(40, 30, @"C:\Windows\System32\notepad.exe", 9) };
            Assert.Equal("parent pid 40 (exited)", Processes.ChainText(Processes.Chain(host, all)));
            Assert.Equal("parent pid 40 (exited)", Processes.ChainText(Processes.Chain(host, new Dictionary<int, Processes.Proc>())));
        }

        [Fact]
        public void ChainTextHasNoStatusWords()
        {
            // parsers take "[gone]" / "[unsigned]" as the line's status
            var text = Processes.ChainText(Processes.Chain(P(50, 40, Temp, 5), new Dictionary<int, Processes.Proc>()));
            Assert.DoesNotContain("[", text);
        }
    }
}
