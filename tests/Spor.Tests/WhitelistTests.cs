using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using Xunit;

namespace Spor.Tests
{
    /// <summary>resources/whitelist.txt: parsing, and the same rules as the constants it replaced (Spor 0.7.1).</summary>
    public class WhitelistTests
    {
        static readonly Whitelist.Data Built = Whitelist.Parse(Util.Embedded(Whitelist.OverrideFile));

        [Fact]
        public void TheBuiltInFileHasEveryScope()
        {
            foreach (var scope in Whitelist.NoiseModules.Select(m => "noise:" + m)
                         .Concat(new[] { "staging", "script-noise", "breadcrumb", "skip-dir", "stale-task", "locked-task" }))
                Assert.True(Built.Of(scope).Count > 0, scope);
        }

        [Theory]
        [InlineData("noise:nothere\t\\\\X\\\\")]                 // unknown scope
        [InlineData("noise:files\t\\\\(X\\\\")]                  // bad regex
        [InlineData("staging")]                                  // no value
        [InlineData("stale-task\t\\Microsoft\\Windows\\X")]      // no program
        public void ABrokenFileThrows(string line) =>
            Assert.ThrowsAny<Exception>(() => Whitelist.Parse("# comment\r\n\r\n" + line + "\r\n"));

        [Fact]
        public void CommentsBlankLinesAndNotes()
        {
            var d = Whitelist.Parse("# x\r\n\r\nskip-dir\tCache\tbrowser caches\r\n  # indented comment\r\nlocked-task\t\\A\\B\r\n");
            Assert.Equal(new[] { "Cache" }, d.Of("skip-dir"));
            Assert.Equal(new[] { @"\A\B" }, d.Of("locked-task"));
        }

        [Fact]
        public void AnEmptyScopeMatchesNothing()
        {
            var rx = new Regex(Whitelist.Joined(Whitelist.Parse(""), "noise:files"), Util.RX);
            Assert.DoesNotMatch(rx, @"\USERS\A\X.EXE");
            Assert.DoesNotMatch(rx, "");
        }

        // ---- the constants of Spor 0.7.1 that the file replaces ----
        const string OldPrefetch = @"^\\(\$WINREAGENT|\$WINDOWS\.~BT|\$WINDOWS\.~WS)\\|^\\PROGRAMDATA\\(MICROSOFT\\(WINDOWS DEFENDER|WINDOWS\\WER|CLICKTORUN|EDGEUPDATE)|NVIDIA CORPORATION|A-VOLUTE|LENOVO)\\|\\START MENU\\|\\\.M2\\|\\\.VSCODE\\EXTENSIONS\\|\\NODE_MODULES\\|\\SITE-PACKAGES\\|\\APPDATA\\LOCAL\\(PACKAGES|DISCORD|PROGRAMS\\MICROSOFT VS CODE)\\|\\APPDATA\\LOCAL\\MICROSOFT\\EDGE\\USER DATA\\(?!DEFAULT\\EXTENSIONS)|\\APPDATA\\LOCAL\\TEMP\\(MSEDGE_|HSPERFDATA|__PSSCRIPTPOLICYTEST)|\\__PYCACHE__\\|\\PYTHON\d+\\(LIB|DLLS)\\|\\QMLCACHE\\|\\MICROSOFT\\WINDOWS\\RECENT\\";
        const string OldAmcache = @"^\\(\$WINREAGENT|\$WINDOWS\.~BT|\$WINDOWS\.~WS)\\|\\PACKAGE CACHE\\|\\APPDATA\\LOCAL\\PROGRAMS\\MICROSOFT VS CODE\\|\\APPDATA\\LOCAL\\MICROSOFT\\(EDGE|ONEDRIVE)\\|\\PYTHON\d+\\(LIB|DLLS)\\";
        const string OldExec = @"^\\(\$WINREAGENT|\$WINDOWS\.~BT|\$WINDOWS\.~WS)\\|\\PACKAGE CACHE\\|\\APPDATA\\LOCAL\\PROGRAMS\\MICROSOFT VS CODE\\|\\APPDATA\\LOCAL\\MICROSOFT\\(EDGE|ONEDRIVE)\\|\\PYTHON\d+\\(LIB|DLLS)\\|\\TEMP\\IS-[A-Z0-9]+\.TMP\\|\\TEMP\\~NSU\.TMP\\|\\TEMP\\VSCODE-STABLE-USER-|\\TEMP\\[^\\]+\\RESOURCES\\APP\\SERVICEHUB\\|^\\WINDOWS\\TEMP\\\{[0-9A-F-]{36}\}\\\.(BE|CR)\\";
        const string OldFiles = @"\\APPDATA\\LOCAL\\PROGRAMS\\MICROSOFT VS CODE\\|\\APPDATA\\LOCAL\\MICROSOFT\\(EDGE|ONEDRIVE|TEAMS|WINGET)\\|\\APPDATA\\LOCAL\\(DISCORD|SLACK|GITHUBDESKTOP|SQUIRRELTEMP)\\|\\\.VSCODE\\|\\APPDATA\\LOCAL\\TEMP\\(MSEDGE_|CHROME_|SCOPED_DIR|.*\\RESOURCES\\APP\\SERVICEHUB\\)|\\PROGRAMDATA\\MICROSOFT\\(WINDOWS DEFENDER|CLICKTORUN|EDGEUPDATE|WINDOWS\\WER)\\|\\PYTHON\d+\\(LIB|DLLS|SCRIPTS)\\|\\APPDATA\\LOCAL\\TEMP\\IS-[A-Z0-9]+\.TMP\\";
        const string OldStaging = @"^\\(PROGRAM FILES( \(X86\))?\\(MICROSOFT\\EDGEUPDATE|BRAVESOFTWARE\\UPDATE|GOOGLE\\UPDATE)\\INSTALL\\\{[0-9A-F-]{36}\}\\|WINDOWS\\SOFTWAREDISTRIBUTION\\|WINDOWS\\WINSXS\\)";
        const string OldScriptNoise = @"\\(Mozilla\\(Firefox|Thunderbird)|Thunderbird|Waterfox|LibreWolf)\\|\\(nvm|npm|npm-cache|pnpm|yarn|JetBrains|Code\\User|Code - Insiders|Cursor\\User|GitHub Desktop|Postman)\\|\\(prefs|user|times)\.js$";
        const string OldBreadcrumb = @"^\\PROGRAMDATA\\MICROSOFT\\NETFRAMEWORK\\BREADCRUMBSTORE\\";
        static readonly string[] OldSkipDirs = {
            "node_modules", ".git", "site-packages", "__pycache__", "Cache", "Code Cache", "GPUCache", "Service Worker", "IndexedDB",
            "Packages", "WinSxS", "assembly", "CacheStorage", "ShaderCache", "DawnCache", "DawnGraphiteCache", "DawnWebGPUCache", "GrShaderCache", "blob_storage",
            "Local Storage", "Session Storage", "INetCache", "WebCache", "Crashpad", "CrashDumps", "Package Cache", "WindowsApps", "pip", "npm-cache",
            ".nuget", ".gradle", ".m2", ".cargo", ".rustup", "venv", ".venv" };

        const string G = "{01234567-89AB-CDEF-0123-456789ABCDEF}";
        // paths without the drive, as the modules match them: every rule, near misses and plain user folders
        static readonly string[] Samples = {
            @"\$WINREAGENT\SCRATCH\X\DISMHOST.EXE", @"\$WINDOWS.~BT\SOURCES\SETUPHOST.EXE", @"\$Windows.~WS\x.exe", @"\PROGRAMDATA\EVIL\$WINREAGENT\X.EXE",
            @"\PROGRAMDATA\MICROSOFT\WINDOWS DEFENDER\PLATFORM\4.18\MSMPENG.EXE", @"\ProgramData\Microsoft\Windows\WER\Temp\x.dll",
            @"\PROGRAMDATA\MICROSOFT\CLICKTORUN\X.EXE", @"\PROGRAMDATA\MICROSOFT\EDGEUPDATE\X.EXE", @"\PROGRAMDATA\NVIDIA CORPORATION\X.DLL",
            @"\PROGRAMDATA\A-VOLUTE\X.DLL", @"\PROGRAMDATA\LENOVO\VANTAGE\X.DLL", @"\PROGRAMDATA\PACKAGE CACHE\{X}\Y.EXE",
            @"\USERS\A\APPDATA\ROAMING\MICROSOFT\WINDOWS\START MENU\PROGRAMS\X.LNK", @"\USERS\A\APPDATA\ROAMING\MICROSOFT\WINDOWS\RECENT\X.LNK",
            @"\USERS\A\.M2\REPOSITORY\X.JAR", @"\USERS\A\.VSCODE\EXTENSIONS\X\Y.JS", @"\USERS\A\.vscode\argv.json", @"\USERS\A\PROJ\NODE_MODULES\X\Y.JS",
            @"\PYTHON312\LIB\SITE-PACKAGES\X.PYD", @"\PYTHON312\DLLS\X.PYD", @"\PYTHON312\SCRIPTS\PIP.EXE", @"\X\__PYCACHE__\Y.PYC", @"\X\QMLCACHE\Y",
            @"\USERS\A\APPDATA\LOCAL\PACKAGES\X\Y.DLL", @"\USERS\A\APPDATA\LOCAL\DISCORD\APP-1\X.DLL", @"\USERS\A\APPDATA\LOCAL\SLACK\X.EXE",
            @"\USERS\A\APPDATA\LOCAL\GITHUBDESKTOP\X.EXE", @"\USERS\A\APPDATA\LOCAL\SQUIRRELTEMP\X.EXE",
            @"\USERS\A\APPDATA\LOCAL\PROGRAMS\MICROSOFT VS CODE\CODE.EXE",
            @"\USERS\A\APPDATA\LOCAL\MICROSOFT\EDGE\USER DATA\DEFAULT\EXTENSIONS\X\Y.JS", @"\USERS\A\APPDATA\LOCAL\MICROSOFT\EDGE\USER DATA\DEFAULT\CACHE\X",
            @"\USERS\A\APPDATA\LOCAL\MICROSOFT\ONEDRIVE\X.EXE", @"\USERS\A\APPDATA\LOCAL\MICROSOFT\TEAMS\X.EXE", @"\USERS\A\APPDATA\LOCAL\MICROSOFT\WINGET\X.EXE",
            @"\USERS\A\APPDATA\LOCAL\TEMP\MSEDGE_URL_FETCHER_1\X.DLL", @"\USERS\A\APPDATA\LOCAL\TEMP\HSPERFDATA_A\1",
            @"\USERS\A\APPDATA\LOCAL\TEMP\__PSSCRIPTPOLICYTEST_ABCDEFGH.XYZ.PS1", @"\USERS\A\APPDATA\LOCAL\TEMP\CHROME_X\Y.EXE",
            @"\USERS\A\APPDATA\LOCAL\TEMP\SCOPED_DIR1\Y.EXE", @"\USERS\A\APPDATA\LOCAL\TEMP\ABC\RESOURCES\APP\SERVICEHUB\X.EXE",
            @"\Users\a\AppData\Local\Temp\IS-AB12C.tmp\setup.tmp", @"\USERS\A\APPDATA\LOCAL\TEMP\~NSU.TMP\AU_.EXE",
            @"\USERS\A\APPDATA\LOCAL\TEMP\VSCODE-STABLE-USER-X64\X.EXE", @"\WINDOWS\TEMP\" + G + @"\.BE\X.EXE", @"\WINDOWS\TEMP\" + G + @"\.XX\X.EXE",
            @"\PROGRAM FILES (X86)\MICROSOFT\EDGEUPDATE\INSTALL\" + G + @"\X.EXE", @"\PROGRAM FILES\GOOGLE\UPDATE\INSTALL\" + G + @"\X.EXE",
            @"\PROGRAM FILES\BRAVESOFTWARE\UPDATE\INSTALL\" + G + @"\X.EXE", @"\PROGRAM FILES\BRAVESOFTWARE\UPDATE\X.EXE",
            @"\WINDOWS\SOFTWAREDISTRIBUTION\DOWNLOAD\X.CAB", @"\WINDOWS\WINSXS\AMD64_X\TIWORKER.EXE", @"\USERS\A\WINDOWS\WINSXS\X.EXE",
            @"\USERS\A\APPDATA\ROAMING\MOZILLA\FIREFOX\PROFILES\X\PREFS.JS", @"\USERS\A\APPDATA\ROAMING\CODE\USER\X.JS", @"\USERS\A\APPDATA\ROAMING\NPM\X.CMD",
            @"\USERS\A\APPDATA\ROAMING\X\USER.JS", @"\USERS\A\APPDATA\ROAMING\X\USER.JSON",
            @"\PROGRAMDATA\MICROSOFT\NETFRAMEWORK\BREADCRUMBSTORE\NETCORE,X.DLL",
            @"\USERS\A\APPDATA\ROAMING\EVIL\RUN.EXE", @"\USERS\A\DOWNLOADS\SETUP.EXE", @"\WINDOWS\SYSTEM32\X.EXE", @"\WINDOWS\TEMP\X.EXE",
        };

        public static IEnumerable<object[]> RuleCases() => new[]
        {
            new object[] { "noise:prefetch", OldPrefetch }, new object[] { "noise:amcache", OldAmcache }, new object[] { "noise:exec", OldExec },
            new object[] { "noise:files", OldFiles }, new object[] { "staging", OldStaging }, new object[] { "script-noise", OldScriptNoise },
            new object[] { "breadcrumb", OldBreadcrumb },
        };

        [Theory]
        [MemberData(nameof(RuleCases))]
        public void TheSameMatchesAsBefore(string scope, string old)
        {
            var o = new Regex(old, Util.RX);
            var n = new Regex(Whitelist.Joined(Built, scope), Util.RX);
            Assert.Contains(Samples, s => o.IsMatch(s));   // the samples exercise the rule
            foreach (var s in Samples)
            {
                Assert.True(o.IsMatch(s) == n.IsMatch(s), $"{scope}: {s}");
                Assert.True(o.Match(s).Value == n.Match(s).Value, $"{scope} match: {s}");   // StagingRoot and the breadcrumb count use it
            }
        }

        [Fact]
        public void TheSameNamesAsBefore()
        {
            Assert.Equal(OldSkipDirs, Built.Of("skip-dir"));
            Assert.Equal(new[] { @"\Microsoft\Windows\Security\Pwdless\IntelligentPwdlessTask" }, Built.Of("locked-task"));
            Assert.Equal(new Dictionary<string, string>
            {
                [@"\Microsoft\Windows\Location\Notifications"] = "LocationNotificationWindows.exe",
                [@"\Microsoft\Windows\UpdateOrchestrator\USO_UxBroker"] = "MusNotification.exe",
            }, Whitelist.StaleTasks);
        }
    }
}
