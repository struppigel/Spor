using System.Collections.Generic;
using System.Linq;
using Xunit;

namespace Spor.Tests
{
    /// <summary>!sideload: a validly signed program next to an unsigned DLL it imports, with proxy evidence.</summary>
    public class SideloadTests
    {
        static readonly ICollection<string> Known = new HashSet<string>(new[] { "kernel32.dll", "user32.dll", "version.dll" }, System.StringComparer.OrdinalIgnoreCase);

        static PeInfo Imports(params string[] names)
        {
            var pe = new PeInfo { Valid = true };
            pe.Imports.AddRange(names);
            return pe;
        }

        static PeInfo Exports(int stubs, int real)
        {
            var pe = new PeInfo { Valid = true, IsDll = true };
            for (int i = 0; i < stubs; i++) pe.Exports.Add(new PeExport { Name = "S" + i, Stub = true });
            for (int i = 0; i < real; i++) pe.Exports.Add(new PeExport { Name = "R" + i });
            return pe;
        }

        static PeFile Host(string path, bool signed, params string[] imports) => new PeFile(path, signed, signed ? "Some Developer" : null, null, Imports(imports));
        static PeFile Dll(string path, bool signed, string original = null, PeInfo pe = null) => new PeFile(path, signed, signed ? "Some Developer" : null, original, pe ?? Exports(0, 3));

        const string Temp = @"C:\Users\anna\AppData\Local\Temp\tmp-1-abc\";

        [Fact]
        public void SignedHostUnsignedProxyDllAndRenamedOriginal()
        {
            // the worked example's shape: signed host, unsigned DLL it imports, the signed original under another name
            var host = Host(Temp + "qwXyZaB.exe", true, "KERNEL32.dll", "providers.dll");
            var dlls = new[] { Dll(Temp + "providers.dll", false, "providers.dll", Exports(9, 1)), Dll(Temp + "providersxyzzy.dll", true, "providers.dll") };
            var hit = Assert.Single(Sideload.Decide(host, dlls, Known));
            Assert.Equal("providers.dll", hit.Dll.Name);
            Assert.Equal("proxy DLL, forwards to providersxyzzy.dll (original name providers.dll)", hit.Evidence);
            Assert.Equal("loaded by qwXyZaB.exe (signed by Some Developer); proxy DLL, forwards to providersxyzzy.dll (original name providers.dll)", hit.DllDetails);
            Assert.Equal("side-loads providers.dll", hit.HostDetails);
        }

        [Fact]
        public void SignedHostInRoamingWithAnUnsignedLibcef()
        {
            // a signed app persisted in AppData\Roaming with a replaced libcef.dll; proxy evidence from its exports
            var dir = @"C:\Users\anna\AppData\Roaming\Updater\";
            var host = Host(dir + "app.exe", true, "libcef.dll", "KERNEL32.dll");
            var hit = Assert.Single(Sideload.Decide(host, new[] { Dll(dir + "libcef.dll", false, pe: Exports(7, 1)) }, Known));
            Assert.Equal("exports forwarded: 7 of 8", hit.Evidence);
        }

        [Fact]
        public void WithoutProxyEvidenceStillFlagged()
        {
            var host = Host(@"C:\Users\anna\Downloads\tool\tool.exe", true, "helper.dll");
            var hit = Assert.Single(Sideload.Decide(host, new[] { Dll(@"C:\Users\anna\Downloads\tool\helper.dll", false) }, Known));
            Assert.Null(hit.Evidence);
            Assert.Equal("loaded by tool.exe (signed by Some Developer)", hit.DllDetails);
        }

        [Fact]
        public void UnsignedHostIsNotChecked()
        {
            var host = Host(Temp + "a.exe", false, "helper.dll");
            Assert.Empty(Sideload.Decide(host, new[] { Dll(Temp + "helper.dll", false) }, Known));
        }

        [Fact]
        public void KnownDllsAndApiSetsAreNotSideloaded()
        {
            // Windows loads these from System32 whatever lies next to the program
            var host = Host(Temp + "a.exe", true, "version.dll", "api-ms-win-core-file-l1-1-0.dll");
            var dlls = new[] { Dll(Temp + "version.dll", false), Dll(Temp + "api-ms-win-core-file-l1-1-0.dll", false) };
            Assert.Empty(Sideload.Decide(host, dlls, Known));
        }

        [Fact]
        public void InstallerPluginDllsAreNotImported()
        {
            // NSIS and Inno Setup load their unsigned plugins with LoadLibrary: not in the import table
            var host = Host(Temp + "setup.exe", true, "KERNEL32.dll", "USER32.dll");
            var dlls = new[] { Dll(Temp + "System.dll", false), Dll(Temp + "nsDialogs.dll", false) };
            Assert.Empty(Sideload.Decide(host, dlls, Known));
        }

        [Fact]
        public void SignedDllNextToSignedProgramIsFine()
        {
            var host = Host(@"C:\Users\anna\Downloads\app\app.exe", true, "helper.dll");
            Assert.Empty(Sideload.Decide(host, new[] { Dll(@"C:\Users\anna\Downloads\app\helper.dll", true) }, Known));
        }

        [Fact]
        public void ProgramFilesIsNotChecked()
        {
            var host = Host(@"C:\Program Files\Vendor\app.exe", true, "helper.dll");
            Assert.Empty(Sideload.Decide(host, new[] { Dll(@"C:\Program Files\Vendor\helper.dll", false) }, Known));
        }

        [Fact]
        public void BuiltPeFilesThroughTheParser()
        {
            // the whole chain on bytes: imports from the host's PE, stubs from the DLL's PE
            var host = new PeFile(Temp + "h.exe", true, "Dev", null, new PeBuilder(true).Import("KERNEL32.dll", "x.dll").Parse());
            var dll = new PeFile(Temp + "x.dll", false, null, null,
                                 new PeBuilder(true).Dll().Forwarder("A", "y.A").Forwarder("B", "y.B").Export("C", 0xC3, 0, 0, 0, 0, 0).Parse());
            var hit = Assert.Single(Sideload.Decide(host, new[] { dll }, Known));
            Assert.Equal("exports forwarded: 2 of 3", hit.Evidence);
        }
    }
}
