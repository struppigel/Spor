using System;
using System.Collections.Generic;
using System.Linq;
using Xunit;

namespace Spor.Tests
{
    /// <summary>Scan profiles: which modules each runs, and that -modules overrides the profile.</summary>
    public class ProfileTests
    {
        static List<string> Ids(Options o) => Scanner.Selected(o).Select(m => m.Id).ToList();

        [Fact]
        public void DefaultIsEverythingButUsb()
        {
            var ids = Ids(new Options());
            Assert.DoesNotContain("usb", ids);
            Assert.Equal(Scanner.All.Length - 1, ids.Count);
        }

        [Fact]
        public void AllIsEveryModule() => Assert.Equal(Scanner.All.Select(m => m.Id), Ids(new Options { Profile = "all" }));

        [Fact]
        public void UsbProfile()
        {
            var ids = Ids(new Options { Profile = "USB" });
            Assert.Equal(new[] { "prefetch", "exec", "files", "persistence", "processes", "usb" }, ids);   // module order, case-insensitive profile
        }

        [Fact]
        public void ModulesOverrideTheProfile() =>
            Assert.Equal(new[] { "files", "usb" }, Ids(new Options { Profile = "default", Modules = new HashSet<string>(new[] { "usb", "files" }, StringComparer.OrdinalIgnoreCase) }));

        [Fact]
        public void UnknownProfile()
        {
            Assert.Null(Scanner.ProfileModules("nope"));
            Assert.Equal(Ids(new Options()), Ids(new Options { Profile = "nope" }));   // falls back to default
        }

        [Fact]
        public void ProfilesNameRealModules() =>
            Assert.All(Scanner.Profiles.SelectMany(p => p.Modules), id => Assert.Contains(Scanner.All, m => m.Id == id));
    }
}
