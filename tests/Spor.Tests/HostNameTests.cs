using Xunit;

namespace Spor.Tests
{
    /// <summary>DNS cache categories: victim ID in name, abused TLD.</summary>
    public class HostNameTests
    {
        [Fact]
        public void MacIdUnderAnAbusedTld()
        {
            Assert.True(HostNames.VictimId("0800272a1b3c.example.click"));
            Assert.True(HostNames.AbusedTld("0800272a1b3c.example.click"));
        }

        [Theory]
        [InlineData("3f2504e0-4f89-11d3-9a0c-0305e82c3301.example.com")]
        [InlineData("3f2504e04f8911d39a0c0305e82c3301.example.com")]
        [InlineData("k7q2m9x4p1r8t5w3z6.example.net")]
        public void VictimIds(string host) => Assert.True(HostNames.VictimId(host));

        [Theory]
        [InlineData("d1a2b3c4e5f6a7.cloudfront.net")]                       // CDN
        [InlineData("0123456789ab.trafficmanager.net")]                     // cloud, a MAC-like label
        [InlineData("3f2504e0-4f89-11d3-9a0c-0305e82c3301.cloudapp.net")]   // cloud, a GUID
        [InlineData("www.example.click")]
        [InlineData("deadbeefcafe.ingest.sentry.io")]                       // more than two labels follow
        [InlineData("example.com")]
        [InlineData("accounts.google.com")]
        [InlineData("backgroundchange.example.com")]                        // a long word, no digits
        [InlineData("facade.example.com")]                                  // 6 hex letters, not 12
        [InlineData("rr10---sn-4g5e6nzl.googlevideo.com")]                  // a video CDN node
        [InlineData("rr10---sn-4g5e6nzl.example.com")]                      // dashes: a node name, not an ID
        public void NotVictimIds(string host) => Assert.False(HostNames.VictimId(host));

        [Fact]
        public void AbusedTldOnly()
        {
            Assert.True(HostNames.AbusedTld("www.example.click"));
            Assert.False(HostNames.VictimId("www.example.click"));
            Assert.False(HostNames.AbusedTld("example.com"));
            Assert.False(HostNames.AbusedTld("click"));
            Assert.False(HostNames.AbusedTld("www.clicks.com"));
        }
    }
}
