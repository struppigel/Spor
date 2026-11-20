using Xunit;

namespace Spor.Tests
{
    /// <summary>Zone.Identifier streams: the zone, the URLs, and what counts as a download URL.</summary>
    public class ZoneTests
    {
        [Theory]
        [InlineData(0, "zone 0")]
        [InlineData(1, "zone 1")]
        [InlineData(2, "zone 2")]
        [InlineData(3, "downloaded from the internet (no URL saved)")]
        [InlineData(4, "zone 4")]
        public void ZoneOnlyIsNoUrl(int id, string text)
        {
            var z = Ads.ParseZone($"[ZoneTransfer]\r\nZoneId={id}\r\n");
            Assert.Equal(id, z.Id);
            Assert.False(z.HasUrl);
            Assert.Equal(text, z.Text);
        }

        [Fact]
        public void HostUrlIsAUrl()
        {
            var z = Ads.ParseZone("[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://example.com/a.zip\r\n");
            Assert.True(z.HasUrl);
            Assert.Equal("from https://example.com/a.zip", z.Text);
        }

        [Fact]
        public void HostAndReferrerUrl()
        {
            var z = Ads.ParseZone("[ZoneTransfer]\nZoneId=3\nReferrerUrl=https://example.com/page\nHostUrl=https://cdn.example.com/a.zip\n");
            Assert.True(z.HasUrl);
            Assert.Equal("from https://cdn.example.com/a.zip, referrer https://example.com/page", z.Text);
        }

        [Theory]
        [InlineData("about:internet")]
        [InlineData("about:blank")]
        public void PseudoUrlsAreNoUrl(string url)
        {
            var z = Ads.ParseZone("[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=" + url + "\r\n");
            Assert.False(z.HasUrl);
            Assert.Equal(3, z.Id);
        }

        [Theory]
        [InlineData("")]
        [InlineData(null)]
        [InlineData("garbage without lines")]
        [InlineData("[ZoneTransfer]\r\nZoneId=abc\r\nHostUrl=\r\n")]
        public void EmptyOrMalformedStream(string text)
        {
            var z = Ads.ParseZone(text);
            Assert.Null(z.Id);
            Assert.False(z.HasUrl);
            Assert.Null(z.Text);
        }

        [Fact]
        public void NulBytesAfterTheUrlAreRemoved()
        {
            var z = Ads.ParseZone("[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://example.com/a.exe\0\0\r\n");
            Assert.Equal("https://example.com/a.exe", z.HostUrl);
        }
    }
}
