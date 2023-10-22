using System;
using System.Globalization;
using System.Linq;
using NUnit.Framework;
using Uri = Substrate.NET.Wallet.Keyring.Uri;

namespace Substrate.NET.Wallet.Test.Keyrings
{
    public class UriTests
    {
        public static byte[] HelloWorldBytes = new byte[] { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        public static byte[] HelloWorldDotBytes = new byte[] { 12, 68, 79, 84, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

        [Test]
        [TestCase("//2")]
        public void KeyExtractUri_FromInvalidUri_ShouldFail(string value)
        {
            Assert.Throws<InvalidOperationException>(() => Uri.KeyExtractUri(value));
        }

        [Test]
        public void KeyExtractUri_DeriveOnHelloWorld()
        {
            var res = Uri.KeyExtractUri("hello world");

            Assert.That(res.Phrase, Is.EqualTo("hello world"));
            Assert.That(res.Path.Count, Is.EqualTo(0));
        }

        [Test]
        [TestCase("hello world/1", false)]
        [TestCase("hello world//1", true)]
        public void KeyExtractUri_DeriveOnHelloWorld_1(string value, bool isHard)
        {
            var res = Uri.KeyExtractUri(value);

            Assert.That(res.Password, Is.Null);
            Assert.That(res.Phrase, Is.EqualTo("hello world"));
            Assert.That(res.Path.Count, Is.EqualTo(1));
            Assert.That(res.Path[0].IsHard, Is.EqualTo(isHard));
            Assert.That(res.Path[0].ChainCode, Is.EqualTo(HelloWorldBytes));
        }

        [Test]
        [TestCase("hello world/DOT", false)]
        [TestCase("hello world//DOT", true)]
        public void KeyExtractUri_DeriveOnHelloWorld_Dot(string value, bool isHard)
        {
            var res = Uri.KeyExtractUri(value);

            Assert.That(res.Password, Is.Null);
            Assert.That(res.Phrase, Is.EqualTo("hello world"));
            Assert.That(res.Path.Count, Is.EqualTo(1));
            Assert.That(res.Path[0].IsHard, Is.EqualTo(isHard));
            
            Assert.That(res.Path[0].ChainCode, Is.EqualTo(HelloWorldDotBytes));
        }

        [Test]
        public void KeyExtractUri_DeriveMultiple_1_Dot()
        {
            var res = Uri.KeyExtractUri("hello world//1/DOT");

            Assert.That(res.Password, Is.Null);
            Assert.That(res.Phrase, Is.EqualTo("hello world"));
            Assert.That(res.Path.Count, Is.EqualTo(2));
            
            Assert.That(res.Path[0].IsHard, Is.True);
            Assert.That(res.Path[0].ChainCode, Is.EqualTo(HelloWorldBytes));

            Assert.That(res.Path[1].IsHard, Is.False);
            Assert.That(res.Path[1].ChainCode, Is.EqualTo(HelloWorldDotBytes));
        }

        public void KeyExtractUri_DeriveMultiple_Dot_1()
        {
            var res = Uri.KeyExtractUri("hello world//DOT/1");

            Assert.That(res.Password, Is.Null);
            Assert.That(res.Phrase, Is.EqualTo("hello world"));
            Assert.That(res.Path.Count, Is.EqualTo(2));

            Assert.That(res.Path[0].IsHard, Is.True);
            Assert.That(res.Path[0].ChainCode, Is.EqualTo(HelloWorldDotBytes));

            Assert.That(res.Path[1].IsHard, Is.False);
            Assert.That(res.Path[1].ChainCode, Is.EqualTo(HelloWorldBytes));
        }

        public void KeyExtractUri_DeriveMultiple_3()
        {
            var res = Uri.KeyExtractUri("hello world//1/DOT///password");

            Assert.That(res.Password, Is.EqualTo("password"));
            Assert.That(res.Phrase, Is.EqualTo("hello world"));
            Assert.That(res.Path.Count, Is.EqualTo(2));

            Assert.That(res.Path[0].IsHard, Is.True);
            Assert.That(res.Path[0].ChainCode, Is.EqualTo(HelloWorldBytes));

            Assert.That(res.Path[1].IsHard, Is.False);
            Assert.That(res.Path[1].ChainCode, Is.EqualTo(HelloWorldDotBytes));
        }

        public void KeyExtractUri_DeriveMultiple_4()
        {
            var res = Uri.KeyExtractUri("hello world/1//DOT///password");

            Assert.That(res.Password, Is.EqualTo("password"));
            Assert.That(res.Phrase, Is.EqualTo("hello world"));
            Assert.That(res.Path.Count, Is.EqualTo(2));

            Assert.That(res.Path[0].IsHard, Is.False);
            Assert.That(res.Path[0].ChainCode, Is.EqualTo(HelloWorldBytes));

            Assert.That(res.Path[1].IsHard, Is.True);
            Assert.That(res.Path[1].ChainCode, Is.EqualTo(HelloWorldDotBytes));
        }

        public void KeyExtractUri_DeriveMultiple_Alice()
        {
            var res = Uri.KeyExtractUri("bottom drive obey lake curtain smoke basket hold race lonely fit walk//Alice");

            Assert.That(res.Password, Is.Null);
            Assert.That(res.Phrase, Is.EqualTo("bottom drive obey lake curtain smoke basket hold race lonely fit walk"));
            Assert.That(res.Path.Count, Is.EqualTo(1));

            Assert.That(res.Path[0].IsHard, Is.True);
            Assert.That(res.Path[0].ChainCode, Is.EqualTo(new byte[] { 20, 65, 108, 105, 99, 101, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }));
        }

        [Test]
        public void KeyExtractPath_FromSoft()
        {
            var res = Uri.KeyExtractPath("/1");

            Assert.That(res.parts, Is.EqualTo(new string[1] { "/1" }));
            Assert.That(res.path.Length, Is.EqualTo(1));
            Assert.That(res.path[0].IsHard, Is.EqualTo(false));
            Assert.That(res.path[0].ChainCode, Is.EqualTo(new byte[] { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }));
        }

        [Test]
        public void KeyExtractPath_FromHard()
        {
            var res = Uri.KeyExtractPath("//1");

            Assert.That(res.parts, Is.EqualTo(new string[1] { "//1" }));
            Assert.That(res.path.Length, Is.EqualTo(1));
            Assert.That(res.path[0].IsHard, Is.EqualTo(true));
            Assert.That(res.path[0].ChainCode, Is.EqualTo(new byte[] { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }));
        }

        [Test]
        public void KeyExtractPath_FromHardAndSoft()
        {
            var res = Uri.KeyExtractPath("//1/2");

            Assert.That(res.parts, Is.EqualTo(new string[] { "//1", "/2" }));
            Assert.That(res.path.Length, Is.EqualTo(2));

            Assert.That(res.path[0].IsHard, Is.EqualTo(true));
            Assert.That(res.path[0].ChainCode, Is.EqualTo(new byte[] { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }));

            Assert.That(res.path[0].IsHard, Is.EqualTo(false));
            Assert.That(res.path[0].ChainCode, Is.EqualTo(new byte[] { 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }));
        }

        [Test]
        [TestCase("1/2")]
        [TestCase("hello")]
        public void KeyExtractPath_InvalidPath_ShouldFail(string value)
        {
            Assert.Throws<InvalidOperationException>(() => Uri.KeyExtractPath("value"));
        }
    }
}
