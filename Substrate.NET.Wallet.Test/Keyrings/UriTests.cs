using System;
using System.Globalization;
using System.Linq;
using NUnit.Framework;
using Substrate.NetApi;
using Uri = Substrate.NET.Wallet.Keyring.Uri;

namespace Substrate.NET.Wallet.Test.Keyrings
{
    public class UriTests
    {
        public static byte[] HelloWorldBytes = new byte[] { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        public static byte[] HelloWorldDotBytes = new byte[] { 12, 68, 79, 84, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

        [Test]
        public void CompactAddLenght_ShouldAddLengthPrefix()
        {
            var input = new byte[] { 12, 13 };

        }

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

        [Test]
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

        [Test]
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

        [Test]
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

        [Test]
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

            Assert.That(res.Parts, Is.EqualTo(new string[1] { "/1" }));
            Assert.That(res.Path.Count, Is.EqualTo(1));
            Assert.That(res.Path[0].IsHard, Is.EqualTo(false));
            Assert.That(res.Path[0].ChainCode, Is.EqualTo(new byte[] { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }));
        }

        [Test]
        public void KeyExtractPath_FromHard()
        {
            var res = Uri.KeyExtractPath("//1");

            Assert.That(res.Parts, Is.EqualTo(new string[1] { "//1" }));
            Assert.That(res.Path.Count, Is.EqualTo(1));
            Assert.That(res.Path[0].IsHard, Is.EqualTo(true));
            Assert.That(res.Path[0].ChainCode, Is.EqualTo(new byte[] { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }));
        }

        [Test]
        public void KeyExtractPath_FromHardAndSoft()
        {
            var res = Uri.KeyExtractPath("//1/2");

            Assert.That(res.Parts, Is.EqualTo(new string[] { "//1", "/2" }));
            Assert.That(res.Path.Count, Is.EqualTo(2));

            Assert.That(res.Path[0].IsHard, Is.EqualTo(true));
            Assert.That(res.Path[0].ChainCode, Is.EqualTo(new byte[] { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }));

            Assert.That(res.Path[1].IsHard, Is.EqualTo(false));
            Assert.That(res.Path[1].ChainCode, Is.EqualTo(new byte[] { 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }));
        }

        [Test]
        [TestCase("1/2")]
        [TestCase("hello")]
        [TestCase("//funding/")]
        public void KeyExtractPath_InvalidPath_ShouldFail(string value)
        {
            Assert.Throws<InvalidOperationException>(() => Uri.KeyExtractPath(value));
        }

        // <summary>
        /// Parity source : https://github.com/polkadot-js/wasm/blob/master/packages/wasm-crypto/src/rs/sr25519.rs#L294
        /// </summary>
        [Test]
        public void Sr25519_DeriveHard_ShouldSucceed()
        {
            var cc = Utils.HexToByteArray("14416c6963650000000000000000000000000000000000000000000000000000");
            var seed = Utils.HexToByteArray("fac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e");
            var expected = Utils.HexToByteArray("d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d");

            var res = Keyring.Uri.Sr25519DeriveHard(seed, cc);

            Assert.That(res.Length, Is.EqualTo(96));

            var publicKey = res.Skip(64).Take(32);
            Assert.That(publicKey, Is.EquivalentTo(expected));
        }

        [Test]
        public void Sr25519_CreateDeriveSoft_ShouldSucceed()
        {
            var cc = Utils.HexToByteArray("0c666f6f00000000000000000000000000000000000000000000000000000000");
            var seed = Utils.HexToByteArray("fac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e");
            var expected = Utils.HexToByteArray("40b9675df90efa6069ff623b0fdfcf706cd47ca7452a5056c7ad58194d23440a");

            var res = Keyring.Uri.Sr25519DeriveSoft(seed, cc);

            Assert.That(res.Length, Is.EqualTo(96));

            var publicKey = res.Skip(64).Take(32);

            Assert.That(publicKey, Is.EquivalentTo(expected));
        }
    }
}
