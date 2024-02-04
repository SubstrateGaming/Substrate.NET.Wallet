using NUnit.Framework;
using Substrate.NetApi;
using Substrate.NetApi.Extensions;
using System.Collections.Generic;
using System.Linq;

namespace Substrate.NET.Wallet.Test.Keyrings
{
    internal class KeypairEd25519Tests
    {
        public (byte[] publicKey, byte[] seed) FirstAccount = (
            new byte[] { 47, 140, 97, 41, 216, 22, 207, 81, 195, 116, 188, 127, 8, 195, 230, 62, 209, 86, 207, 120, 174, 251, 74, 101, 80, 217, 123, 135, 153, 121, 119, 238 },
            "12345678901234567890123456789012".ToBytes()
        );

        public (byte[] publicKey, byte[] seed) SecondAccount = (
            new byte[] { 215, 90, 152, 1, 130, 177, 10, 183, 213, 75, 254, 211, 201, 100, 7, 58, 14, 225, 114, 243, 218, 166, 35, 37, 175, 2, 26, 104, 247, 7, 81, 26 },
            Utils.HexToByteArray("0x9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        );

        private Substrate.NET.Wallet.Keyring.Keyring keyring { get; set; }

        [SetUp]
        public void Setup()
        {
            keyring = new Keyring.Keyring()
            {
                Ss58Format = 42
            };

            keyring.AddFromSeed(FirstAccount.seed, null, NetApi.Model.Types.KeyType.Ed25519);
        }

        [Test]
        public void AddPairTwo()
        {
            Assert.That(
                keyring.AddFromSeed(SecondAccount.seed, null, NetApi.Model.Types.KeyType.Ed25519).Account.Bytes,
                Is.EqualTo(SecondAccount.publicKey));
        }

        [Test]
        [TestCase("seed sock milk update focus rotate barely fade car face mechanic mercy", "5DkQP32jP4DVJLWWBRBoZF2tpWjqFrcrTBo6H5NcSk7MxKCC")]
        public void CreateEd25519_WithMnemonic(string mnemonic, string publicKey)
        {
            var kp = keyring.AddFromUri(
                    mnemonic, null, NetApi.Model.Types.KeyType.Ed25519);
            Assert.That(kp.Address, Is.EqualTo(publicKey));
        }

        [Test]
        public void CreateEd25519_WithMnemonic_Ss58Changed()
        {
            keyring.Ss58Format = 2;
            var kp = keyring.AddFromUri(
                    "moral movie very draw assault whisper awful rebuild speed purity repeat card", null, NetApi.Model.Types.KeyType.Ed25519);

            Assert.That(kp.Address, Is.EqualTo("HSLu2eci2GCfWkRimjjdTXKoFSDL3rBv5Ey2JWCBj68cVZj"));
        }

        [Test]
        public void Ed25519_SignsAndVerifies()
        {
            string message = "this is a message";
            var wallet = keyring.Wallets.First();

            var signature = wallet.Sign(message);

            Assert.That(wallet.Verify(signature, message, true), Is.True);
            Assert.That(wallet.Verify(signature, message, false), Is.False);
            Assert.That(wallet.Verify(signature, new byte[32].Populate()), Is.False);
        }

        [Test]
        public void GetAllPublicKeys()
        {
            keyring.AddFromSeed(SecondAccount.seed, null, NetApi.Model.Types.KeyType.Ed25519);

            Assert.That(keyring.GetPublicKeys(), Is.EqualTo(new List<byte[]>() { FirstAccount.publicKey, SecondAccount.publicKey }));
        }

        [Test]
        public void GetByPublicKey()
        {
            Assert.That(keyring.GetWallet(FirstAccount.publicKey).Account.Bytes, Is.EqualTo(FirstAccount.publicKey));
            Assert.That(keyring.GetWallet(SecondAccount.publicKey), Is.Null);
        }
    }
}