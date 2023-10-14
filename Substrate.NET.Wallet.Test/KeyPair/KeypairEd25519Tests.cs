using NUnit.Framework;
using Substrate.NET.Wallet.Extensions;
using Substrate.NET.Wallet.Keyring;
using Substrate.NetApi;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Substrate.NET.Wallet.Test.KeyringTests
{
    internal class KeypairEd25519Tests
    {
        public byte[] publicKeyOne = new byte[] { 47, 140, 97, 41, 216, 22, 207, 81, 195, 116, 188, 127, 8, 195, 230, 62, 209, 86, 207, 120, 174, 251, 74, 101, 80, 217, 123, 135, 153, 121, 119, 238 };
        public byte[] publicKeyTwo = new byte[] { 215, 90, 152, 1, 130, 177, 10, 183, 213, 75, 254, 211, 201, 100, 7, 58, 14, 225, 114, 243, 218, 166, 35, 37, 175, 2, 26, 104, 247, 7, 81, 26 };
        public byte[] seedOne = "12345678901234567890123456789012".ToBytes();
        public byte[] seedTwo = Utils.HexToByteArray("0x9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");

        Substrate.NET.Wallet.Keyring.Keyring keyring { get; set; }

        [SetUp]
        public void Setup()
        {
            keyring = new Keyring.Keyring()
            {
                Ss58Format = 42
            };

            keyring.AddFromSeed(seedOne, null, NetApi.Model.Types.KeyType.Ed25519);
        }

        [Test]
        public void AddPairTwo()
        {
            Assert.That(
                keyring.AddFromSeed(seedTwo, null, NetApi.Model.Types.KeyType.Ed25519).PairInformation.PublicKey,
                Is.EqualTo(publicKeyTwo));
        }

        [Test]
        public void CreateEd25519_WithMnemonic()
        {
            var kp = keyring.AddFromUri(
                    "seed sock milk update focus rotate barely fade car face mechanic mercy", null, NetApi.Model.Types.KeyType.Ed25519);
            Assert.That(kp.Address, Is.EqualTo("5DkQP32jP4DVJLWWBRBoZF2tpWjqFrcrTBo6H5NcSk7MxKCC"));
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
            var pair = keyring.Pairs.First();
            var signature = pair.Sign(message);

            Assert.That(pair.Verify(signature, pair.PairInformation.PublicKey, message), Is.True);
            Assert.That(pair.Verify(signature, new byte[32].Populate(), message), Is.False);
            Assert.That(pair.Verify(signature, pair.PairInformation.PublicKey, new byte[32].Populate()), Is.False);
        }
    }
}
