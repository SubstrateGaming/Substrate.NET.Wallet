﻿using NUnit.Framework;
using Substrate.NET.Wallet.Extensions;
using Substrate.NetApi;
using Substrate.NetApi.Extensions;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Substrate.NET.Wallet.Test.Keyrings
{
    internal class KeypairSr25519Tests
    {
        public (byte[] publicKey, byte[] seed) FirstAccount = (
            new byte[] { 116, 28, 8, 160, 111, 65, 197, 150, 96, 143, 103, 116, 37, 155, 217, 4, 51, 4, 173, 250, 93, 62, 234, 98, 118, 11, 217, 190, 151, 99, 77, 99 },
            "12345678901234567890123456789012".ToBytes()
        );

        public (byte[] publicKey, byte[] seed) SecondAccount = (
            Utils.HexToByteArray("0x44a996beb1eef7bdcab976ab6d2ca26104834164ecf28fb375600576fcc6eb0f"),
            Utils.HexToByteArray("0x9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        );
        Substrate.NET.Wallet.Keyring.Keyring keyring { get; set; }

        [SetUp]
        public void Setup()
        {
            keyring = new Keyring.Keyring()
            {
                Ss58Format = 42
            };

            keyring.AddFromSeed(FirstAccount.seed, null, NetApi.Model.Types.KeyType.Sr25519);
        }

        [Test]
        public void AddPairTwo()
        {
            var kp = keyring.AddFromSeed(SecondAccount.seed, null, NetApi.Model.Types.KeyType.Sr25519);
            Assert.That(
                kp.Account.Bytes,
                Is.EqualTo(SecondAccount.publicKey));
        }

        [Test]
        public void CreateSr25519_WithMnemonic()
        {
            keyring.Ss58Format = 2;
            var kp = keyring.AddFromUri(
                    "moral movie very draw assault whisper awful rebuild speed purity repeat card", null, NetApi.Model.Types.KeyType.Sr25519);
            Assert.That(kp.Address, Is.EqualTo("FSjXNRT2K1R5caeHLPD6WMrqYUpfGZB7ua8W89JFctZ1YqV"));
        }

        [Test]
        public void CreateWithIntegerDerivations()
        {
            var kp1 = keyring.CreateFromUri("//9007199254740991", null, NetApi.Model.Types.KeyType.Sr25519);
            Assert.That(kp1.Address, Is.EqualTo("5CDsyNZyqxLpHnTvknr68anUcYoBFjZbFKiEJJf4prB75Uog"));

            var kp2 = keyring.CreateFromUri("//900719925474099999", null, NetApi.Model.Types.KeyType.Sr25519);
            Assert.That(kp2.Address, Is.EqualTo("5GHj2D7RG2m2DXYwGSDpXwuuxn53G987i7p2EQVDqP4NYu4q"));
        }

        [Test]
        public void Sr25519_SignsAndVerifies()
        {
            string message = "this is a message";
            var pair = keyring.Wallets.First();
            var signature = pair.Sign(message);

            Assert.That(pair.Verify(signature, message), Is.True);
            Assert.That(pair.Verify(signature, new byte[32].Populate()), Is.False);
        }

        [Test]
        public void GetAllPublicKeys()
        {
            keyring.AddFromSeed(SecondAccount.seed, null, NetApi.Model.Types.KeyType.Sr25519);

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
