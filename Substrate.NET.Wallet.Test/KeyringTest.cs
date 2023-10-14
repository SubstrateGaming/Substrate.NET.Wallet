using NUnit.Framework;
using Substrate.NetApi;
using System;
using System.IO;
using Substrate.NET.Wallet.Extensions;
using Substrate.NET.Wallet.Keyring;
using static Substrate.NET.Wallet.Keyring.Mnemonic;

namespace Substrate.NET.Wallet.Test
{
    internal class KeyringTest
    {
        protected string readJsonFromFile(string jsonFile)
        {
            return File.ReadAllText($"{AppContext.BaseDirectory}\\Data\\{jsonFile}");
        }

        private Meta defaultMeta = new Meta()
        {
            genesisHash = "0x91b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3",
            isHardware = false,
            name = "SubstrateAccount2",
            tags = null
        };

        [Test]
        [TestCase("json_account1.json", "SUBSTRATE")]
        [TestCase("json_generated_1.json", "AccountTest4")]
        public void ValidJson_WithValidPassword_ShouldUnlock(string json, string password)
        {
            var input = readJsonFromFile(json);

            var keyring = new Keyring.Keyring();
            var kp = keyring.AddFromJson(input);

            Assert.That(kp, Is.Not.Null);

            // Ensure wallet is lock because we don't provide any password
            Assert.That(kp.IsLocked, Is.EqualTo(true));

            kp.Unlock(password);
            Assert.That(kp.IsLocked, Is.EqualTo(false));

            // And now lock it again
            kp.Lock();
            Assert.That(kp.IsLocked, Is.EqualTo(true));
        }

        [Test]
        [TestCase("json_account1.json")]
        public void ValidJson_WithInvalidPassword_ShouldThrowException(string json)
        {
            var input = readJsonFromFile(json);

            var keyring = new Keyring.Keyring();
            var res = keyring.AddFromJson(input);

            Assert.Throws<InvalidOperationException>(() => res.Unlock("SS2"));
        }

        [Test]
        [TestCase("json_account1.json", "SUBSTRATE")]
        public void ImportFromValidJson_ThenDuplicateAccount_ShouldHaveSamePrivateKey(string json, string password)
        {
            var input = readJsonFromFile(json);

            var keyring = new Keyring.Keyring();
            var keyringPair1 = keyring.AddFromJson(input);

            var walletEncryptionSamePassword = keyringPair1.ToWalletEncryption(password);
            var keyringPair2 = keyring.AddFromJson(walletEncryptionSamePassword);

            Assert.That(keyringPair1.PairInformation.PublicKey, Is.EqualTo(keyringPair2.PairInformation.PublicKey));

            Assert.That(keyringPair1.IsLocked, Is.False);
            Assert.That(keyringPair2.IsLocked, Is.True);

            keyringPair2.Unlock(password);
            Assert.That(keyringPair1.PairInformation.SecretKey, Is.EqualTo(keyringPair2.PairInformation.SecretKey));
        }

        [TestCase("fun claim spawn flavor enable enrich advice canyon aisle aware energy level")]
        public void AddFromMnemonic_ShouldSucceed(string mnemonic)
        {
            var keyring = new Keyring.Keyring();
            var kp = keyring.AddFromMnemonic(mnemonic, defaultMeta, NetApi.Model.Types.KeyType.Sr25519);

            Assert.That(kp.IsLocked, Is.False);
        }

        [Test]
        public void GenerateNewAccount_WithPassword_AndExportToJson()
        {
            var keyring = new Keyring.Keyring();
            var kp = keyring.AddFromMnemonic(GenerateMnemonic(MnemonicSize.Words12), new Meta()
            {
                genesisHash = "0x91b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3",
                isHardware = false,
                name = "SubstrateAccount",
                tags = null
            }, NetApi.Model.Types.KeyType.Sr25519);

            var walletResult = kp.ToWalletEncryption("testPassword");
            var jsonResult = walletResult.ToJson();

            Assert.That(jsonResult, Is.Not.Null);
        }

        [Test]
        public void GenerateNewAccount_Ed25519AndSr25519_ShouldHaveDifferentPublicAndSecretKey()
        {
            var mnemonic = GenerateMnemonic(MnemonicSize.Words12);
            var keyring = new Keyring.Keyring();

            var kp_Ed25519 = keyring.AddFromMnemonic(mnemonic, defaultMeta, NetApi.Model.Types.KeyType.Ed25519);
            var kp_Sr25519 = keyring.AddFromMnemonic(mnemonic, defaultMeta, NetApi.Model.Types.KeyType.Sr25519);

            Assert.That(kp_Ed25519.PairInformation.PublicKey, Is.Not.EquivalentTo(kp_Sr25519.PairInformation.PublicKey));
            Assert.That(kp_Ed25519.PairInformation.SecretKey, Is.Not.EquivalentTo(kp_Sr25519.PairInformation.SecretKey));
        }
    }
}
