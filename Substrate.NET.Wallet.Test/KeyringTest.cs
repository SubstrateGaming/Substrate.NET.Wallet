using NUnit.Framework;
using Substrate.NetApi;
using System;
using System.IO;
using Substrate.NET.Wallet.Extensions;
using Substrate.NET.Wallet.Keyring;

namespace Substrate.NET.Wallet.Test
{
    internal class KeyringTest
    {
        protected string readJsonFromFile(string jsonFile)
        {
            return File.ReadAllText($"{AppContext.BaseDirectory}\\Data\\{jsonFile}");
        }

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
        [TestCase("json_account1.json")]
        public void ValidJson_WithNewPassword_ShouldRewriteJson(string json)
        {
            var input = readJsonFromFile(json);

            var keyring = new Keyring.Keyring();
            var keyringPair1 = keyring.AddFromJson(input);

            var walletEncryptionSamePassword = keyringPair1.ToWalletEncryption("SUBSTRATE");
            var keyringPair2 = keyring.AddFromJson(walletEncryptionSamePassword);

            Assert.That(keyringPair1.PairInformation.PublicKey, Is.EqualTo(keyringPair2.PairInformation.PublicKey));

            // Both are lock
            Assert.That(keyringPair1.IsLocked, Is.True);
            Assert.That(keyringPair2.IsLocked, Is.True);

            keyringPair1.Unlock("SUBSTRATE");
            keyringPair2.Unlock("SUBSTRATE");
            Assert.That(keyringPair1.PairInformation.SecretKey, Is.EqualTo(keyringPair2.PairInformation.SecretKey));
        }

        [Test, Ignore("WIP")]
        [TestCase("13zUtDC1UdzLu3ac7buXexHS1S5wAp5z1YmgsdiLHJpU7LtM")]
        public void AddFromMnemonic_WithValidMnemonic_ShouldSuceed(string address)
        {
            var meta = new Meta()
            {
                genesisHash = "0x35a06bfec2edf0ff4be89a6428ccd9ff5bd0167d618c5a0d4341f9600a458d14",
                isHardware = false,
                name = "SUBSTRATE"
            };
            var keyring = new Keyring.Keyring();
            keyring.Ss58Format = 2;

            var kp = keyring.AddFromMnemonic("moral movie very draw assault whisper awful rebuild speed purity repeat card", meta, NetApi.Model.Types.KeyType.Sr25519);

            Assert.That(kp.Address, Is.EqualTo("HSLu2eci2GCfWkRimjjdTXKoFSDL3rBv5Ey2JWCBj68cVZj"));
        }

        [TestCase("fun claim spawn flavor enable enrich advice canyon aisle aware energy level", "AccountTest4")]
        public void CreateNewAccount_WithPassword_AndExportToJson(string mnemonic, string password)
        {
            //var seed = Mnemonic.MnemonicFromEntropy(new byte[16].Populate(), Mnemonic.BIP39Wordlist.English);

            var keyring = new Keyring.Keyring();
            var kp = keyring.AddFromMnemonic(mnemonic, new Meta()
            {
                genesisHash = "0x91b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3",
                isHardware = false,
                name = "SubstrateAccount2",
                tags = null
            }, NetApi.Model.Types.KeyType.Sr25519);

            var walletResult = kp.ToWalletEncryption(password);
            Assert.That(walletResult, Is.Not.Null);

            var jsonResult = kp.ToJson(password);
            Assert.That(jsonResult, Is.Not.Null);
        }

        [Test]
        public void GenerateNewAccount_WithPassword_AndExportToJson()
        {
            var mnemonic = Mnemonic.MnemonicFromEntropy(new byte[16].Populate(), Mnemonic.BIP39Wordlist.English);

            var keyring = new Keyring.Keyring();
            var kp = keyring.AddFromMnemonic(mnemonic, new Meta()
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
    }
}
