using NUnit.Framework;
using System;
using System.IO;
using Substrate.NET.Wallet.Keyring;
using Substrate.NetApi;
using static Substrate.NetApi.Mnemonic;

namespace Substrate.NET.Wallet.Test
{
    internal class KeyringTest
    {
        protected string readJsonFromFile(string jsonFile)
        {
            return File.ReadAllText($"{AppContext.BaseDirectory}/Data/{jsonFile}");
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
            var kp = keyring.AddFromMnemonic(Mnemonic.GenerateMnemonic(Mnemonic.MnemonicSize.Words12), new Meta()
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
            var mnemonic = Mnemonic.GenerateMnemonic(Mnemonic.MnemonicSize.Words12);
            var keyring = new Keyring.Keyring();

            var kp_Ed25519 = keyring.AddFromMnemonic(mnemonic, defaultMeta, NetApi.Model.Types.KeyType.Ed25519);
            var kp_Sr25519 = keyring.AddFromMnemonic(mnemonic, defaultMeta, NetApi.Model.Types.KeyType.Sr25519);

            Assert.That(kp_Ed25519.PairInformation.PublicKey, Is.Not.EquivalentTo(kp_Sr25519.PairInformation.PublicKey));
            Assert.That(kp_Ed25519.PairInformation.SecretKey, Is.Not.EquivalentTo(kp_Sr25519.PairInformation.SecretKey));
        }

        [Test]
        public void DecodeAddress()
        {
            var keyring = new Substrate.NET.Wallet.Keyring.Keyring();
            var publicKey = new byte[] { 16, 178, 46, 190, 137, 179, 33, 55, 11, 238, 141, 57, 213, 197, 212, 17, 218, 241, 232, 252, 145, 201, 209, 83, 64, 68, 89, 15, 31, 150, 110, 188 };

            Assert.That(keyring.DecodeAddress("5CSbZ7wG456oty4WoiX6a1J88VUbrCXLhrKVJ9q95BsYH4TZ"), Is.EqualTo(publicKey));
            Assert.That(keyring.DecodeAddress("CxDDSH8gS7jecsxaRL9Txf8H5kqesLXAEAEgp76Yz632J9M"), Is.EqualTo(publicKey));
            Assert.That(keyring.DecodeAddress("1NthTCKurNHLW52mMa6iA8Gz7UFYW5UnM3yTSpVdGu4Th7h"), Is.EqualTo(publicKey));
        }

        [Test]
        public void EncodeAddress()
        {
            var keyring = new Substrate.NET.Wallet.Keyring.Keyring();
            var publicKey = new byte[] { 16, 178, 46, 190, 137, 179, 33, 55, 11, 238, 141, 57, 213, 197, 212, 17, 218, 241, 232, 252, 145, 201, 209, 83, 64, 68, 89, 15, 31, 150, 110, 188 };

            keyring.Ss58Format = 42;
            Assert.That(keyring.EncodeAddress(publicKey), Is.EqualTo("5CSbZ7wG456oty4WoiX6a1J88VUbrCXLhrKVJ9q95BsYH4TZ"));

            keyring.Ss58Format = 2;
            Assert.That(keyring.EncodeAddress(publicKey), Is.EqualTo("CxDDSH8gS7jecsxaRL9Txf8H5kqesLXAEAEgp76Yz632J9M"));

            keyring.Ss58Format = 0;
            Assert.That(keyring.EncodeAddress(publicKey), Is.EqualTo("1NthTCKurNHLW52mMa6iA8Gz7UFYW5UnM3yTSpVdGu4Th7h"));
        }

        [Test]
        public void Example()
        {
            // Create a new Keyring, by default ss58 format is 42 (Substrate standard address)
            var keyring = new Substrate.NET.Wallet.Keyring.Keyring();

            // You can specify ss58 address if needed (check SS58 regitry here : https://github.com/paritytech/ss58-registry/blob/main/ss58-registry.json)
            keyring.Ss58Format = 0; // Polkadot

            // Generate a new mnemonic for a new account
            var newMnemonic = Mnemonic.GenerateMnemonic(MnemonicSize.Words12);

            // Use an existing mnemonic
            var existingMnemonicAccount = "entire material egg meadow latin bargain dutch coral blood melt acoustic thought";

            // Import an account from mnemonic automatically unlock all feature
            var firstPair = keyring.AddFromMnemonic(existingMnemonicAccount, new Meta() { name = "My account name"}, NetApi.Model.Types.KeyType.Ed25519);
            // firstPair.IsLocked => false

            // You can export you account to a Json file
            var json = firstPair.ToJson("myPassword");

            // Import an account from a json file
            var secondPair = keyring.AddFromJson(json);
            // You need to unlock the account with the associated password
            secondPair.Unlock("myPassword");

            // Get an account instance from this Key pair
            var account = firstPair.GetAccount();

            // Sign a message
            string message = "Hello !";
            var signature = firstPair.Sign(message);
            var isVerify = firstPair.Verify(signature, message);
        }
    }
}
