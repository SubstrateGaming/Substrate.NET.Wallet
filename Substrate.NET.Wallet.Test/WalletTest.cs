using NUnit.Framework;
using Substrate.NET.Wallet;
using Substrate.NetApi;
using Substrate.NetApi.Model.Types;
using System;
using System.IO;

namespace SubstrateNetWalletTest
{
    public class WalletTest
    {
        [SetUp]
        public void Setup()
        {
            SystemInteraction.ReadData = f => File.ReadAllText(Path.Combine(Environment.CurrentDirectory, f));
            SystemInteraction.DataExists = f => File.Exists(Path.Combine(Environment.CurrentDirectory, f));
            SystemInteraction.ReadPersistent = f => File.ReadAllText(Path.Combine(Environment.CurrentDirectory, f));
            SystemInteraction.PersistentExists = f => File.Exists(Path.Combine(Environment.CurrentDirectory, f));
            SystemInteraction.Persist = (f, c) => File.WriteAllText(Path.Combine(Environment.CurrentDirectory, f), c);
        }

        [Test]
        public void IsValidPasswordTest()
        {
            var wallet = new Wallet();

            Assert.False(wallet.IsValidPassword("12345678"));
            Assert.False(wallet.IsValidPassword("ABCDEFGH"));
            Assert.False(wallet.IsValidPassword("abcdefgh"));
            Assert.False(wallet.IsValidPassword("ABCDefgh"));
            Assert.False(wallet.IsValidPassword("1BCDefg"));

            Assert.True(wallet.IsValidPassword("ABCDefg1"));
        }

        [Test]
        public void IsValidWalletNameTest()
        {
            var wallet = new Wallet();

            Assert.False(wallet.IsValidWalletName("1234"));
            Assert.False(wallet.IsValidWalletName("ABC_/"));

            Assert.True(wallet.IsValidWalletName("wal_let"));
            Assert.True(wallet.IsValidWalletName("1111111"));
        }

        [Test]
        public void CreateWalletEd25519Test()
        {
            // create new wallet with password and persist
            var wallet1 = new Wallet();

            wallet1.Create("aA1234dd", KeyType.Ed25519);

            Assert.True(wallet1.IsCreated);

            Assert.True(wallet1.IsUnlocked);

            // read wallet
            var wallet2 = new Wallet();

            wallet2.Load();

            Assert.True(wallet2.IsCreated);

            Assert.False(wallet2.IsUnlocked);

            // unlock wallet with password
            wallet2.Unlock("aA1234dd");

            Assert.True(wallet2.IsUnlocked);

            Assert.AreEqual(wallet1.Account.Value, wallet2.Account.Value);

            var wallet3 = new Wallet();

            Assert.False(wallet3.IsCreated);

            wallet3.Load();

            Assert.True(wallet3.IsCreated);

            Assert.False(wallet3.IsUnlocked);

            // unlock wallet with password
            wallet3.Unlock("aA4321dd");

            Assert.False(wallet3.IsUnlocked);

            var wallet4 = new Wallet();
            wallet4.Load("dev_wallet");

            Assert.True(wallet4.IsCreated);
        }

        [Test]
        public void CreateWalletSr25519Test()
        {
            // create new wallet with password and persist
            var wallet1 = new Wallet();

            wallet1.Create("aA1234dd", KeyType.Sr25519);

            Assert.True(wallet1.IsCreated);

            Assert.True(wallet1.IsUnlocked);

            // read wallet
            var wallet2 = new Wallet();

            wallet2.Load();

            Assert.True(wallet2.IsCreated);

            Assert.False(wallet2.IsUnlocked);

            // unlock wallet with password
            wallet2.Unlock("aA1234dd");

            Assert.True(wallet2.IsUnlocked);

            Assert.AreEqual(wallet1.Account.Value, wallet2.Account.Value);

            var wallet3 = new Wallet();

            Assert.False(wallet3.IsCreated);

            wallet3.Load();

            Assert.True(wallet3.IsCreated);

            Assert.False(wallet3.IsUnlocked);

            // unlock wallet with password
            wallet3.Unlock("aA4321dd");

            Assert.False(wallet3.IsUnlocked);

            var wallet4 = new Wallet();
            wallet4.Load("dev_wallet");

            Assert.True(wallet4.IsCreated);
        }

        [Test]
        public void CreateMnemonicSr25519Test()
        {
            //var mnemonic = "donor rocket find fan language damp yellow crouch attend meat hybrid pulse";
            var mnemonic = "tornado glad segment lift squirrel top ball soldier joy sudden edit advice";

            // create new wallet with password and persist
            var wallet1 = new Wallet();

            wallet1.Create("aA1234dd", mnemonic, KeyType.Sr25519, Mnemonic.BIP39Wordlist.English, "mnemonic_wallet");

            Assert.True(wallet1.IsCreated);

            Assert.True(wallet1.IsUnlocked);

            Assert.AreEqual("5DUUUnqM2wtsr7Acc4T5usvN3pmkdX5shkKkPEFtH7mEdk1g", wallet1.Account.Value);

            // read wallet
            var wallet2 = new Wallet();

            wallet2.Load("mnemonic_wallet");

            Assert.True(wallet2.IsCreated);

            Assert.False(wallet2.IsUnlocked);

            // unlock wallet with password
            wallet2.Unlock("aA1234dd");

            Assert.True(wallet2.IsUnlocked);

            Assert.AreEqual(wallet1.Account.Value, wallet2.Account.Value);
        }

        [Test]
        public void CreateMnemonicEd25519Test()
        {
            var mnemonic = "tornado glad segment lift squirrel top ball soldier joy sudden edit advice";

            // create new wallet with password and persist
            var wallet1 = new Wallet();

            wallet1.Create("aA1234dd", mnemonic, KeyType.Ed25519, Mnemonic.BIP39Wordlist.English, "mnemonic_wallet");

            Assert.True(wallet1.IsCreated);

            Assert.True(wallet1.IsUnlocked);

            Assert.AreEqual("5HDyAVCfErKADLgtdhGKPiDbFStPP2cXAzNnJh4qbFaECkWY", wallet1.Account.Value);

            // read wallet
            var wallet2 = new Wallet();

            wallet2.Load("mnemonic_wallet");

            Assert.True(wallet2.IsCreated);

            Assert.False(wallet2.IsUnlocked);

            // unlock wallet with password
            wallet2.Unlock("aA1234dd");

            Assert.True(wallet2.IsUnlocked);

            Assert.AreEqual(wallet1.Account.Value, wallet2.Account.Value);
        }

        [Test]
        public void CheckAccount()
        {
            var wallet = new Wallet();
            wallet.Load("dev_wallet");

            Assert.True(wallet.IsCreated);

            wallet.Unlock("aA1234dd");

            Assert.True(wallet.IsUnlocked);

            Assert.AreEqual("5FfzQe73TTQhmSQCgvYocrr6vh1jJXEKB8xUB6tExfpKVCEZ", wallet.Account.Value);
        }
    }
}