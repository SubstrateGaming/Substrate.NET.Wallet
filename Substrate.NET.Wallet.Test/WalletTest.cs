using NUnit.Framework;
using Substrate.NET.Wallet;
using Substrate.NET.Wallet.Keyring;
using Substrate.NetApi;
using Substrate.NetApi.Extensions;
using Substrate.NetApi.Model.Types;
using System;
using System.IO;
using System.Linq;
using System.Text;
using static Substrate.NetApi.Mnemonic;

namespace Substrate.NET.Wallet.Test
{
    public class WalletTest
    {
        [SetUp]
        public void Setup()
        {
            Func<string, string> dir = f => Path.Combine(Environment.CurrentDirectory, f);
            SystemInteraction.ReadData = f => File.ReadAllText(dir(f));
            SystemInteraction.DataExists = f => File.Exists(dir(f));
            SystemInteraction.ReadPersistent = f => File.ReadAllText(dir(f));
            SystemInteraction.PersistentExists = f => File.Exists(dir(f));
            SystemInteraction.Persist = (f, c) => File.WriteAllText(dir(f), c);
        }

        [Test]
        public void IsValidPasswordTest()
        {
            Assert.False(Wallet.IsValidPassword("12345678"));
            Assert.False(Wallet.IsValidPassword("ABCDEFGH"));
            Assert.False(Wallet.IsValidPassword("abcdefgh"));
            Assert.False(Wallet.IsValidPassword("ABCDefgh"));
            
            Assert.True(Wallet.IsValidPassword("1BCDefg"));
            Assert.True(Wallet.IsValidPassword("ABCDefg1"));
        }

        [Test]
        public void IsValidWalletNameTest()
        {
            Assert.False(Wallet.IsValidWalletName("123"));
            Assert.True(Wallet.IsValidWalletName("ABC_/"));
            Assert.False(Wallet.IsValidWalletName("1111111"));

            Assert.True(Wallet.IsValidWalletName("wal_let"));
        }

        [Test]
        [TestCase("ApolixitWalletTest", "MyAwesomePassword1")]
        public void CreateWallet_SaveIt_ThenTryLoad_ShouldSuceed(string walletName, string walletPassword)
        {
            var keyring = new Keyring.Keyring();

            // Create a new random wallet
            var wallet = keyring.AddFromMnemonic(
                Mnemonic.GenerateMnemonic(MnemonicSize.Words12), 
                new Meta(), 
                KeyType.Sr25519);

            //Load from mnemonic should get wallet unlocked, but ofc, not saved
            Assert.IsTrue(wallet.IsUnlocked);
            Assert.IsFalse(wallet.IsStored);

            wallet.Save(walletName, walletPassword);
            Assert.IsTrue(wallet.IsStored);

            // Now let's try load
            Assert.IsTrue(Wallet.TryLoad(walletName, out Wallet loadedWallet));

            Assert.IsTrue(loadedWallet.IsStored);

            // Wallet is load, but locked
            Assert.IsFalse(loadedWallet.IsUnlocked);

            loadedWallet.Unlock(walletPassword);
            Assert.IsTrue(loadedWallet.IsUnlocked);

            Assert.That(loadedWallet.Account.Bytes, Is.EqualTo(wallet.Account.Bytes));
            Assert.That(loadedWallet.Account.PrivateKey, Is.EqualTo(wallet.Account.PrivateKey));
        }
    }
}