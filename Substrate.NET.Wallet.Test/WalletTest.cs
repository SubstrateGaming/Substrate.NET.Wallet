using Microsoft.VisualStudio.TestPlatform.CommunicationUtilities;
using NUnit.Framework;
using Substrate.NET.Wallet;
using Substrate.NET.Wallet.Keyring;
using Substrate.NetApi;
using Substrate.NetApi.Extensions;
using Substrate.NetApi.Model.Types;
using Substrate.NetApi.Sign;
using System;
using System.IO;
using System.Linq;
using System.Text;
using static Substrate.NetApi.Mnemonic;

namespace Substrate.NET.Wallet.Test
{
    public class WalletTest
    {
        private Wallet randomWallet;
        [SetUp]
        public void Setup()
        {
            Func<string, string> dir = f => Path.Combine(Environment.CurrentDirectory, f);
            SystemInteraction.ReadData = f => File.ReadAllText(dir(f));
            SystemInteraction.DataExists = f => File.Exists(dir(f));
            SystemInteraction.ReadPersistent = f => File.ReadAllText(dir(f));
            SystemInteraction.PersistentExists = f => File.Exists(dir(f));
            SystemInteraction.Persist = (f, c) => File.WriteAllText(dir(f), c);

            randomWallet = Keyring.Keyring.CreateFromUri(
                string.Join(" ", Mnemonic.GenerateMnemonic(MnemonicSize.Words12)),
                new Meta(),
                KeyType.Sr25519, 42);
        }

        [Test]
        public void IsValidPasswordTest()
        {
            Assert.That(Wallet.IsValidPassword("12345678"), Is.False);
            Assert.That(Wallet.IsValidPassword("ABCDEFGH"), Is.False);
            Assert.That(Wallet.IsValidPassword("abcdefgh"), Is.False);
            Assert.That(Wallet.IsValidPassword("ABCDefgh"), Is.False);

            Assert.That(Wallet.IsValidPassword("1BCDefg"), Is.True);
            Assert.That(Wallet.IsValidPassword("ABCDefg1"), Is.True);
        }

        [Test]
        public void IsValidWalletNameTest()
        {
            Assert.That(Wallet.IsValidWalletName("123"), Is.False);
            Assert.That(Wallet.IsValidWalletName("ABC_/"), Is.True);
            Assert.That(Wallet.IsValidWalletName("1111111"), Is.False);
            Assert.That(Wallet.IsValidWalletName("1234"), Is.False);

            Assert.That(Wallet.IsValidWalletName("wal_let"), Is.True);
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
            Assert.That(wallet.IsUnlocked, Is.True);
            Assert.That(wallet.IsStored, Is.False);

            wallet.Save(walletName, walletPassword);
            Assert.That(wallet.IsStored, Is.True);

            // Now let's try load
            Assert.That(Wallet.TryLoad(walletName, out Wallet loadedWallet), Is.True);

            Assert.That(loadedWallet.IsStored, Is.True);

            // Wallet is load, but locked
            Assert.That(loadedWallet.IsUnlocked, Is.False);

            loadedWallet.Unlock(walletPassword);
            Assert.That(loadedWallet.IsUnlocked, Is.True);

            Assert.That(loadedWallet.Account.Bytes, Is.EqualTo(wallet.Account.Bytes));
            Assert.That(loadedWallet.Account.PrivateKey, Is.EqualTo(wallet.Account.PrivateKey));
        }

        [Test]
        public void WalletStored_WhenNoCachingSet_ShoudFail()
        {
            SystemInteraction.DataExists = f => false;
            SystemInteraction.PersistentExists = f => false;

            Assert.That(Wallet.TryLoad("test", out Wallet wallet), Is.False);
        }

        [Test]
        public void WalletSign_WhenLock_ShoudFail()
        {
            randomWallet.Lock();
            Assert.Throws<InvalidOperationException>(() => randomWallet.Sign("testMessage"));
        }

        [Test]
        public void WalletVerify_WhenLock_ShoudFail()
        {
            randomWallet.Lock();
            Assert.Throws<InvalidOperationException>(() => randomWallet.Verify(new byte[0], "testMessage"));
        }

        [Test]
        public void WalletDerive_WhenLock_ShoudFail()
        {
            randomWallet.Lock();
            Assert.Throws<InvalidOperationException>(() => randomWallet.Derive("testDerive"));
        }
    }
}