using NUnit.Framework;
using Substrate.NET.Wallet;
using Substrate.NetApi;
using Substrate.NetApi.Model.Types;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

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
            Assert.False(Wallet.IsValidPassword("12345678"));
            Assert.False(Wallet.IsValidPassword("ABCDEFGH"));
            Assert.False(Wallet.IsValidPassword("abcdefgh"));
            Assert.False(Wallet.IsValidPassword("ABCDefgh"));
            Assert.False(Wallet.IsValidPassword("1BCDefg"));

            Assert.True(Wallet.IsValidPassword("ABCDefg1"));
        }

        [Test]
        public void IsValidWalletNameTest()
        {
            Assert.False(Wallet.IsValidWalletName("1234"));
            Assert.False(Wallet.IsValidWalletName("ABC_/"));

            Assert.True(Wallet.IsValidWalletName("wal_let"));
            Assert.True(Wallet.IsValidWalletName("1111111"));
        }

        [Test]
        public void LoadWalletFromFileTest()
        {
            var walletName = "dev_wallet";

            Wallet.Load(walletName, out Wallet wallet1);
            Assert.True(wallet1.IsStored);
            Assert.False(wallet1.IsUnlocked);
        }

        [Test]
        public void CreateWalletEd25519Test()
        {
            var walletName = "wallet1";

            Wallet.CreateFromRandom("aA1234dd", KeyType.Ed25519, walletName, out Wallet wallet1);
            Assert.True(wallet1.IsStored);
            Assert.True(wallet1.IsUnlocked);

            // load wallet wallet
            Wallet.Load(walletName, out Wallet wallet2);
            Assert.True(wallet2.IsStored);
            Assert.False(wallet2.IsUnlocked);

            // unlock wallet with password
            Assert.False(wallet2.IsUnlocked);
            wallet2.Unlock("aA1234dd");
            Assert.True(wallet2.IsUnlocked);
            Assert.AreEqual(wallet1.Account.Value, wallet2.Account.Value);
        }

        [Test]
        public void CreateWalletSr25519Test()
        {
            var walletName = "wallet2";

            // create new wallet with password and persist
            Wallet.CreateFromRandom("aA1234dd", KeyType.Sr25519, walletName, out Wallet wallet1);
            Assert.True(wallet1.IsStored);
            Assert.True(wallet1.IsUnlocked);

            // read wallet
            Wallet.Load(walletName, out Wallet wallet2);
            Assert.True(wallet2.IsStored);
            Assert.False(wallet2.IsUnlocked);

            // unlock wallet with password
            Assert.False(wallet2.IsUnlocked);
            wallet2.Unlock("aA1234dd");
            Assert.True(wallet2.IsUnlocked);
            Assert.AreEqual(wallet1.Account.Value, wallet2.Account.Value);
        }

        [Test]
        public void CreateMnemonicSr25519Test()
        {
            //var mnemonic = "donor rocket find fan language damp yellow crouch attend meat hybrid pulse";
            var mnemonic = "tornado glad segment lift squirrel top ball soldier joy sudden edit advice";
            var walletName = "mnem_wallet1";

            // create new wallet with password and persist
            Wallet.CreateFromMnemonic("aA1234dd", mnemonic, KeyType.Sr25519, Mnemonic.BIP39Wordlist.English, walletName, out Wallet wallet1);
            Assert.True(wallet1.IsStored);
            Assert.True(wallet1.IsUnlocked);
            Assert.AreEqual("5Fe24e21Ff5vRtuWa4ZNPv1EGQz1zBq1VtT8ojqfmzo9k11P", wallet1.Account.Value);

            // read wallet
            Wallet.Load(walletName, out Wallet wallet2);
            Assert.True(wallet2.IsStored);
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
            var walletName = "mnem_wallet2";

            // create new wallet with password and persist
            Wallet.CreateFromMnemonic("aA1234dd", mnemonic, KeyType.Ed25519, Mnemonic.BIP39Wordlist.English, walletName, out Wallet wallet1);
            Assert.True(wallet1.IsStored);
            Assert.True(wallet1.IsUnlocked);
            Assert.AreEqual("5CcaF7yE6YU67TyPHjSwd9DKiVBTAS2AktdxNG3DeLYs63gF", wallet1.Account.Value);

            // read wallet
            Wallet.Load(walletName, out Wallet wallet2);
            Assert.True(wallet2.IsStored);
            Assert.False(wallet2.IsUnlocked);

            // unlock wallet with password
            wallet2.Unlock("aA1234dd");
            Assert.True(wallet2.IsUnlocked);
            Assert.AreEqual(wallet1.Account.Value, wallet2.Account.Value);
        }

        [Test]
        public void CreateAccountTest()
        {
            var mnemonic = "tornado glad segment lift squirrel top ball soldier joy sudden edit advice";
            var address = "5CcaF7yE6YU67TyPHjSwd9DKiVBTAS2AktdxNG3DeLYs63gF";
            var walletName = "acc_wallet";

            // create new wallet with password and persist
            Wallet.CreateFromMnemonic("aA1234dd", mnemonic, KeyType.Ed25519, Mnemonic.BIP39Wordlist.English, walletName, out Wallet wallet1);
            Assert.True(wallet1.IsStored);
            Assert.True(wallet1.IsUnlocked);
            Assert.AreEqual(address, wallet1.Account.Value);

            // recreate wallet
            Wallet.CreateFromAccount(wallet1.Account, "aA1234dd", walletName + "_cp", out Wallet wallet2);
            Assert.True(wallet2.IsStored);
            Assert.True(wallet2.IsUnlocked);
            Assert.AreEqual(address, wallet2.Account.Value);

            // read wallet
            Wallet.Load(walletName, out Wallet wallet3);
            Assert.True(wallet3.IsStored);
            Assert.False(wallet3.IsUnlocked);
            Assert.AreEqual(address, wallet3.Account.Value);
            wallet3.Unlock("aA1234dd");
            Assert.True(wallet3.IsUnlocked);
        }

        [Test]
        public void SignatureVerifyTest()
        {
            var data = Encoding.UTF8.GetBytes("Let's sign this message, now!");

            Random random = new Random();
            var randomBytes = new byte[16];
            random.NextBytes(randomBytes);

            var mnemonic = string.Join(" ", Mnemonic.MnemonicFromEntropy(randomBytes, Mnemonic.BIP39Wordlist.English));
            var accountSr = Mnemonic.GetAccountFromMnemonic(mnemonic, "", KeyType.Sr25519);

            Assert.True(Wallet.TrySignMessage(accountSr, data, out byte[] signatureSrNoWrap, false));
            Assert.True(Wallet.TrySignMessage(accountSr, data, out byte[] signatureSrWrap, true));

            Assert.True(Wallet.VerifySignature(accountSr, data, signatureSrNoWrap, false));
            Assert.True(Wallet.VerifySignature(accountSr, data, signatureSrWrap, true));

            var accountEd = Mnemonic.GetAccountFromMnemonic(mnemonic, "", KeyType.Ed25519);

            Assert.True(Wallet.TrySignMessage(accountEd, data, out byte[] signatureEdNoWrap, false));
            Assert.True(Wallet.TrySignMessage(accountEd, data, out byte[] signatureEdWrap, true));

            Assert.True(Wallet.VerifySignature(accountEd, data, signatureEdNoWrap, false));
            Assert.True(Wallet.VerifySignature(accountEd, data, signatureEdWrap, true));
        }

        [Test]
        public void FullCreationTest()
        {
            RandomNumberGenerator random = RandomNumberGenerator.Create();
            var randomBytes = new byte[16];
            random.GetBytes(randomBytes);
            var mnemonic = string.Join(" ", Mnemonic.MnemonicFromEntropy(randomBytes, Mnemonic.BIP39Wordlist.English));
            var tempAccount = Mnemonic.GetAccountFromMnemonic(mnemonic, "", KeyType.Sr25519);
            var tempName = "HANS_IS";
            var tempPassword = "aA1234dd";

            Wallet.CreateFromAccount(tempAccount, tempPassword, tempName, out Wallet wallet1);
            Assert.True(wallet1.IsStored);
            Assert.True(wallet1.IsUnlocked);
        }
    }
}