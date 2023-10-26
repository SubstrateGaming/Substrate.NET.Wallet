using NUnit.Framework;
using Substrate.NET.Wallet;
using Substrate.NET.Wallet.Keyring;
using Substrate.NetApi;
using Substrate.NetApi.Extensions;
using Substrate.NetApi.Model.Types;
using System;
using System.IO;
using System.Text;

namespace Substrate.NET.Wallet.Test
{
    public class WalletTest
    {
        /*
         const alice = createPair({ toSS58, type: 'sr25519' }, { publicKey: hexToU8a(PAIRSSR25519[0].p), secretKey: hexToU8a(PAIRSSR25519[0].s) }, {});
    const stash = alice.derive('//stash');
    const soft = alice.derive('//funding/0');
         */
        public Wallet AliceSr25519 => Pair.CreatePair(new KeyringAddress(KeyType.Sr25519),
                new PairInfo(
                    Utils.HexToByteArray("0xd43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d"),
                    Utils.HexToByteArray("0x98319d4ff8a9508c4bb0cf0b5a78d760a0b2082c02775e6e82370816fedfff48925a225d97aa00682d6a59b95b18780c10d7032336e88f3442b42361f4a66011"))
                );

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

        //[Test]
        //public void LoadWalletFromFileTest()
        //{
        //    var walletName1 = "dev_wallet1";
        //    Wallet.TryLoad(walletName1, out Wallet wallet1);
        //    Assert.True(wallet1.IsStored);
        //    Assert.False(wallet1.IsUnlocked);
        //    Assert.AreEqual("Ed25519",
        //        wallet1.FileStore.GetKeyType().ToString());
        //    Assert.AreEqual("5FfzQe73TTQhmSQCgvYocrr6vh1jJXEKB8xUB6tExfpKVCEZ",
        //        wallet1.FileStore.address);
        //    Assert.AreEqual("0x17E39AC65C894EC263396E9B8720D78A7A5FE0CB6C5C05DC32E756DF3D5D2D9622DBFDB41CE0C9067B810BB03E1DCE9C89CFC061FBB063B616FF91F3AA31498158632A35601C91DFEE5DA869D44FA8A4",
        //        Utils.Bytes2HexString(wallet1.FileStore.EncryptedSeed));
        //    Assert.AreEqual("0x34F0627DB7C9BF1B580A597122622E95",
        //        Utils.Bytes2HexString(wallet1.FileStore.Salt));
        //    wallet1.Unlock("aA1234dd");
        //    Assert.True(wallet1.IsUnlocked);

        //    var walletName2 = "dev_wallet2";
        //    Wallet.TryLoad(walletName2, out Wallet wallet2);
        //    Assert.True(wallet2.IsStored);
        //    Assert.False(wallet2.IsUnlocked);
        //    Assert.AreEqual("Sr25519",
        //        wallet2.FileStore.GetKeyType().ToString());
        //    Assert.AreEqual("5Fe24e21Ff5vRtuWa4ZNPv1EGQz1zBq1VtT8ojqfmzo9k11P",
        //        Utils.GetAddressFrom(wallet2.FileStore.PublicKey));
        //    Assert.AreEqual("0xDA24A6B58BE083B58E3F011929B8A454B5FE9F1B91961DCC766D3E9F6AFE7AF96AAC1372DBA4537856F95C7E47A365C10590ACC092DB5AA95D6ECF5E06167B799AC6247178B7C51AC9B8F64C16602659",
        //        Utils.Bytes2HexString(wallet2.FileStore.EncryptedSeed));
        //    Assert.AreEqual("0xD048477FCAD42D83402CDE3B2AF369D4",
        //        Utils.Bytes2HexString(wallet2.FileStore.Salt));
        //    wallet2.Unlock("aA1234dd");
        //    Assert.True(wallet2.IsUnlocked);
        //    Assert.AreEqual("0x6BED04FEE1504A49825339A68F601F7739FA7CEBF3B5E6A4A2476979F53CF40A112F6ED717AE8E8F5134C784A07DE6F3B2F7DA51D8117C566547A5038D4B3C27",
        //        Utils.Bytes2HexString(wallet2.Account.PrivateKey));
        //}

        //[Test]
        //public void LoadWalletFromFileStore()
        //{
        //    var walletName1 = "dev_wallet1";
        //    Wallet.TryLoad(walletName1, out Wallet wallet1);
        //    Assert.True(wallet1.IsStored);
        //    Assert.False(wallet1.IsUnlocked);

        //    var walletName2 = "dev_wallet3";
        //    Wallet.Load(walletName2, wallet1.FileStore, out Wallet wallet2);

        //    Assert.AreEqual("Ed25519",
        //        wallet2.FileStore.KeyType.ToString());
        //    Assert.AreEqual("5FfzQe73TTQhmSQCgvYocrr6vh1jJXEKB8xUB6tExfpKVCEZ",
        //        Utils.GetAddressFrom(wallet2.FileStore.PublicKey));
        //    Assert.AreEqual("0x17E39AC65C894EC263396E9B8720D78A7A5FE0CB6C5C05DC32E756DF3D5D2D9622DBFDB41CE0C9067B810BB03E1DCE9C89CFC061FBB063B616FF91F3AA31498158632A35601C91DFEE5DA869D44FA8A4",
        //        Utils.Bytes2HexString(wallet2.FileStore.EncryptedSeed));
        //    Assert.AreEqual("0x34F0627DB7C9BF1B580A597122622E95",
        //        Utils.Bytes2HexString(wallet2.FileStore.Salt));
        //    wallet2.Unlock("aA1234dd");
        //    Assert.True(wallet2.IsUnlocked);
        //}

        //[Test]
        //public void CreateWalletEd25519Test()
        //{
        //    var walletName = "wallet1";

        //    Wallet.CreateFromRandom("aA1234dd", KeyType.Ed25519, walletName, out Wallet wallet1);
        //    Assert.True(wallet1.IsStored);
        //    Assert.True(wallet1.IsUnlocked);

        //    // load wallet wallet
        //    Wallet.TryLoad(walletName, out Wallet wallet2);
        //    Assert.True(wallet2.IsStored);
        //    Assert.False(wallet2.IsUnlocked);
        //    wallet2.Unlock("aA1234dd");
        //    Assert.True(wallet2.IsUnlocked);
        //    Assert.AreEqual(wallet1.Account.Value, wallet2.Account.Value);
        //}

        //[Test]
        //public void CreateWalletSr25519Test()
        //{
        //    var walletName = "wallet2";

        //    // create new wallet with password and persist
        //    Wallet.CreateFromRandom("aA1234dd", KeyType.Sr25519, walletName, out Wallet wallet1);
        //    Assert.True(wallet1.IsStored);
        //    Assert.True(wallet1.IsUnlocked);

        //    // read wallet
        //    Wallet.TryLoad(walletName, out Wallet wallet2);
        //    Assert.True(wallet2.IsStored);
        //    Assert.False(wallet2.IsUnlocked);
        //    wallet2.Unlock("aA1234dd");
        //    Assert.True(wallet2.IsUnlocked);
        //    Assert.AreEqual(wallet1.Account.Value, wallet2.Account.Value);
        //}

        //[Test]
        //public void CreateMnemonicSr25519Test()
        //{
        //    //var mnemonic = "donor rocket find fan language damp yellow crouch attend meat hybrid pulse";
        //    var mnemonic = "tornado glad segment lift squirrel top ball soldier joy sudden edit advice";
        //    var walletName = "mnem_wallet1";

        //    // create new wallet with password and persist
        //    Wallet.CreateFromMnemonic("aA1234dd", mnemonic, KeyType.Sr25519, Mnemonic.BIP39Wordlist.English, walletName, out Wallet wallet1);
        //    Assert.True(wallet1.IsStored);
        //    Assert.True(wallet1.IsUnlocked);
        //    Assert.AreEqual("5Fe24e21Ff5vRtuWa4ZNPv1EGQz1zBq1VtT8ojqfmzo9k11P", wallet1.Account.Value);

        //    // read wallet
        //    Wallet.TryLoad(walletName, out Wallet wallet2);
        //    Assert.True(wallet2.IsStored);
        //    Assert.False(wallet2.IsUnlocked);
        //    wallet2.Unlock("aA1234dd");
        //    Assert.True(wallet2.IsUnlocked);
        //    Assert.AreEqual(wallet1.Account.Value, wallet2.Account.Value);
        //}

        //[Test]
        //public void CreateMnemonicEd25519Test()
        //{
        //    var mnemonic = "tornado glad segment lift squirrel top ball soldier joy sudden edit advice";
        //    var walletName = "mnem_wallet2";

        //    // create new wallet with password and persist
        //    Wallet.CreateFromMnemonic("aA1234dd", mnemonic, KeyType.Ed25519, Mnemonic.BIP39Wordlist.English, walletName, out Wallet wallet1);
        //    Assert.True(wallet1.IsStored);
        //    Assert.True(wallet1.IsUnlocked);
        //    Assert.AreEqual("5CcaF7yE6YU67TyPHjSwd9DKiVBTAS2AktdxNG3DeLYs63gF", wallet1.Account.Value);

        //    // read wallet
        //    Wallet.TryLoad(walletName, out Wallet wallet2);
        //    Assert.True(wallet2.IsStored);
        //    Assert.False(wallet2.IsUnlocked);
        //    wallet2.Unlock("aA1234dd");
        //    Assert.True(wallet2.IsUnlocked);
        //    Assert.AreEqual(wallet1.Account.Value, wallet2.Account.Value);
        //}

        //[Test]
        //public void SignatureVerify_Sr25519()
        //{
        //    var data = "Let's sign this message, now!";

        //    var aliceSignature = AliceSr25519.Sign(data);
        //    Assert.True(AliceSr25519.Verify(aliceSignature, data, true));
        //    Assert.True(AliceSr25519.Verify(aliceSignature, data, false));
        //}
    }
}