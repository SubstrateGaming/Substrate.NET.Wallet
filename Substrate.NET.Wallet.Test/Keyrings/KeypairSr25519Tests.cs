using NUnit.Framework;
using Substrate.NET.Schnorrkel;
using Substrate.NET.Wallet.Derivation;
using Substrate.NET.Wallet.Extensions;
using Substrate.NET.Wallet.Keyring;
using Substrate.NetApi;
using Substrate.NetApi.Extensions;
using Substrate.NetApi.Model.Types;
using Substrate.NetApi.Sign;
using System.Collections.Generic;
using System.Linq;

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

        private Substrate.NET.Wallet.Keyring.Keyring keyring { get; set; }

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
        public void Sr25519_SignsAndVerifies()
        {
            string message = "this is a message";
            var wallet = keyring.Wallets.First();
            var signature = wallet.Sign(message);

            Assert.That(wallet.Verify(signature, message), Is.True);
            Assert.That(wallet.Verify(signature, new byte[32].Populate()), Is.False);
        }

        [Test]
        public void Sr25519_SignsAndVerifiesBothMethods()
        {
            string message = "this is a message";

            var (_, seed) = Keyring.Keyring.CreateSeedFromUri("//Alice");

            /*
             * Build an account with ExpandToSecret().ToBytes() => concatenate secret + nonce
             */
            var miniSecret_simple = new Schnorrkel.Keys.MiniSecret(seed, Schnorrkel.Keys.ExpandMode.Ed25519);
            var account_simple = Account.Build(KeyType.Sr25519, miniSecret_simple.ExpandToSecret().ToBytes(), miniSecret_simple.ExpandToPublic().Key);

            /*
             * Build an account with ExpandToSecret().ToHalfEd25519Bytes() => concatenate secret with MultiplyScalarBytesByCofactor + nonce
             */
            var miniSecret_Ed25519Bytes = new Schnorrkel.Keys.MiniSecret(seed, Schnorrkel.Keys.ExpandMode.Ed25519);
            var account_Ed25519Bytes = Account.Build(KeyType.Sr25519, miniSecret_Ed25519Bytes.ExpandToSecret().ToEd25519Bytes(), miniSecret_Ed25519Bytes.ExpandToPublic().Key);

            // Just to check
            // --
            var concatenated_2 = miniSecret_Ed25519Bytes.GetPair().ToHalfEd25519Bytes();
            var publicKey_2 = concatenated_2.SubArray(Keys.SECRET_KEY_LENGTH, Keys.SECRET_KEY_LENGTH + Keys.PUBLIC_KEY_LENGTH);
            var secretKey_2 = concatenated_2.SubArray(0, Keys.SECRET_KEY_LENGTH);
            var edBytes = miniSecret_Ed25519Bytes.ExpandToSecret().ToEd25519Bytes();
            Assert.That(edBytes, Is.EquivalentTo(secretKey_2));
            Assert.That(edBytes, Is.EquivalentTo(account_Ed25519Bytes.PrivateKey));

            Assert.That(publicKey_2, Is.EquivalentTo(miniSecret_Ed25519Bytes.ExpandToPublic().Key));
            // --

            // Sign with SignSimple (use SecretKey.FromBytes085 which mean that take the first 32 bytes for secret + the last 32 bytes for nonce)
            var signature_simple_1 = Sr25519v091.SignSimple(account_simple.Bytes, account_simple.PrivateKey, message.ToBytes());

            // Sign with SignSimple (use SecretKey.FromEd25519Bytes which mean that take the first 32 bytes for secret with DivideScalarBytesByCofactor + the last 32 bytes for nonce)
            var signature_Ed25519 = Sr25519v091.SignSimpleFromEd25519(account_Ed25519Bytes.Bytes, account_Ed25519Bytes.PrivateKey, message.ToBytes());

            // Now we do the opposite, get the KeyPair from the private key
            var keyPair_3 = Schnorrkel.Keys.KeyPair.FromHalfEd25519Bytes(account_Ed25519Bytes.PrivateKey.Concat(account_Ed25519Bytes.Bytes).ToArray());
            var signature_simple_2 = Sr25519v091.SignSimple(keyPair_3.Public.Key, keyPair_3.Secret.ToBytes(), message.ToBytes());

            // All PublicKey should be equals
            Assert.That(account_simple.Bytes, Is.EquivalentTo(account_Ed25519Bytes.Bytes));
            Assert.That(account_simple.Bytes, Is.EquivalentTo(keyPair_3.Public.Key));

            // Private key for account_Ed25519Bytes should be different of account_simple and keyPair_3
            Assert.That(account_simple.PrivateKey, Is.Not.EquivalentTo(account_Ed25519Bytes.PrivateKey));
            Assert.That(account_simple.PrivateKey, Is.EquivalentTo(keyPair_3.Secret.ToBytes()));

            // Signature should be different because signature has randomness
            Assert.That(signature_simple_1, Is.Not.EquivalentTo(signature_Ed25519));
            Assert.That(signature_simple_1, Is.Not.EquivalentTo(signature_simple_2));

            /*
             * But all signatures should be verified, no matter the account
             * If we sign with SignSimple we could be able to verify with Verify
             * If we sign with SignSimpleEd25519 we could be able to verify with VerifyEd25519
             *
             * I do it multiple time to ensure the signature is not modify by the verify function
             */
            Assert.That(Sr25519v091.Verify(signature_simple_1, account_simple.Bytes, message.ToBytes()), Is.True);
            Assert.That(Sr25519v091.Verify(signature_simple_1, account_simple.Bytes, message.ToBytes()), Is.True);

            Assert.That(Sr25519v091.Verify(signature_Ed25519, account_Ed25519Bytes.Bytes, message.ToBytes()), Is.True);
            Assert.That(Sr25519v091.Verify(signature_Ed25519, account_Ed25519Bytes.Bytes, message.ToBytes()), Is.True);

            Assert.That(Sr25519v091.Verify(signature_simple_2, keyPair_3.Public.Key, message.ToBytes()), Is.True);
            Assert.That(Sr25519v091.Verify(signature_simple_2, keyPair_3.Public.Key, message.ToBytes()), Is.True);
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

        [Test]
        public void SignWithAlice_ShouldSucceed()
        {
            var keyring = new Keyring.Keyring();
            var aliceWallet = keyring.AddFromUri("//Alice", new Meta(), KeyType.Sr25519);

            var message = "pwet".ToBytes();
            message = WrapMessage.Wrap(message);

            var sign = aliceWallet.Sign(message);
            Assert.IsTrue(aliceWallet.Verify(sign, message));

            var polkadotJsSignature = Utils.HexToByteArray("0xd8b5894fc138ded2c7311602da5dc86521b280d5489f2f64421e222c6034727a9dc49759b6d3061405e3221b411b521397a818caddbdbc80fba4bebdc88a108d");

            Assert.IsTrue(Schnorrkel.Sr25519v091.Verify(polkadotJsSignature, aliceWallet.Account.Bytes, message));
            Assert.IsTrue(aliceWallet.Verify(polkadotJsSignature, message));
        }
    }
}