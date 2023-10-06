using NUnit.Framework;
using Substrate.NetApi;
using System;
using System.IO;

namespace Substrate.NET.Wallet.Test
{
    public class EncodingTest
    {
        private Random _random;

        [SetUp]
        public void Setup()
        {
            SystemInteraction.ReadData = f => File.ReadAllText(Path.Combine(Environment.CurrentDirectory, f));
            SystemInteraction.DataExists = f => File.Exists(Path.Combine(Environment.CurrentDirectory, f));
            SystemInteraction.ReadPersistent = f => File.ReadAllText(Path.Combine(Environment.CurrentDirectory, f));
            SystemInteraction.PersistentExists = f => File.Exists(Path.Combine(Environment.CurrentDirectory, f));
            SystemInteraction.Persist = (f, c) => File.WriteAllText(Path.Combine(Environment.CurrentDirectory, f), c);

            _random = new Random();
        }

        [Test]
        public void EncryptionTest()
        {
            var origData = new byte[_random.Next(10, 500)];
            _random.NextBytes(origData);

            var salt = new byte[32];
            _random.NextBytes(salt);

            var encryptedData = Wallet.Encrypt(origData, "aA1234dd", salt);
            var reprData = Wallet.Decrypt(encryptedData, "aA1234dd", salt);

            Assert.AreEqual(origData, reprData);
        }

        [Test]
        public void EncryptionSaltTest()
        {
            var address = "5CcaF7yE6YU67TyPHjSwd9DKiVBTAS2AktdxNG3DeLYs63gF";

            var seed = new byte[16];
            _random.NextBytes(seed);

            var hash = new byte[16];
            _random.NextBytes(hash);

            var salt = Wallet.GetSalt(Utils.GetPublicKeyFrom(address), hash);

            var encodedData = Wallet.Encrypt(seed, "aA1234dd", salt);
            var reprData = Wallet.Decrypt(encodedData, "aA1234dd", salt);

            Assert.AreEqual(seed, reprData);
        }
    }
}