using NUnit.Framework;
using System;
using System.IO;

namespace Substrate.NET.Wallet.Test
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
            Assert.That(Wallet.IsValidWalletName("1234"), Is.False);
            Assert.That(Wallet.IsValidWalletName("ABC_/"), Is.False);
            Assert.That(Wallet.IsValidWalletName("1111111"), Is.False);

            Assert.That(Wallet.IsValidWalletName("wal_let"), Is.True);
        }
    }
}