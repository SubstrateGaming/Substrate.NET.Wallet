using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Substrate.NET.Wallet.Test
{
    public class WordManagerTests
    {
        private WordManager _wordManager;

        [SetUp]
        public void Setup()
        {
            _wordManager = WordManager.Create()
            .WithMinimumLength(4)
            .WithMaximumLength(20)
            .WithAtLeastOneUppercase()
            .WithAtLeastOneLowercase()
            .WithAtLeastOneDigit();
        }

        [Test]
        [TestCase("E7ird@M!jGc&")]
        public void WordManager_WithValidPassword_ShouldSuceed(string phrase)
        {
            Assert.IsTrue(_wordManager.IsValid(phrase));
        }

        [Test]
        [TestCase("", 4)]
        [TestCase("o", 3)]
        [TestCase("ooo", 3)]
        [TestCase("$r4aDhFX&RzSbF3sHGGiRy", 1)]
        [TestCase("oOoOoOoO", 1)]
        [TestCase("o111111111111", 1)]
        [TestCase("O111111111111", 1)]
        public void WordManager_WithInvalidPassword_ShouldFail(string word, int nbError)
        {
            Assert.IsFalse(_wordManager.IsValid(word));

            var errorCount = _wordManager.GetErrors(word).Count();
            Assert.That(errorCount, Is.EqualTo(nbError));
        }

        [Test]
        public void WordManager_WithInvalidSettings_ShouldFail()
        {
            Assert.Throws<ArgumentException>(() => 
            WordManager.Create().WithMinimumLength(10).WithMaximumLength(8));

            Assert.Throws<ArgumentException>(() =>
            WordManager.Create().WithMaximumLength(8).WithMinimumLength(10));
        }
    }
}
