using NUnit.Framework;
using System;
using System.Linq;

namespace Substrate.NET.Wallet.Test
{
    public class WordManagerTests
    {
        private WordManager _wordManagerWithRequirement;

        private WordManager _wordManagerWithForbidden
            ;

        [SetUp]
        public void Setup()
        {
            _wordManagerWithRequirement = WordManager.Create()
            .WithMinimumLength(4)
            .WithMaximumLength(20)
            .Should().AtLeastOneUppercase()
            .Should().AtLeastOneLowercase()
            .Should().AtLeastOneDigit();

            _wordManagerWithForbidden = WordManager.Create()
                .ShouldNot().HaveLowercase()
                .ShouldNot().HaveDigit();
        }

        [Test]
        [TestCase("E7ird@M!jGc&")]
        public void WordManager_WithShould_WithValidInput_ShouldSuceed(string phrase)
        {
            Assert.That(_wordManagerWithRequirement.IsValid(phrase), Is.True);
        }

        [Test]
        [TestCase("ONLYUPPER")]
        public void WordManager_WithShouldNot_WithValidInput_ShouldSuceed(string phrase)
        {
            Assert.That(_wordManagerWithForbidden.IsValid(phrase), Is.True);
        }

        [Test]
        [TestCase("", 4)]
        [TestCase("o", 3)]
        [TestCase("ooo", 3)]
        [TestCase("$r4aDhFX&RzSbF3sHGGiRy", 1)]
        [TestCase("oOoOoOoO", 1)]
        [TestCase("o111111111111", 1)]
        [TestCase("O111111111111", 1)]
        public void WordManager_ShouldPattern_WithInvalidInput_ShouldFail(string word, int nbError)
        {
            Assert.That(_wordManagerWithRequirement.IsValid(word), Is.False);

            var errorCount = _wordManagerWithRequirement.GetErrors(word).Count();
            Assert.That(errorCount, Is.EqualTo(nbError));
        }

        [Test]
        [TestCase("Xx", 1)]
        [TestCase("Xx0", 2)]
        public void WordManager_ShouldNotPattern_WithInvalidInput_ShouldFail(string word, int nbError)
        {
            Assert.That(_wordManagerWithForbidden.IsValid(word), Is.False);

            var errorCount = _wordManagerWithForbidden.GetErrors(word).Count();
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