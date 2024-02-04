using NUnit.Framework;
using Substrate.NetApi;
using Substrate.NetApi.Model.Types;

namespace Substrate.NET.Wallet.Test.Keyrings
{
    public class DerivationTests : MainTests
    {
        [Test]
        public void AllowDerivationOnAlice()
        {
            var alice = pairDefs["Alice"].GetWallet();

            var stash = alice.Derive("//stash");
            var soft = alice.Derive("//funding/0");

            Assert.That(stash.Account.Bytes, Is.EquivalentTo(Utils.HexToByteArray(pairDefs["Alice stash"].PublickKey)));
            Assert.That(soft.Address, Is.EqualTo("5ECQNn7UueWHPFda5qUi4fTmTtyCnPvGnuoyVVSj5CboJh9J"));
        }

        [Test]
        public void AllowDerivationOnBob()
        {
            var bob = pairDefs["Bob"].GetWallet();

            var stash = bob.Derive("//stash");

            Assert.That(stash.Account.Bytes, Is.EquivalentTo(Utils.HexToByteArray(pairDefs["Bob stash"].PublickKey)));
        }

        [Test]
        [TestCase(42, "//9007199254740991", "5CDsyNZyqxLpHnTvknr68anUcYoBFjZbFKiEJJf4prB75Uog")]
        [TestCase(42, "//Alice", "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY")]
        [TestCase(42, "//900719925474099999", "5GHj2D7RG2m2DXYwGSDpXwuuxn53G987i7p2EQVDqP4NYu4q")]
        [TestCase(252, "//Alice", "xw8P6urbSAronL3zZFB7dg8p7LLSgKCUFDUgjohnf1iP434ic")]
        public void CreateWithParams(short ss58, string derivation, string address)
        {
            var keyring = new Keyring.Keyring();
            keyring.Ss58Format = ss58;

            var res = keyring.AddFromUri(derivation, defaultMeta, KeyType.Sr25519);

            Assert.That(res.Address, Is.EqualTo(address));
        }
    }
}