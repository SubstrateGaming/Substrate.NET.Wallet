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

        /// <summary>
        /// Based on SubKey (https://docs.substrate.io/reference/command-line-tools/subkey/)
        /// </summary>
        [Test]
        [TestCase("//Alice", "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY", "0xd43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d", "0xe5be9a5092b81bca64be81d212e7f2f9eba183bb7a90954f7b76361f6edb5c0a")]
        [TestCase("//Alice//stash", "5GNJqTPyNqANBkUVMN1LPPrxXnFouWXoe2wNSmmEoLctxiZY", "0xbe5ddb1579b72e84524fc29e78609e3caf42e85aa118ebfe0b0ad404b5bdd25f", "0x3c881bc4d45926680c64a7f9315eeda3dd287f8d598f3653d7c107799c5422b3")]
        [TestCase("//Bob", "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty", "0x8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48", "0x398f0c28f98885e046333d4a41c19cee4c37368a9832c6502f6cfd182e2aef89")]
        [TestCase("//Bob//stash", "5HpG9w8EBLe5XCrbczpwq5TSXvedjrBGCwqxK1iQ7qUsSWFc", "0xfe65717dad0447d715f660a0a58411de509b42e6efb8375f562f58a554d5860e", "0x1a7d114100653850c65edecda8a9b2b4dd65d900edef8e70b1a6ecdcda967056")]
        [TestCase("//Charlie", "5FLSigC9HGRKVhB9FiEo4Y3koPsNmBmLJbpXg2mp1hXcS59Y", "0x90b5ab205c6974c9ea841be688864633dc9ca8a357843eeacf2314649965fe22", "0xbc1ede780f784bb6991a585e4f6e61522c14e1cae6ad0895fb57b9a205a8f938")]
        [TestCase("//Dave", "5DAAnrj7VHTznn2AWBemMuyBwZWs6FNFjdyVXUeYum3PTXFy", "0x306721211d5404bd9da88e0204360a1a9ab8b87c66c1bc2fcdd37f3c2222cc20", "0x868020ae0687dda7d57565093a69090211449845a7e11453612800b663307246")]
        [TestCase("//Ferdie", "5CiPPseXPECbkjWCa6MnjNokrgYjMqmKndv2rSnekmSK2DjL", "0x1cbd2d43530a44705ad088af313e18f80b53ef16b36177cd4b77b846f2a5f07c", "0x42438b7883391c05512a938e36c2df0131e088b3756d6aa7a755fbff19d2f842")]
        [TestCase("//Eve", "5HGjWAeFDfFCWPsjFQdVV2Msvz2XtMktvgocEZcCj68kUMaw", "0xe659a7a1628cdd93febc04a4e0646ea20e9f5f0ce097d9a05290d4a9e054df4e", "0x786ad0e2df456fe43dd1f91ebca22e235bc162e0bb8d53c633e8c85b2af68b7a")]
        public void SubKeysScenario_ShouldSuceed(string uri, string expectedAddress, string expectedPublicKey, string expectedSeed)
        {
            var keyring = new Keyring.Keyring();
            var res = keyring.AddFromUri(uri, defaultMeta, KeyType.Sr25519);

            Assert.That(res.Account.Bytes, Is.EquivalentTo(Utils.HexToByteArray(expectedPublicKey)));
            Assert.That(res.Address, Is.EqualTo(expectedAddress));
        }
    }
}