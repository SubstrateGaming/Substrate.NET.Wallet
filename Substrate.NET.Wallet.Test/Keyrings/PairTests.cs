using NUnit.Framework;
using Substrate.NET.Wallet.Keyring;
using Substrate.NetApi;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Substrate.NET.Wallet.Test.Keyrings
{
    public class PairTests
    {
        private readonly KeyringPair alicePairEd25519 = new KeyringPair(
            "5GoKvZWG5ZPYL1WUovuHW3zJBWBP5eT8CbqjdRY4Q6iMaQua",
            new byte[] { 209, 114, 167, 76, 218, 76, 134, 89, 18, 195, 43, 160, 168, 10, 87, 174, 105, 171, 174, 65, 14, 92, 203, 89, 222, 232, 78, 47, 68, 50, 219, 79 },
            null,
            null,
            new PairInfo(
                new byte[] { 209, 114, 167, 76, 218, 76, 134, 89, 18, 195, 43, 160, 168, 10, 87, 174, 105, 171, 174, 65, 14, 92, 203, 89, 222, 232, 78, 47, 68, 50, 219, 79 },
                null
            ),
            NetApi.Model.Types.KeyType.Ed25519,
            null
        );

        [Test]
        public void GetPublickKeyAfterDecoding()
        {
            var password = "TESTING";
            var encoded = alicePairEd25519.EncodePkcs8(password);

            var pair = Pair.CreatePair(KeyringAddress.Standard(NetApi.Model.Types.KeyType.Ed25519), new PairInfo(alicePairEd25519.PairInformation.PublicKey));

            pair.Unlock(password, encoded);

            Assert.That(pair.IsLocked, Is.False);
        }

        [Test]
        public void AllowDerivationOnAlice()
        {
            var alice = Pair.CreatePair(
                KeyringAddress.Standard(NetApi.Model.Types.KeyType.Sr25519),
                new PairInfo(
                    Utils.HexToByteArray("0xd43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d"),
                    Utils.HexToByteArray("0x98319d4ff8a9508c4bb0cf0b5a78d760a0b2082c02775e6e82370816fedfff48925a225d97aa00682d6a59b95b18780c10d7032336e88f3442b42361f4a66011")
                    )
                );

            var stash = alice.Derive("//stash");
            var soft = alice.Derive("//funding/0");

            Assert.That(stash.PairInformation.PublicKey, Is.EquivalentTo(Utils.HexToByteArray("0xbe5ddb1579b72e84524fc29e78609e3caf42e85aa118ebfe0b0ad404b5bdd25f")));
            Assert.That(soft.Address, Is.EqualTo("5ECQNn7UueWHPFda5qUi4fTmTtyCnPvGnuoyVVSj5CboJh9J"));
        }
    }
}
