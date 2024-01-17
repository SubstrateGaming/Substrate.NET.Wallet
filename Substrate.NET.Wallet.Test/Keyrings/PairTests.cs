using NUnit.Framework;
using Schnorrkel.Keys;
using Substrate.NET.Wallet.Keyring;
using Substrate.NetApi;
using Substrate.NetApi.Model.Types;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Substrate.NET.Wallet.Test.Keyrings
{
    public class PairTests
    {
        public MiniSecret MiniSecretAlice => new MiniSecret(Utils.HexToByteArray("0xe5be9a5092b81bca64be81d212e7f2f9eba183bb7a90954f7b76361f6edb5c0a"), ExpandMode.Ed25519);
        public MiniSecret MiniSecretBob => new MiniSecret(Utils.HexToByteArray("0x398f0c28f98885e046333d4a41c19cee4c37368a9832c6502f6cfd182e2aef89"), ExpandMode.Ed25519);
        public Account AliceSr25519 => Account.Build(KeyType.Sr25519, MiniSecretAlice.ExpandToSecret().ToBytes(), MiniSecretBob.GetPair().Public.Key);
        public Account BobEd25519 => Account.Build(KeyType.Ed25519, MiniSecretBob.ExpandToSecret().ToBytes(), MiniSecretBob.GetPair().Public.Key);

        [Test]
        public void AllowDerivationOnAlice()
        {
            var alice = Pair.CreatePair(
                new KeyringAddress(NetApi.Model.Types.KeyType.Sr25519),
                new PairInfo(
                    Utils.HexToByteArray("0xd43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d"),
                    Utils.HexToByteArray("0x98319d4ff8a9508c4bb0cf0b5a78d760a0b2082c02775e6e82370816fedfff48925a225d97aa00682d6a59b95b18780c10d7032336e88f3442b42361f4a66011")
                    )
                );

            var stash = alice.Derive("//stash");
            var soft = alice.Derive("//funding/0");

            Assert.That(stash.Account.Bytes, Is.EquivalentTo(Utils.HexToByteArray("0xbe5ddb1579b72e84524fc29e78609e3caf42e85aa118ebfe0b0ad404b5bdd25f")));
            Assert.That(soft.Address, Is.EqualTo("5ECQNn7UueWHPFda5qUi4fTmTtyCnPvGnuoyVVSj5CboJh9J"));
        }
    }
}
