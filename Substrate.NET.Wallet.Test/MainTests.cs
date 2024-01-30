using Substrate.NET.Schnorrkel.Keys;
using Substrate.NET.Wallet.Keyring;
using Substrate.NetApi;
using Substrate.NetApi.Model.Types;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Substrate.NET.Wallet.Test
{
    public class MainTests
    {
        protected Dictionary<string, PairDefTest> pairDefs;

        protected MainTests()
        {
            pairDefs = new Dictionary<string, PairDefTest>() {
                { "Alice", new PairDefTest()
                    {
                        PublickKey = "0xd43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d",
                        SecretKey = "0x98319d4ff8a9508c4bb0cf0b5a78d760a0b2082c02775e6e82370816fedfff48925a225d97aa00682d6a59b95b18780c10d7032336e88f3442b42361f4a66011",
                        Seed = "Alice",
                        KeyType = KeyType.Sr25519
                    }
                },
                { "Alice stash", new PairDefTest()
                    {
                        PublickKey = "0xbe5ddb1579b72e84524fc29e78609e3caf42e85aa118ebfe0b0ad404b5bdd25f",
                        SecretKey = "0xe8da6c9d810e020f5e3c7f5af2dea314cbeaa0d72bc6421e92c0808a0c584a6046ab28e97c3ffc77fe12b5a4d37e8cd4afbfebbf2391ffc7cb07c0f38c023efd",
                        Seed = "Alice//stash",
                        KeyType = KeyType.Sr25519
                    }
                },
                { "Bob", new PairDefTest()
                    {
                        PublickKey = "0x8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48",
                        SecretKey = "0x081ff694633e255136bdb456c20a5fc8fed21f8b964c11bb17ff534ce80ebd5941ae88f85d0c1bfc37be41c904e1dfc01de8c8067b0d6d5df25dd1ac0894a325",
                        Seed = "Bob",
                        KeyType = KeyType.Sr25519
                    }   
                },
                { "Bob stash", new PairDefTest()
                    {
                        PublickKey = "0xfe65717dad0447d715f660a0a58411de509b42e6efb8375f562f58a554d5860e",
                        SecretKey = "0xc006507cdfc267a21532394c49ca9b754ca71de21e15a1cdf807c7ceab6d0b6c3ed408d9d35311540dcd54931933e67cf1ea10d46f75408f82b789d9bd212fde",
                        Seed = "Bob//stash",
                        KeyType = KeyType.Sr25519
                    }
                }
            };
        }

        protected Meta defaultMeta = new Meta()
        {
            genesisHash = "0x91b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3",
            isHardware = false,
            name = "SubstrateAccount2",
            tags = null
        };

        public class PairDefTest
        {
            public string PublickKey { get; set; }
            public string SecretKey { get; set; }
            public string Seed { get; set; }
            public KeyType KeyType { get; set; }

            public Wallet GetWallet()
            {
                return Pair.CreatePair(
                new KeyringAddress(KeyType.Sr25519),
                new PairInfo(
                    Utils.HexToByteArray(PublickKey),
                    Utils.HexToByteArray(SecretKey)
                    )
                );
            }
        }
    }
}
