using Schnorrkel.Keys;
using Substrate.NET.Wallet.Extensions;
using Substrate.NetApi.Model.Types;
using System;
using System.Collections.Generic;
using static Substrate.NetApi.Mnemonic;

namespace Substrate.NET.Wallet.Keyring
{
    public static class MnemonicExtensions
    {
        public static string[] ToMnemonicArray(string mnemonic) => mnemonic.Split(' ');
        public static string ToMnemonicString(string[] mnemonic) => string.Join(" ", mnemonic);

        public static string GetUri(string mnemonic, string derivePath, KeyType _keyType)
        {
            // We don't handle (yet...)  KeyType ed25519-ledger and Ethereum
            return $"{mnemonic}{derivePath}";
        }

        public static byte[] MnemonicToMiniSecret(string mnemonic, string password, BIP39Wordlist bIP39Wordlist = BIP39Wordlist.English)
        {
            if(!ValidateMnemonic(mnemonic, bIP39Wordlist))
            {
                throw new InvalidOperationException("Invalid bip39 mnemonic specified");
            }

            return GetSecretKeyFromMnemonic(mnemonic, password, bIP39Wordlist);
        }

        public static bool ValidateMnemonic(string mnemonic, BIP39Wordlist bIP39Wordlist = BIP39Wordlist.English)
        {
            try
            {
                _ = MnemonicToEntropy(mnemonic, bIP39Wordlist);
                return true;
            } catch (Exception)
            {
                return false;
            }
        }

        public static PairInfo KeyFromPath(PairInfo pair, IEnumerable<DeriveJunction> path, KeyType keyType)
        {
            return pair;
        }
    }
}
