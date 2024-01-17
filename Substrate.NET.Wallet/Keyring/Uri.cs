using Chaos.NaCl;
using Schnorrkel;
using Schnorrkel.Keys;
using Schnorrkel.Ristretto;
using Schnorrkel.Scalars;
using Substrate.NET.Wallet.Derivation;
using Substrate.NET.Wallet.Extensions;
using Substrate.NetApi;
using Substrate.NetApi.Extensions;
using Substrate.NetApi.Model.Types;
using Substrate.NetApi.Model.Types.Primitive;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net.Sockets;
using System.Numerics;
using System.Reflection.Emit;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Substrate.NET.Wallet.Keyring
{
    public class KeyExtractResult
    {
        public string DerivePath { get; set; }
        public string Password { get; set; }
        public IList<DeriveJunction> Path { get; set; }
        public string Phrase { get; set; }
    }

    public class KeyExtractPathResult
    {
        public IList<string> Parts { get; set; }
        public IList<DeriveJunction> Path { get; set; }
    }

    public class DeriveJunction
    {
        public const int JUNCTION_ID_LEN = 32;
        public const string NUMBER_PATTERN = "^\\d+$";

        public bool IsHard { get; internal set; }
        public bool IsSoft => !IsHard;
        public byte[] ChainCode { get; internal set; }

        public static byte[] CompactAddLength(byte[] input)
        {
            var u256 = new U256(input.Length);
            var lenghtCompact = new CompactInteger(u256);
            var encode = lenghtCompact.Encode();
            
            var compacted = new List<byte>();
            compacted.AddRange(encode);
            compacted.AddRange(input);
            return compacted.ToArray();
        }

        public DeriveJunction Hard(string value)
        {
            return Soft(value).Harden();
        }

        public DeriveJunction Harden() {
            IsHard = true;
            return this;
        }

        public DeriveJunction Soft(byte[] value)
        {
            if(value.Length > JUNCTION_ID_LEN)
            {
                return Soft(HashExtension.Blake2(value, 256));
            }

            ChainCode = value.BytesFixLength(256, true);

            return this;
        }
        public DeriveJunction Soft(BigInteger value)
        {
            return Soft(value.ToByteArray());
        }

        public DeriveJunction Soft(string value)
        {
            if(value.IsHex())
                return Soft(Utils.HexToByteArray(value));

            return Soft(CompactAddLength(value.ToBytes()));
        }

        public DeriveJunction Soften()
        {
            IsHard = false;
            return this;
        }

        public static DeriveJunction From(string p)
        {
            var result = new DeriveJunction();

            (string code, bool isHard) = p.StartsWith("/") ? (p.Substring(1), true) : (p, false);

            var resultRegex = Regex.Match(code, NUMBER_PATTERN, RegexOptions.None, TimeSpan.FromMilliseconds(100));
            if(resultRegex.Success)
            {
                BigInteger bigInteger;
                if(BigInteger.TryParse(resultRegex.Value, out bigInteger))
                    result.Soft(bigInteger);
                else
                    throw new InvalidOperationException("Impossible to get big integer, while regex match number ?!");
            } else
            {
                result.Soft(code);
            }

            return isHard ? result.Harden() : result;
        }
    }

    public static class Uri
    {
        public const string DEV_PHRASE = "bottom drive obey lake curtain smoke basket hold race lonely fit walk";
        public const string DEV_SEED = "0xfac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e";

        public const string CaptureUriPattern = "^(\\w+( \\w+)*)((\\/\\/?[^\\/]+)*)(\\/\\/\\/(.*))?$";
        public const string CaptureJunctionPattern = "\\/(\\/?)([^/]+)";

        public static string GetUri(string mnemonic, string derivePath)
        {
            // We don't handle (yet...)  KeyType ed25519-ledger and Ethereum
            return $"{mnemonic}{derivePath}";
        }

        public static KeyExtractResult KeyExtractUri(string suri)
        {
            var match = Regex.Match(suri, CaptureUriPattern, RegexOptions.None, TimeSpan.FromMilliseconds(100));

            if (!match.Success)
                throw new InvalidOperationException("Unable to match provided value to a secret URI");

            var phrase = match.Groups[1].Value;
            var derivePath = match.Groups[3].Value;
            var password = match.Groups[6].Value;

            return new KeyExtractResult()
            {
                DerivePath = derivePath,
                Password = string.IsNullOrEmpty(password) ? null : password,
                Path = KeyExtractPath(derivePath).Path,
                Phrase = phrase
            };
        }

        public static KeyExtractPathResult KeyExtractPath(string derivePath)
        {
            var matches = Regex.Matches(derivePath, CaptureJunctionPattern, RegexOptions.None, TimeSpan.FromMilliseconds(100));
            var paths = new List<DeriveJunction>();

            var parts = new List<string>();
            string constructed = string.Empty;

            if (matches.Count > 0)
            {
                constructed = string.Join("", matches);

                foreach (Match match in matches)
                {
                    parts.Add(match.Value);
                    paths.Add(DeriveJunction.From(match.Value.Substring(1)));
                }
            }

            if (constructed != derivePath)
            {
                throw new InvalidOperationException($"Re-constructed path ${constructed} does not match input");
            }

            return new KeyExtractPathResult()
            {
                Parts = parts,
                Path = paths
            };
        }

        public static PairInfo KeyFromPath(PairInfo pair, IList<DeriveJunction> paths, KeyType keyType)
        {
            foreach(var path in paths)
            {
                pair = CreateDerive(keyType, path, pair);
            }
            return pair;
        }

        private static PairInfo CreateDerive(KeyType keyType, DeriveJunction path, PairInfo pair)
        {
            var pairBytes = pair.SecretKey.Concat(pair.PublicKey).ToArray();
            var keyPair = KeyPair.FromHalfEd25519Bytes(pairBytes);

            switch (keyType)
            {
                case KeyType.Sr25519:
                    var res = path.IsHard ?
                        Sr25519DeriveHard(keyPair, path.ChainCode) :
                        Sr25519DeriveSoft(keyPair, path.ChainCode);

                    return new PairInfo(
                        res.SubArray(Keys.SECRET_KEY_LENGTH, Keys.SECRET_KEY_LENGTH + Keys.PUBLIC_KEY_LENGTH), 
                        res.SubArray(0, Keys.SECRET_KEY_LENGTH));

                case KeyType.Ed25519:
                    if(path.IsHard)
                    {
                        return Keyring.KeyPairFromSeed(
                            KeyType.Ed25519, 
                            Ed25519DeriveHard(pair.SecretKey, path.ChainCode));
                    } else
                    {
                        throw new InvalidOperationException($"Soft derivation paths are not allowed on {KeyType.Ed25519}");
                    }
            }

            throw new NotImplementedException();
        }

        public static byte[] Sr25519DeriveHard(byte[] seed, byte[] chainCode)
            => Sr25519DeriveHard(KeyPair.FromHalfEd25519Bytes(seed), chainCode);

        public static byte[] Sr25519DeriveHard(KeyPair pair , byte[] chainCode)
        {
            if (chainCode.Length != 32)
                throw new InvalidOperationException("Invalid chainCode passed to derive");

            var (miniSecretderived, _) = pair.Secret.HardDerive(chainCode);

            return miniSecretderived.GetPair().ToHalfEd25519Bytes();
        }

        public static byte[] Sr25519DeriveSoft(byte[] seed, byte[] chainCode) 
            => Sr25519DeriveSoft(KeyPair.FromHalfEd25519Bytes(seed), chainCode);

        public static byte[] Sr25519DeriveSoft(KeyPair pair, byte[] chainCode)
        {
            if (chainCode.Length != 32)
                throw new InvalidOperationException("Invalid chainCode passed to derive");

            var (keyPairDerived, _) = pair.SoftDerive(chainCode);

            return keyPairDerived.ToHalfEd25519Bytes();
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="secretKey">64 bytes private key + nonce</param>
        /// <param name="chainCode"></param>
        /// <returns></returns>
        public static byte[] Ed25519DeriveHard(byte[] secretKey, byte[] chainCode)
        {
            var seed = secretKey.SubArray(0, 32);
            var HDKS = DeriveJunction.CompactAddLength(System.Text.Encoding.UTF8.GetBytes("Ed25519HDKD"));

            var all = HDKS.Concat(seed).Concat(chainCode).ToArray();
            var res = HashExtension.Hash(NetApi.Model.Meta.Storage.Hasher.BlakeTwo256, all);

            return res;
        }
    }
}
