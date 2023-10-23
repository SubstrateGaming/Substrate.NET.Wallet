using Schnorrkel.Keys;
using Substrate.NetApi;
using Substrate.NetApi.Extensions;
using Substrate.NetApi.Model.Types;
using Substrate.NetApi.Model.Types.Primitive;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Numerics;
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

        private static BigInteger MAX_U8 = new BigInteger(0xFF);
        private static BigInteger MAX_U16 = new BigInteger(0xFFFF);
        private static BigInteger MAX_U32 = new BigInteger(0xFFFFFFFF);
        private static BigInteger BN_ONE = new BigInteger(1);
        private static BigInteger BN_TWO = new BigInteger(2);

        public bool IsHard { get; internal set; }
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

            //if (parts.Success)
            //{
            //    constructed = parts.Value;
            //    foreach (var p in parts.Groups)
            //    {
            //        //paths.Add(DeriveJunction.From(p));
            //    }
            //}
            //throw new NotImplementedException();

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

        public static PairInfo KeyFromPath(PairInfo pair, IList<DeriveJunction> path, KeyType keyType)
        {
            // TODO : handle DeriveJunction
            return pair;
        }
    }
}
