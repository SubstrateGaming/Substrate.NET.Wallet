using Substrate.NetApi.Extensions;
using Substrate.NetApi.Model.Types.Primitive;
using Substrate.NetApi;
using System;
using System.Collections.Generic;
using System.Numerics;
using System.Text;
using System.Text.RegularExpressions;

namespace Substrate.NET.Wallet.Derivation
{
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

        public DeriveJunction Harden()
        {
            IsHard = true;
            return this;
        }

        public DeriveJunction Soft(byte[] value)
        {
            if (value.Length > JUNCTION_ID_LEN)
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
            if (value.IsHex())
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
            if (resultRegex.Success)
            {
                BigInteger bigInteger;
                if (BigInteger.TryParse(resultRegex.Value, out bigInteger))
                    result.Soft(bigInteger);
                else
                    throw new InvalidOperationException("Impossible to get big integer, while regex match number ?!");
            }
            else
            {
                result.Soft(code);
            }

            return isHard ? result.Harden() : result;
        }
    }
}
