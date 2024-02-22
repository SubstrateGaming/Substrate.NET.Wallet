using Substrate.NetApi;
using Substrate.NetApi.Extensions;
using Substrate.NetApi.Model.Types.Primitive;
using System;
using System.Collections.Generic;
using System.Numerics;
using System.Text.RegularExpressions;

namespace Substrate.NET.Wallet.Derivation
{
    /// <summary>
    /// Analyse a derivation phrase and categorize it as soft and hard derivation
    /// </summary>
    public class DeriveJunction
    {
        /// <summary>
        /// Junction id lenght
        /// </summary>
        public const int JUNCTION_ID_LEN = 32;

        /// <summary>
        /// Regex number pattern
        /// </summary>
        public const string NUMBER_PATTERN = "^\\d+$";

        /// <summary>
        /// Return true if it is a hard derivation (starts with //)
        /// </summary>
        public bool IsHard { get; internal set; }

        /// <summary>
        /// Return true if it is a soft derivation (starts with //)
        /// </summary>
        public bool IsSoft => !IsHard;

        /// <summary>
        /// Represents the chain code associated with the junction
        /// </summary>
        public byte[] ChainCode { get; internal set; }

        /// <summary>
        /// Add lenght as first byte
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        internal static byte[] CompactAddLength(byte[] input)
        {
            var u256 = new U256(input.Length);
            var lenghtCompact = new CompactInteger(u256);
            var encode = lenghtCompact.Encode();

            var compacted = new List<byte>();
            compacted.AddRange(encode);
            compacted.AddRange(input);
            return compacted.ToArray();
        }

        /// <summary>
        /// Harden the given string
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        public DeriveJunction Hard(string value)
        {
            return Soft(value).Harden();
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        public DeriveJunction Harden()
        {
            IsHard = true;
            return this;
        }

        /// <summary>
        /// Soft the given byte array
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        public DeriveJunction Soft(byte[] value)
        {
            if (value.Length > JUNCTION_ID_LEN)
            {
                return Soft(HashExtension.Blake2(value, 256));
            }

            ChainCode = value.BytesFixLength(256, true);

            return this;
        }

        /// <summary>
        /// Soft the given number
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        public DeriveJunction Soft(BigInteger value)
        {
            return Soft(value.ToByteArray());
        }

        /// <summary>
        /// Soft the given string
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        public DeriveJunction Soft(string value)
        {
            if (value.IsHex())
                return Soft(Utils.HexToByteArray(value));

            return Soft(CompactAddLength(value.ToBytes()));
        }

        /// <summary>
        /// Return a soft representation
        /// </summary>
        /// <returns></returns>
        public DeriveJunction Soften()
        {
            IsHard = false;
            return this;
        }

        /// <summary>
        /// Create a <see cref="DeriveJunction"/> instance from a derivation string
        /// </summary>
        /// <param name="p"></param>
        /// <returns></returns>
        /// <exception cref="InvalidOperationException"></exception>
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