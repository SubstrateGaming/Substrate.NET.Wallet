using System;
using System.Collections.Generic;
using System.Text;

namespace Substrate.NET.Wallet.Extensions
{
    public static class StringExtension
    {
        public static byte[] ToBytes(this string value)
        {
            return Encoding.UTF8.GetBytes(value);
        }

        public static bool IsHex(this string value)
        {
            if (string.IsNullOrEmpty(value)) return false;

            return value.ToLower().StartsWith("0x");
        }
    }
}
