using System;
using System.Linq;

namespace Substrate.NET.Wallet.Extensions
{
    public static class BytesExtension
    {
        /// <summary>
        /// Load a byte array with random bytes
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        public static byte[] Populate(this byte[] value)
        {
            new Random().NextBytes(value);
            return value;
        }

        public static byte[] BytesFixLength(this byte[] value, int bitLength = -1, bool atStart = false)
        {
            int byteLength = (int)Math.Ceiling((double)bitLength / 8);

            if (bitLength == -1 || value.Length == byteLength)
                return value;
            else if (value.Length > byteLength)
                return value.Take(byteLength).ToArray();

            byte[] result = new byte[byteLength];

            if (atStart)
                Array.Copy(value, 0, result, 0, value.Length);
            else
                Array.Copy(value, 0, result, byteLength - value.Length, value.Length);

            return result;
        }
    }
}
