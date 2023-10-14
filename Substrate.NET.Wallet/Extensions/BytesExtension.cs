using Schnorrkel.Merlin;
using System;
using System.Linq;
using System.Security.Cryptography;

namespace Substrate.NET.Wallet.Extensions
{
    public static class BytesExtension
    {
        /// <summary>
        /// Load a byte array with random bytes
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public static byte[] Populate(this byte[] data)
        {
            var randomGenerator = RandomNumberGenerator.Create();
            randomGenerator.GetBytes(data);
            return data;
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
