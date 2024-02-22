using Substrate.NetApi.Extensions;
using System;
using System.Linq;
using System.Numerics;

namespace Substrate.NET.Wallet.Keyring
{
    /// <summary>
    /// Scrypt
    /// https://github.com/viniciuschiele/Scrypt/tree/master
    /// </summary>
    public static class Scrypt
    {
        /// <summary>
        /// https://github.com/polkadot-js/common/blob/master/packages/util-crypto/src/scrypt/fromU8a.ts
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        /// <exception cref="InvalidOperationException"></exception>
        public static ScryptResult FromBytes(byte[] data)
        {
            var dataSpan = new Span<byte>(data);

            // Extract salt directly using Span.Slice and convert to array
            var salt = dataSpan.Slice(0, 32).ToArray();

            // Convert slices for N, p, r directly to BigInteger using ReadOnlySpan
            var N = new BigInteger(dataSpan.Slice(32 + 0, 4).ToArray());
            var p = new BigInteger(dataSpan.Slice(32 + 4, 4).ToArray());
            var r = new BigInteger(dataSpan.Slice(32 + 8, 4).ToArray());

            if (N != ScryptParam.Default.IterationCount || p != ScryptParam.Default.ThreadCount || r != ScryptParam.Default.BlockSize)
            {
                throw new InvalidOperationException("Invalid Scrypt params");
            }

            return new ScryptResult(new ScryptParam(N, p, r), salt);
        }

        /// <summary>
        ///
        /// </summary>
        /// <param name="salt"></param>
        /// <param name="param"></param>
        /// <returns></returns>
        public static byte[] ToBytes(byte[] salt, ScryptParam param)
        {
            return salt
                .Concat(param.ToBytes())
                .ToArray();
        }

        /// <summary>
        /// Create a new scrypt encoding with random salt
        /// </summary>
        /// <param name="password"></param>
        /// <param name="param"></param>
        /// <returns></returns>
        public static ScryptResult ScryptEncode(string password, ScryptParam param)
        {
            var randomBytes = new byte[32].Populate();
            return ScryptEncode(password, randomBytes, param);
        }

        /// <summary>
        /// Encode our password with Scrypt algorithm
        /// </summary>
        /// <param name="password"></param>
        /// <param name="salt"></param>
        /// <param name="param"></param>
        /// <returns></returns>
        public static ScryptResult ScryptEncode(string password, byte[] salt, ScryptParam param)
        {
            byte[] passwordBytes = password.ToBytes();

            passwordBytes = CryptSharp.Utility.SCrypt.ComputeDerivedKey(passwordBytes, salt, (int)param.IterationCount, (int)param.BlockSize, (int)param.ThreadCount, null, 64);

            return new ScryptResult(param, salt, passwordBytes);
        }
    }

    /// <summary>
    /// Scrypt result
    /// </summary>
    public class ScryptResult
    {
        /// <summary>
        /// Scrypt result constructor
        /// </summary>
        /// <param name="param"></param>
        /// <param name="salt"></param>
        public ScryptResult(ScryptParam param, byte[] salt)
        {
            Param = param;
            Salt = salt;
        }

        /// <summary>
        /// Scrypt result constructor
        /// </summary>
        /// <param name="param"></param>
        /// <param name="salt"></param>
        /// <param name="password"></param>
        public ScryptResult(ScryptParam param, byte[] salt, byte[] password) : this(param, salt)
        {
            Password = password;
        }

        /// <summary>
        /// Scrypt param
        /// </summary>
        public ScryptParam Param { get; }

        /// <summary>
        /// Salt
        /// </summary>
        public byte[] Salt { get; }

        /// <summary>
        /// Password
        /// </summary>
        public byte[] Password { get; }
    }

    /// <summary>
    /// Scrypt param
    /// </summary>
    public class ScryptParam
    {
        /// <summary>
        /// N
        /// </summary>
        public BigInteger IterationCount { get; }

        /// <summary>
        /// r
        /// </summary>
        public BigInteger ThreadCount { get; }

        /// <summary>
        /// p
        /// </summary>
        public BigInteger BlockSize { get; }

        /// <summary>
        /// Scrypt param constructor
        /// </summary>
        /// <param name="iterationCount"></param>
        /// <param name="threadCount"></param>
        /// <param name="blockSize"></param>
        public ScryptParam(BigInteger iterationCount, BigInteger threadCount, BigInteger blockSize)
        {
            IterationCount = iterationCount;
            ThreadCount = threadCount;
            BlockSize = blockSize;
        }

        /// <summary>
        /// https://github.com/polkadot-js/common/blob/master/packages/util-crypto/src/scrypt/defaults.ts#L6
        /// </summary>
        public static ScryptParam Default { get; set; } = new ScryptParam(1 << 15, 1, 8);

        /// <summary>
        /// To bytes
        /// </summary>
        /// <returns></returns>
        public byte[] ToBytes() => new byte[] { 0, 128, 0, 0, 1, 0, 0, 0, 8, 0, 0, 0 };
    }
}