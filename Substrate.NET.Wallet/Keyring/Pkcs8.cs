using Substrate.NetApi.Model.Types;
using System;
using System.Collections.Generic;

namespace Substrate.NET.Wallet.Keyring
{
    /// <summary>
    /// PKCS8
    /// </summary>
    public static class Pkcs8
    {
        /// <summary>
        /// Decode
        /// </summary>
        /// <param name="password"></param>
        /// <param name="encoded"></param>
        /// <param name="encryptedEncoding"></param>
        /// <returns></returns>
        public static Account Decode(string password, byte[] encoded, List<WalletJson.EncryptedJsonEncoding> encryptedEncoding)
        {
            return Pair.DecodePair(password, encoded, encryptedEncoding);
        }

        /// <summary>
        /// https://github.com/polkadot-js/common/blob/master/packages/keyring/src/pair/index.ts#L104
        /// </summary>
        /// <param name="password"></param>
        /// <param name="encoded"></param>
        /// <param name="encryptionType"></param>
        /// <returns></returns>
        /// <exception cref="InvalidOperationException"></exception>
        public static byte[] Encode(string password, byte[] encoded, List<WalletJson.EncryptedJsonEncoding> encryptionType)
        {
            var pkcs8Pair = Decode(password, encoded, encryptionType);
            return Pair.EncodePair(password, pkcs8Pair);
        }
    }
}