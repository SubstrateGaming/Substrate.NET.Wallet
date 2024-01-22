using Chaos.NaCl;
using Substrate.NET.Wallet.Extensions;
using Substrate.NetApi.Extensions;
using Substrate.NetApi.Model.Types;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Substrate.NET.Wallet.Keyring
{
    public class DecodeResult : PairInfo
    {
        public DecodeResult(byte[] publicKey, byte[] privateKey, byte[] seed, byte[] secretKey) : base(publicKey, secretKey)
        {
            PrivateKey = privateKey;
            Seed = seed;
        }

        public byte[] PrivateKey { get; }
        public byte[] Seed { get; }
    }

    public class PairInfo
    {
        public PairInfo(byte[] publicKey) : this(publicKey, null)
        {

        }

        public PairInfo(byte[] publicKey, byte[] secretKey)
        {
            PublicKey = publicKey;
            SecretKey = secretKey;
        }

        public byte[] PublicKey { get; set; }
        public byte[] SecretKey { get; set; }

        public byte[] ToBytes()
        {
            return SecretKey.Concat(PublicKey).ToArray();
        }
    }

    public static class Pair
    {
        public const int PUB_LENGTH = 32;
        public const int SALT_LENGTH = 32;
        public const int SEC_LENGTH = 64;
        public const int SEED_LENGTH = 32;
        public static int SEED_OFFSET => PKCS8_HEADER.Length;

        public static readonly byte[] PKCS8_HEADER = new byte[] { 48, 83, 2, 1, 1, 48, 5, 6, 3, 43, 101, 112, 4, 34, 4, 32 };
        public static readonly byte[] PKCS8_DIVIDER = new byte[] { 161, 35, 3, 33, 0 };

        public const int ENCODING_VERSION = 3;
        public static readonly string[] ENCODING_NONE = { WalletJson.EncryptedToString(WalletJson.EncryptedJsonEncoding.None) };
        public static readonly string[] ENCODING = {
            WalletJson.EncryptedToString(WalletJson.EncryptedJsonEncoding.Scrypt),
            WalletJson.EncryptedToString(WalletJson.EncryptedJsonEncoding.Xsalsa20Poly1305),
        };

        public static Wallet CreatePair(KeyringAddress setup, PairInfo pair)
            => CreatePair(setup, pair, meta: null, encoded: null, encryptedEncoding: null, ss58Format: 42);

        /// <summary>
        /// https://github.com/polkadot-js/common/blob/master/packages/keyring/src/pair/index.ts#L89
        /// </summary>
        /// <param name="setup"></param>
        /// <param name="publicKey"></param>
        /// <param name="secretKey"></param>
        /// <param name="meta"></param>
        /// <param name="decoded"></param>
        /// <param name="encryptedEncoding"></param>
        /// <returns></returns>
        public static Wallet CreatePair(KeyringAddress setup, PairInfo pair, Meta meta, byte[] encoded, List<WalletJson.EncryptedJsonEncoding> encryptedEncoding, short ss58Format)
        {
            return new Wallet(setup.ToSS58(pair.PublicKey, ss58Format), encoded, meta, pair.PublicKey, pair.SecretKey, setup.KeyType, encryptedEncoding);
        }

        public static PairInfo DecodePair(string password, byte[] encoded, List<WalletJson.EncryptedJsonEncoding> encryptionType)
        {
            var decrypted = Keyring.JsonDecryptData(password, encoded, encryptionType);
            var header = decrypted.SubArray(0, PKCS8_HEADER.Length);

            if (!header.SequenceEqual(PKCS8_HEADER))
                throw new InvalidOperationException("Invalid PKCS8 header");

            var offset = SEED_OFFSET + SEC_LENGTH;
            var secretKey = decrypted.SubArray(SEED_OFFSET, offset);
            var divider = decrypted.SubArray(offset, offset + PKCS8_DIVIDER.Length);

            if (!divider.SequenceEqual(PKCS8_DIVIDER))
                throw new InvalidOperationException("Invalid PKCS8 divider");

            var publicOffset = offset + PKCS8_DIVIDER.Length;
            var publicKey = decrypted.SubArray(publicOffset, publicOffset + PUB_LENGTH);

            return new PairInfo(publicKey, secretKey);
        }

        public static byte[] EncodePair(string password, PairInfo pair)
        {
            if (IsLocked(pair.SecretKey))
                throw new InvalidOperationException("Secret key has to be set");

            var encoded = PKCS8_HEADER.Concat(pair.SecretKey).Concat(PKCS8_DIVIDER).Concat(pair.PublicKey).ToArray();

            if (string.IsNullOrEmpty(password))
                return encoded;

            var scryptResult = Scrypt.ScryptEncode(password, ScryptParam.Default);

            byte[] message = encoded;
            byte[] secret = scryptResult.Password.SubArray(0, 32);
            byte[] nonce = new byte[24].Populate();

            var naclResult = XSalsa20Poly1305.Encrypt(message, secret, nonce);

            return Scrypt.ToBytes(scryptResult.Salt, scryptResult.Param)
                .Concat(nonce)
                .Concat(naclResult)
                .ToArray();
        }

        public static WalletFile ToJsonPair(KeyType keyType, string address, Meta meta, byte[] encoded, bool isEncrypted)
        {
            return new WalletFile()
            {
                address = address,
                encoded = Convert.ToBase64String(encoded),
                encoding = new Encoding()
                {
                    content = new List<string>() { "pkcs8", keyType.ToString().ToLower() },
                    type = isEncrypted ? ENCODING.ToList() : ENCODING_NONE.ToList(),
                    version = ENCODING_VERSION
                },
                meta = meta
            };
        }

        public static bool IsLocked(byte[] secretKey) => secretKey is null || !secretKey.Any();
    }
}
