using Chaos.NaCl;
using Substrate.NetApi;
using Substrate.NetApi.Extensions;
using Substrate.NetApi.Model.Types;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Substrate.NET.Wallet.Keyring
{
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

        public static Wallet CreatePair(Account account)
            => CreatePair(account, meta: null, encoded: null, encryptedEncoding: null, ss58Format: 42);

        /// <summary>
        /// Create a new keypair
        /// </summary>
        /// <param name="setup"></param>
        /// <param name="account"></param>
        /// <param name="meta"></param>
        /// <param name="encoded"></param>
        /// <param name="encryptedEncoding"></param>
        /// <param name="ss58Format"></param>
        /// <returns></returns>
        public static Wallet CreatePair(Account account, Meta meta, byte[] encoded, List<WalletJson.EncryptedJsonEncoding> encryptedEncoding, short ss58Format)
        {
            return new Wallet(Utils.GetAddressFrom(account.Bytes, ss58Format), encoded, meta, account.Bytes, account.PrivateKey, account.KeyType, encryptedEncoding);
        }

        /// <summary>
        /// Decode a keypair from a JSON keypair
        /// </summary>
        /// <param name="password"></param>
        /// <param name="encoded"></param>
        /// <param name="encryptionType"></param>
        /// <returns></returns>
        /// <exception cref="InvalidOperationException"></exception>
        public static Account DecodePair(string password, byte[] encoded, List<WalletJson.EncryptedJsonEncoding> encryptionType)
        {
            var decrypted = Keyring.JsonDecryptData(password, encoded, encryptionType);
            var decryptedSpan = new Span<byte>(decrypted); // Convert the decrypted byte array to a Span<byte>

            var header = decryptedSpan.Slice(0, PKCS8_HEADER.Length);

            if (!header.SequenceEqual(PKCS8_HEADER))
                throw new InvalidOperationException("Invalid PKCS8 header");

            var offset = SEED_OFFSET + SEC_LENGTH;
            var secretKey = decryptedSpan.Slice(SEED_OFFSET, SEC_LENGTH).ToArray(); // Convert span slice to array
            var divider = decryptedSpan.Slice(offset, PKCS8_DIVIDER.Length);

            if (!divider.SequenceEqual(PKCS8_DIVIDER))
                throw new InvalidOperationException("Invalid PKCS8 divider");

            var publicOffset = offset + PKCS8_DIVIDER.Length;
            var publicKey = decryptedSpan.Slice(publicOffset, PUB_LENGTH).ToArray(); // Convert span slice to array

            if (secretKey.Length == 64)
            {
                return Account.Build(KeyType.Sr25519, secretKey, publicKey);
            }
            else
            {
                Chaos.NaCl.Ed25519.KeyPairFromSeed(out publicKey, out secretKey, encoded);
                return Account.Build(KeyType.Ed25519, secretKey, publicKey);
            }
        }

        /// <summary>
        /// Encode a keypair into a byte array
        /// </summary>
        /// <param name="password"></param>
        /// <param name="pair"></param>
        /// <returns></returns>
        /// <exception cref="InvalidOperationException"></exception>
        public static byte[] EncodePair(string password, Account pair)
        {
            if (IsLocked(pair.PrivateKey))
            {
                throw new InvalidOperationException("Secret key has to be set");
            }

            var encoded = PKCS8_HEADER.Concat(pair.PrivateKey).Concat(PKCS8_DIVIDER).Concat(pair.Bytes).ToArray();

            if (string.IsNullOrEmpty(password))
                return encoded;

            var scryptResult = Scrypt.ScryptEncode(password, ScryptParam.Default);

            byte[] message = encoded;
            Span<byte> secretSpan = new Span<byte>(scryptResult.Password).Slice(0, 32);
            byte[] secret = secretSpan.ToArray();
            byte[] nonce = new byte[24].Populate();

            var naclResult = XSalsa20Poly1305.Encrypt(message, secret, nonce);

            return Scrypt.ToBytes(scryptResult.Salt, scryptResult.Param)
                .Concat(nonce)
                .Concat(naclResult)
                .ToArray();
        }

        /// <summary>
        /// Transform a keypair into a JSON representation
        /// </summary>
        /// <param name="keyType"></param>
        /// <param name="address"></param>
        /// <param name="meta"></param>
        /// <param name="encoded"></param>
        /// <param name="isEncrypted"></param>
        /// <returns></returns>
        public static WalletFile ToJsonPair(KeyType keyType, string address, Meta meta, byte[] encoded, bool isEncrypted)
        {
            return new WalletFile()
            {
                Address = address,
                Encoded = Convert.ToBase64String(encoded),
                Encoding = new Encoding()
                {
                    Content = new List<string>() { "pkcs8", keyType.ToString().ToLower() },
                    Type = isEncrypted ? ENCODING.ToList() : ENCODING_NONE.ToList(),
                    Version = ENCODING_VERSION
                },
                Meta = meta
            };
        }

        public static bool IsLocked(byte[] secretKey) => secretKey is null || !secretKey.Any();
    }
}