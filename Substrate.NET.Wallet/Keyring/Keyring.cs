using Newtonsoft.Json;
using Schnorrkel.Keys;
using Substrate.NET.Wallet.Extensions;
using Substrate.NetApi;
using Substrate.NetApi.Model.Types;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Substrate.NET.Wallet.Keyring
{
    public class KeyringAddress
    {
        public KeyType KeyType { get; set; }
        public Func<byte[], short, string> ToSS58 { get; set; }

        public static KeyringAddress Standard(KeyType keyType) 
            => new KeyringAddress() { KeyType = keyType, ToSS58 = Utils.GetAddressFrom };
    }

    /// <summary>
    /// Keyring is a cryptographic key management tool or library used to manage cryptographic keys and perform key-related operations, such as key generation, storage, and signing.
    /// </summary>
    public class Keyring
    {
        public const int NONCE_LENGTH = 24;
        public const int SCRYPT_LENGTH = 32 + 3 * 4;
        public const short DEFAULT_SS58 = 42;

        public IList<KeyringPair> Pairs { get; private set; } = new List<KeyringPair>();
        public short Ss58Format { get; set; } = DEFAULT_SS58;

        public byte[] DecodeAddress(string address)
        {
            short network;
            return Utils.GetPublicKeyFrom(address, out network);
        }

        public string EncodeAddress(byte[] publicKey)
        {
            return Utils.GetAddressFrom(publicKey, Ss58Format);
        }

        #region Get methods
        public IList<byte[]> GetPublicKeys()
        {
            return Pairs.Select(x => x.PairInformation.PublicKey).ToList();
        }

        public KeyringPair GetPair(byte[] publicKey)
        {
            return Pairs.FirstOrDefault(x => x.PairInformation.PublicKey.SequenceEqual(publicKey));
        }
        #endregion

        #region Add methods
        public void AddPair(KeyringPair keyringPair)
        {
            Pairs.Add(keyringPair);
        }

        public KeyringPair AddFromAddress(string address, Meta meta, byte[] encoded, KeyType keyType, List<WalletJson.EncryptedJsonEncoding> encryptedEncoding)
        {
            var publicKey = Utils.GetPublicKeyFrom(address);

            var keyringPair = Pair.CreatePair(
                KeyringAddress.Standard(keyType),
                new PairInfo(publicKey, new byte[32]),
                meta, encoded, encryptedEncoding, Ss58Format);

            AddPair(keyringPair);
            return keyringPair;
        }

        public KeyringPair AddFromJson(string jsonWallet)
        {
            return AddFromJson(JsonConvert.DeserializeObject<WalletEncryption>(jsonWallet));
        }

        public KeyringPair AddFromJson(WalletEncryption walletEncryption)
        {
            var keyringPair = CreateFromJson(walletEncryption);
            AddPair(keyringPair);
            return keyringPair;
        }

        public KeyringPair AddFromMnemonic(string[] mnemonic, Meta meta, KeyType keyType)
            => AddFromMnemonic(string.Join(" ", mnemonic), meta, keyType);

        public KeyringPair AddFromMnemonic(string mnemonic, Meta meta, KeyType keyType)
        {
            return AddFromUri(mnemonic, meta, keyType);
        }

        public KeyringPair AddFromUri(string uri, Meta meta, KeyType keyType)
        {
            var pair = CreateFromUri(uri, meta, keyType);
            AddPair(pair);

            return pair;
        }

        public KeyringPair AddFromSeed(byte[] seed, Meta meta, KeyType keyType)
        {
            var pair = Pair.CreatePair(KeyringAddress.Standard(keyType), KeyPairFromSeed(keyType, seed), meta, null, null, Ss58Format);
            AddPair(pair);

            return pair;
        }
        #endregion

        #region Create method
        private KeyringPair CreateFromJson(WalletEncryption walletEncryption)
        {
            if (walletEncryption == null) throw new ArgumentNullException(nameof(walletEncryption));

            if (walletEncryption.encoding.version == 3 && walletEncryption.encoding.content[0] != "pkcs8")
                throw new InvalidOperationException($"Unable to decode non pkcs8 type, found {walletEncryption.encoding.content[0]} instead");

            KeyType keyType;
            switch (walletEncryption.encoding.content[1].ToLowerInvariant())
            {
                case "ed25519":
                    keyType = KeyType.Ed25519;
                    break;
                case "sr25519":
                    keyType = KeyType.Sr25519;
                    break;
                default: throw new InvalidOperationException($"{walletEncryption.encoding.content[1]} type is not supported");
            };

            List<WalletJson.EncryptedJsonEncoding> encryptedEncoding = walletEncryption.encoding.type.Select(encrypt => WalletJson.EncryptedFromString(encrypt)).ToList();

            var publicKey = Utils.GetPublicKeyFrom(walletEncryption.address);
            var encoded = walletEncryption.encoded.IsHex() ?
                Utils.HexToByteArray(walletEncryption.encoded) :
                Convert.FromBase64String(walletEncryption.encoded);

            return Pair.CreatePair(
                KeyringAddress.Standard(keyType),
                new PairInfo(publicKey, null),
                walletEncryption.meta, encoded, encryptedEncoding, Ss58Format);
        }

        public KeyringPair CreateFromUri(string uri, Meta meta, KeyType keyType)
        {
            if (string.IsNullOrEmpty(uri)) throw new ArgumentNullException("uri");

            var resolvedUri = uri.StartsWith("//") ? $"{Uri.DEV_PHRASE}{uri}" : uri;
            var extract = Uri.KeyExtractUri(resolvedUri);

            bool isPhraseHex = extract.Phrase.IsHex();

            byte[] seed;
            if (isPhraseHex)
            {
                seed = Utils.HexToByteArray(extract.Phrase);
            } else
            {
                int phraseLength = extract.Phrase.Split(' ').Length;

                // Mnemonic size should be equal to 12, 15, 18, 21 or 24 words
                if (new byte[5] { 12, 15, 18, 21, 24 }.Any(l => l == phraseLength))
                {
                    if (!Mnemonic.ValidateMnemonic(mnemonic, bIP39Wordlist))
                    {
                        throw new InvalidOperationException("Invalid bip39 mnemonic specified");
                    }

                    seed = Mnemonic.GetSecretKeyFromMnemonic(mnemonic, password, bIP39Wordlist);
                } else
                {
                    if(phraseLength > 32)
                        throw new InvalidOperationException("Specified phrase is not a valid mnemonic and is invalid as a raw seed at > 32 bytes");

                    seed = extract.Phrase.PadRight(32).ToBytes();
                }
            }

            var derivedPair = Uri.KeyFromPath(KeyPairFromSeed(keyType, seed), extract.Path, keyType);

            return Pair.CreatePair(KeyringAddress.Standard(keyType), derivedPair, meta, null, null, Ss58Format);
        }
        #endregion

        #region Utility methods
        public static byte[] JsonDecryptData(string password, byte[] encrypted, List<WalletJson.EncryptedJsonEncoding> encryptedEncoding)
        {
            ensureDataIsSet(encrypted);

            if (encryptedEncoding.Any(x => x == WalletJson.EncryptedJsonEncoding.Xsalsa20Poly1305) && string.IsNullOrEmpty(password))
                throw new InvalidOperationException("Password require to encrypt data");

            var encoded = encrypted;
            if (!string.IsNullOrEmpty(password))
            {
                byte[] passwordBytes = password.ToBytes();
                if (encryptedEncoding.Any(x => x == WalletJson.EncryptedJsonEncoding.Scrypt))
                {
                    var scryptRes = Scrypt.FromBytes(encoded);
                    passwordBytes = Scrypt.ScryptEncode(password, scryptRes.Salt, scryptRes.Param).Password;
                    encrypted = encrypted.SubArray(SCRYPT_LENGTH);
                }

                encoded = Chaos.NaCl.XSalsa20Poly1305.TryDecrypt(
                    encrypted.Skip(NONCE_LENGTH).ToArray(),
                    passwordBytes.BytesFixLength(256, true),
                    encrypted.Take(NONCE_LENGTH).ToArray());

            }

            if (encoded is null || !encoded.Any())
                throw new InvalidOperationException("Unable to decode using the supplied passphrase");

            return encoded;
        }

        public PairInfo KeyPairFromSeed(KeyType keyType, byte[] seed)
        {
            switch (keyType)
            {
                case KeyType.Ed25519:
                    Chaos.NaCl.Ed25519.KeyPairFromSeed(out byte[] pubKey, out byte[] priKey, seed);
                    return new PairInfo(pubKey ,priKey);

                case KeyType.Sr25519:
                    var miniSecret = new MiniSecret(seed, ExpandMode.Ed25519);
                    return new PairInfo(miniSecret.GetPair().Public.Key, miniSecret.ExpandToSecret().ToBytes());

                default:
                    throw new NotImplementedException($"KeyType {keyType} isn't implemented!");
            }
        }

        private static void ensureDataIsSet(byte[] data, string message = "No data available")
        {
            if (data is null || !data.Any())
                throw new ArgumentException(string.IsNullOrEmpty(message) ? "No data available" : message);
        }
        #endregion
    }
}
