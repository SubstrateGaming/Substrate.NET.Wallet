using Substrate.NET.Schnorrkel.Keys;
using Substrate.NET.Wallet.Derivation;
using Substrate.NET.Wallet.Extensions;
using Substrate.NetApi;
using Substrate.NetApi.Extensions;
using Substrate.NetApi.Model.Types;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("Substrate.NET.Wallet.Test")]

namespace Substrate.NET.Wallet.Keyring
{
    public class KeyringAddress
    {
        public KeyType KeyType { get; set; }
        public Func<byte[], short, string> ToSS58 { get; set; }

        public KeyringAddress(KeyType keyType)
        {
            KeyType = keyType;
            ToSS58 = Utils.GetAddressFrom;
        }

        public KeyringAddress(KeyType keyType, Func<byte[], short, string> toSS58)
        {
            KeyType = keyType;
            ToSS58 = toSS58;
        }
    }

    /// <summary>
    /// Keyring is a cryptographic key management tool or library used to manage cryptographic keys and perform key-related operations, such as key generation, storage, and signing.
    /// </summary>
    public class Keyring
    {
        public const int NONCE_LENGTH = 24;
        public const int SCRYPT_LENGTH = 32 + 3 * 4;
        public const short DEFAULT_SS58 = 42;

        public IList<Wallet> Wallets { get; private set; } = new List<Wallet>();
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
            return Wallets.Select(x => x.Account.Bytes).ToList();
        }

        public Wallet GetWallet(byte[] publicKey)
        {
            return Wallets.FirstOrDefault(x => x.Account.Bytes.SequenceEqual(publicKey));
        }

        #endregion Get methods

        #region Add methods

        public void AddWallet(Wallet wallet)
        {
            Wallets.Add(wallet);
        }

        public Wallet AddFromAddress(string address, Meta meta, byte[] encoded, KeyType keyType, List<WalletJson.EncryptedJsonEncoding> encryptedEncoding)
        {
            var publicKey = Utils.GetPublicKeyFrom(address);

            var keyringPair = Pair.CreatePair(
                new KeyringAddress(keyType),
                new PairInfo(publicKey, new byte[32]),
                meta, encoded, encryptedEncoding, Ss58Format);

            AddWallet(keyringPair);
            return keyringPair;
        }

        public Wallet AddFromJson(string jsonWallet)
        {
            return AddFromJson(System.Text.Json.JsonSerializer.Deserialize<WalletFile>(jsonWallet));
        }

        public Wallet AddFromJson(WalletFile walletEncryption)
        {
            var keyringPair = CreateFromJson(walletEncryption);
            AddWallet(keyringPair);
            return keyringPair;
        }

        public Wallet AddFromMnemonic(string[] mnemonic, Meta meta, KeyType keyType)
            => AddFromMnemonic(string.Join(" ", mnemonic), meta, keyType);

        public Wallet AddFromMnemonic(string mnemonic, Meta meta, KeyType keyType)
        {
            return AddFromUri(mnemonic, meta, keyType);
        }

        public Wallet AddFromUri(string uri, Meta meta, KeyType keyType)
        {
            var pair = CreateFromUri(uri, meta, keyType);
            AddWallet(pair);

            return pair;
        }

        public Wallet AddFromSeed(byte[] seed, Meta meta, KeyType keyType)
        {
            var pair = Pair.CreatePair(new KeyringAddress(keyType), KeyPairFromSeed(keyType, seed), meta, null, null, Ss58Format);
            AddWallet(pair);

            return pair;
        }

        #endregion Add methods

        #region Create method

        private Wallet CreateFromJson(WalletFile walletEncryption)
        {
            if (walletEncryption == null) throw new ArgumentNullException(nameof(walletEncryption));

            if (walletEncryption.encoding.version == 3 && walletEncryption.encoding.content[0] != "pkcs8")
                throw new InvalidOperationException($"Unable to decode non pkcs8 type, found {walletEncryption.encoding.content[0]} instead");

            KeyType keyType = walletEncryption.GetKeyType();

            List<WalletJson.EncryptedJsonEncoding> encryptedEncoding = walletEncryption.encoding.type.Select(encrypt => WalletJson.EncryptedFromString(encrypt)).ToList();

            var publicKey = Utils.GetPublicKeyFrom(walletEncryption.address);
            var encoded = walletEncryption.encoded.IsHex() ?
                Utils.HexToByteArray(walletEncryption.encoded) :
                Convert.FromBase64String(walletEncryption.encoded);

            return Pair.CreatePair(
                new KeyringAddress(keyType),
                new PairInfo(publicKey, null),
                walletEncryption.meta, encoded, encryptedEncoding, Ss58Format);
        }

        public Wallet CreateFromUri(string uri, Meta meta, KeyType keyType)
        {
            var (extract, seed) = CreateSeedFromUri(uri);

            var derivedPair = Uri.KeyFromPath(KeyPairFromSeed(keyType, seed), extract.Path, keyType);

            return Pair.CreatePair(new KeyringAddress(keyType), derivedPair, meta, null, null, Ss58Format);
        }

        internal static (KeyExtractResult, byte[]) CreateSeedFromUri(string uri)
        {
            if (string.IsNullOrEmpty(uri)) throw new ArgumentNullException("uri");

            var resolvedUri = uri.StartsWith("//") ? $"{Uri.DEV_PHRASE}{uri}" : uri;
            KeyExtractResult extract = Uri.KeyExtractUri(resolvedUri);
            bool isPhraseHex = extract.Phrase.IsHex();

            var seed = new byte[32];
            if (isPhraseHex)
            {
                seed = Utils.HexToByteArray(extract.Phrase);
            }
            else
            {
                int phraseLength = extract.Phrase.Split(' ').Length;

                // Mnemonic size should be equal to 12, 15, 18, 21 or 24 words
                if (new byte[5] { 12, 15, 18, 21, 24 }.Any(l => l == phraseLength))
                {
                    if (!Mnemonic.ValidateMnemonic(extract.Phrase, Mnemonic.BIP39Wordlist.English))
                    {
                        throw new InvalidOperationException("Invalid bip39 mnemonic specified");
                    }

                    seed = Mnemonic.GetSecretKeyFromMnemonic(extract.Phrase, extract.Password, Mnemonic.BIP39Wordlist.English);
                }
                else
                {
                    if (phraseLength > 32)
                        throw new InvalidOperationException("Specified phrase is not a valid mnemonic and is invalid as a raw seed at > 32 bytes");

                    seed = extract.Phrase.PadRight(32).ToBytes();
                }
            }

            return (extract, seed);
        }

        #endregion Create method

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

        public static PairInfo KeyPairFromSeed(KeyType keyType, byte[] seed)
        {
            if (seed.Length != 32)
                throw new InvalidOperationException($"Seed is not 32 bytes (currently {seed.Length})");

            switch (keyType)
            {
                case KeyType.Ed25519:
                    Chaos.NaCl.Ed25519.KeyPairFromSeed(out byte[] pubKey, out byte[] priKey, seed);
                    return new PairInfo(pubKey, priKey);

                case KeyType.Sr25519:
                    var miniSecret = new MiniSecret(seed, ExpandMode.Ed25519);
                    var concatenated = miniSecret.GetPair().ToHalfEd25519Bytes();
                    var publicKey = concatenated.SubArray(Keys.SECRET_KEY_LENGTH, Keys.SECRET_KEY_LENGTH + Keys.PUBLIC_KEY_LENGTH);
                    var secretKey = concatenated.SubArray(0, Keys.SECRET_KEY_LENGTH);

                    return new PairInfo(publicKey, secretKey);

                default:
                    throw new NotImplementedException($"KeyType {keyType} isn't implemented!");
            }
        }

        public static bool IsMnemonicPhraseValid(string[] mnemonic, Mnemonic.BIP39Wordlist language = Mnemonic.BIP39Wordlist.English)
            => IsMnemonicPhraseValid(string.Join(" ", mnemonic), language);

        public static bool IsMnemonicPhraseValid(string mnemonic, Mnemonic.BIP39Wordlist language = Mnemonic.BIP39Wordlist.English)
        {
            if (string.IsNullOrEmpty(mnemonic)) return false;

            var words = mnemonic.Split(' ');

            // Mnemonic size should be equal to 12, 15, 18, 21 or 24 words
            if (
                new byte[5] { 12, 15, 18, 21, 24 }.Any(l => l == words.Length) &&
                words.All(p => p.Length > 2) &&
                Mnemonic.ValidateMnemonic(mnemonic, language))
            {
                return true;
            }

            return false;
        }

        private static void ensureDataIsSet(byte[] data, string message = "No data available")
        {
            if (data is null || !data.Any())
                throw new ArgumentException(string.IsNullOrEmpty(message) ? "No data available" : message);
        }

        #endregion Utility methods
    }
}