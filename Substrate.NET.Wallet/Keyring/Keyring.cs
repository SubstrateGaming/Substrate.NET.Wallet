using Substrate.NET.Schnorrkel.Keys;
using Substrate.NET.Wallet.Derivation;
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
                Account.Build(keyType, null, publicKey),
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
            var keyringPair = CreateFromJson(walletEncryption, Ss58Format);
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
            var pair = CreateFromUri(uri, meta, keyType, Ss58Format);
            AddWallet(pair);

            return pair;
        }

        public Wallet AddFromSeed(byte[] seed, Meta meta, KeyType keyType)
        {
            var pair = Pair.CreatePair(Account.FromSeed(keyType, seed), meta, null, null, Ss58Format);
            AddWallet(pair);

            return pair;
        }

        #endregion Add methods

        #region Create method

        internal static Wallet CreateFromJson(WalletFile walletEncryption, short Ss58Format)
        {
            if (walletEncryption == null) throw new ArgumentNullException(nameof(walletEncryption));

            if (walletEncryption.Encoding.Version == 3 && walletEncryption.Encoding.Content[0] != "pkcs8")
                throw new InvalidOperationException($"Unable to decode non pkcs8 type, found {walletEncryption.Encoding.Content[0]} instead");

            KeyType keyType = walletEncryption.GetKeyType();

            List<WalletJson.EncryptedJsonEncoding> encryptedEncoding = walletEncryption.Encoding.Type.Select(encrypt => WalletJson.EncryptedFromString(encrypt)).ToList();

            var publicKey = Utils.GetPublicKeyFrom(walletEncryption.Address);
            var encoded = walletEncryption.Encoded.IsHex() ?
                Utils.HexToByteArray(walletEncryption.Encoded) :
                Convert.FromBase64String(walletEncryption.Encoded);

            return Pair.CreatePair(
                Account.Build(keyType, null, publicKey),
                walletEncryption.Meta, encoded, encryptedEncoding, Ss58Format);
        }

        internal static Wallet CreateFromUri(string uri, Meta meta, KeyType keyType, short Ss58Format)
        {
            var (extract, seed) = CreateSeedFromUri(uri);

            var derivedPair = Uri.KeyFromPath(Account.FromSeed(keyType, seed), extract.Path, keyType);

            return Pair.CreatePair(derivedPair, meta, null, null, Ss58Format);
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
            if (encrypted is null || !encrypted.Any())
            {
                throw new ArgumentException("No data available");
            }

            if (encryptedEncoding.Exists(x => x == WalletJson.EncryptedJsonEncoding.Xsalsa20Poly1305) && string.IsNullOrEmpty(password))
            {
                throw new InvalidOperationException("Password require to encrypt data");
            }

            var encoded = encrypted;
            if (!string.IsNullOrEmpty(password))
            {
                byte[] passwordBytes = password.ToBytes();
                if (encryptedEncoding.Any(x => x == WalletJson.EncryptedJsonEncoding.Scrypt))
                {
                    var scryptRes = Scrypt.FromBytes(encoded);
                    passwordBytes = Scrypt.ScryptEncode(password, scryptRes.Salt, scryptRes.Param).Password;
                    encrypted = encrypted.AsSpan().Slice(SCRYPT_LENGTH).ToArray();
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

        public static Account KeyPairFromSeed(KeyType keyType, byte[] seed)
        {
            if (seed.Length != 32)
                throw new InvalidOperationException($"Seed is not 32 bytes (currently {seed.Length})");

            switch (keyType)
            {
                case KeyType.Ed25519:
                    Chaos.NaCl.Ed25519.KeyPairFromSeed(out byte[] pubKey, out byte[] priKey, seed);
                    return Account.Build(keyType, priKey, pubKey);

                case KeyType.Sr25519:
                    var miniSecret = new MiniSecret(seed, ExpandMode.Ed25519);
                    return Account.Build(keyType, miniSecret.ExpandToSecret().ToEd25519Bytes(), miniSecret.ExpandToPublic().Key);

                default:
                    throw new NotImplementedException($"KeyType {keyType} isn't implemented!");
            }
        }

        #endregion Utility methods
    }
}