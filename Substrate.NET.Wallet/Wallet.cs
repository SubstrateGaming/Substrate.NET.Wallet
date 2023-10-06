using Chaos.NaCl;
using Schnorrkel;
using Schnorrkel.Keys;
using Serilog;
using Sodium;
using Substrate.NET.Wallet.Model;
using Substrate.NetApi;
using Substrate.NetApi.Model.Types;
using Substrate.NetApi.Sign;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;

[assembly: InternalsVisibleTo("Substrate.NET.Wallet.Test")]

namespace Substrate.NET.Wallet
{
    /// <summary>
    /// Basic Wallet implementation
    /// TODO: Make sure that a live runtime change is handled correctly.
    /// </summary>
    public class Wallet
    {
        /// <summary> The logger. </summary>
        private static readonly ILogger Logger = new LoggerConfiguration().CreateLogger();

        private const string FileType = "json";

        private static readonly RandomNumberGenerator _random = RandomNumberGenerator.Create();

        public Account Account { get; private set; }

        public string FileName { get; private set; }

        public EncodedData FileStore { get; private set; }

        /// <summary>
        ///
        /// </summary>
        /// <param name="account"></param>
        /// <param name="walletName"></param>
        /// <param name="fileStore"></param>
        private Wallet(Account account, string walletName, EncodedData fileStore)
        {
            Account = account;
            FileName = walletName;
            FileStore = fileStore;
        }

        /// <summary>
        /// Gets a value indicating whether this instance is unlocked.
        /// </summary>
        /// <value>
        ///   <c>true</c> if this instance is unlocked; otherwise, <c>false</c>.
        /// </value>
        public bool IsUnlocked => Account != null && Account.PrivateKey != null;

        /// <summary>
        /// Gets a value indicating whether this instance is created.
        /// </summary>
        /// <value>
        ///   <c>true</c> if this instance is created; otherwise, <c>false</c>.
        /// </value>
        public bool IsStored => FileStore != null;

        /// <summary>
        /// Unlocks the asynchronous.
        /// </summary>
        /// <param name="password">The password.</param>
        /// <param name="noCheck">if set to <c>true</c> [no check].</param>
        /// <returns></returns>
        /// <exception cref="Exception">Public key check failed!</exception>
        public bool Unlock(string password, bool noCheck = false)
        {
            if (IsUnlocked || !IsStored)
            {
                Logger.Warning("Wallet is already unlocked or doesn't exist.");
                return IsUnlocked && IsStored;
            }

            Logger.Information("Unlock wallet.");

            if (!Enum.TryParse(FileStore.Encoding.Content[1], true, out KeyType keyType))
            {
                Logger.Warning("Couldn't parse key type defintion.");
                return false;
            }

            try
            {
                var publicKeyBytes = Utils.GetPublicKeyFrom(FileStore.Address);
                var salt = GetSalt(Utils.GetPublicKeyFrom(FileStore.Address), Utils.HexToByteArray(FileStore.Meta.GenesisHash));
                var seed = Decrypt(FileStore.Encoded, password, salt);

                byte[] publicKey = null;
                byte[] privateKey = null;

                switch (keyType)
                {
                    case KeyType.Ed25519:
                        Ed25519.KeyPairFromSeed(out publicKey, out privateKey, seed);
                        break;

                    case KeyType.Sr25519:
                        var miniSecret = new MiniSecret(seed, ExpandMode.Ed25519);
                        var getPair = miniSecret.GetPair();
                        privateKey = getPair.Secret.ToBytes();
                        publicKey = getPair.Public.Key;
                        break;
                }

                if (!noCheck && !publicKey.SequenceEqual(publicKeyBytes))
                {
                    throw new NotSupportedException("Public key check failed!");
                }

                Account = Account.Build(keyType, privateKey, publicKey);
            }
            catch (Exception e)
            {
                Logger.Warning("Couldn't unlock the wallet with this password. {error}", e);
                return false;
            }

            return true;
        }

        internal static byte[] GetSalt(byte[] hash1, byte[] hash2)
        {
            byte[] concHash = new byte[hash1.Length + hash2.Length];
            Array.Copy(hash1, 0, concHash, 0, hash1.Length);
            Array.Copy(hash2, 0, concHash, hash1.Length, hash2.Length);
            return SHA256.Create().ComputeHash(concHash);
        }

        /// <summary>
        ///
        /// </summary>
        /// <param name="password"></param>
        /// <param name="noCheck"></param>
        /// <returns></returns>
        public bool Lock(string password, bool noCheck = false)
        {
            if (!IsUnlocked || !IsStored)
            {
                Logger.Warning("Wallet is already unlocked or doesn't exist.");
                return IsUnlocked && IsStored;
            }

            Logger.Information("Lock wallet.");

            if (!Enum.TryParse(FileStore.Encoding.Content[1], true, out KeyType keyType))
            {
                Logger.Warning("Couldn't parse key type defintion.");
                return false;
            }

            try
            {
                Account = Account.Build(keyType, null, Account.Bytes);
            }
            catch (Exception e)
            {
                Logger.Warning("Couldn't lock the wallet. {error}", e);
                return false;
            }

            return true;
        }

        /// <summary>
        /// Tries the sign message.
        /// </summary>
        /// <param name="data"></param>
        /// <param name="signature"></param>
        /// <param name="wrap"></param>
        /// <returns></returns>
        public bool TrySignMessage(byte[] data, out byte[] signature, bool wrap = true)
            => TrySignMessage(Account, data, out signature, wrap);

        /// <summary>
        /// Verifies the signature.
        /// </summary>
        /// <param name="data"></param>
        /// <param name="signature"></param>
        /// <param name="wrap"></param>
        /// <returns></returns>
        public bool VerifySignature(byte[] data, byte[] signature, bool wrap = true)
            => VerifySignature(Account, data, signature, wrap);

        /// <summary>
        /// Load the wallet from the file system.
        /// </summary>
        /// <param name="walletName"></param>
        /// <param name="wallet"></param>
        /// <returns></returns>
        public static bool Load(string walletName, out Wallet wallet)
        {
            wallet = null;

            if (!IsValidWalletName(walletName))
            {
                Logger.Warning("Wallet name is invalid, please provide a proper wallet name. [A-Za-Z_]{20}.");
                return false;
            }

            var walletFileName = ConcatWalletFileType(walletName);
            if (!Caching.TryReadFile(walletFileName, out EncodedData fileStore))
            {
                Logger.Warning("Failed to load wallet file '{walletFileName}'!", walletFileName);
                return false;
            }

            if (!Enum.TryParse(fileStore.Encoding.Content[1], true, out KeyType keyType))
            {
                Logger.Warning("Couldn't parse key type defintion.");
                return false;
            }

            var publicKeyBytes = Utils.HexToByteArray(fileStore.Address);

            var newAccount = new Account();
            newAccount.Create(keyType, publicKeyBytes);

            wallet = new Wallet(newAccount, walletName, fileStore);

            return true;
        }

        /// <summary>
        /// Load the wallet from the file store object.
        /// </summary>
        /// <param name="walletName"></param>
        /// <param name="fileStore"></param>
        /// <param name="wallet"></param>
        /// <param name="tryPersist"></param>
        /// <returns></returns>
        public static bool Load(string walletName, EncodedData fileStore, out Wallet wallet, bool tryPersist = true)
        {
            wallet = null;

            if (!IsValidWalletName(walletName))
            {
                Logger.Warning("Wallet name is invalid, please provide a proper wallet name. [A-Za-Z_]{20}.");
                return false;
            }

            if (!Enum.TryParse(fileStore.Encoding.Content[1], true, out KeyType keyType))
            {
                Logger.Warning("Couldn't parse key type defintion.");
                return false;
            }

            var publicKeyBytes = Utils.HexToByteArray(fileStore.Address);

            var newAccount = new Account();
            newAccount.Create(keyType, publicKeyBytes);

            if (tryPersist)
            {
                try
                {
                    Caching.Persist(Wallet.ConcatWalletFileType(walletName), fileStore);
                }
                catch (Exception e)
                {
                    Logger.Warning("Failed to persist wallet file '{walletFileName}'! {error}", walletName, e);
                    return false;
                }
            }

            wallet = new Wallet(newAccount, walletName, fileStore);

            return true;
        }

        /// <summary>
        /// Creates the from random.
        /// </summary>
        /// <param name="password"></param>
        /// <param name="keyType"></param>
        /// <param name="walletName"></param>
        /// <param name="wallet"></param>
        /// <param name="tryPersist"></param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        public static bool CreateFromRandom(string password, KeyType keyType, string walletName, out Wallet wallet, bool tryPersist = true)
        {
            wallet = null;

            if (!IsValidWalletName(walletName))
            {
                Logger.Warning("Wallet name is invalid, please provide a proper wallet name. [A-Za-Z_]{20}.");
                return false;
            }

            if (!IsValidPassword(password))
            {
                Logger.Warning(
                    "Password is invalid, please provide a proper password. Minmimu eight size and must have upper, lower and digits.");
                return false;
            }

            Logger.Information("Creating new wallet.");

            var randomBytes = new byte[48];

            _random.GetBytes(randomBytes);

            var memoryBytes = randomBytes.AsMemory();

            var hash = memoryBytes.Slice(0, 16).ToArray();

            var seed = memoryBytes.Slice(16, 32).ToArray();

            Account account;
            switch (keyType)
            {
                case KeyType.Ed25519:
                    Ed25519.KeyPairFromSeed(out byte[] pubKey, out byte[] priKey, seed);
                    account = Account.Build(KeyType.Ed25519, priKey, pubKey);
                    break;

                case KeyType.Sr25519:
                    var miniSecret = new MiniSecret(seed, ExpandMode.Ed25519);
                    account = Account.Build(KeyType.Sr25519, miniSecret.ExpandToSecret().ToBytes(), miniSecret.GetPair().Public.Key);
                    break;

                default:
                    throw new NotImplementedException($"KeyType {keyType} isn't implemented!");
            }

            var fileStore = GetFileStore(account.Value, account.KeyType, hash, seed, password);

            if (tryPersist)
            {
                try
                {
                    Caching.Persist(Wallet.ConcatWalletFileType(walletName), fileStore);
                }
                catch (Exception e)
                {
                    Logger.Warning("Failed to persist wallet file '{walletFileName}'! {error}", walletName, e);
                    return false;
                }
            }

            wallet = new Wallet(account, walletName, fileStore);

            return !tryPersist || wallet.Save(password);
        }

        private static EncodedData GetFileStore(string address, KeyType keyType, byte[] hash, byte[] seed, string password)
        {
            var salt = GetSalt(Utils.GetPublicKeyFrom(address), hash);

            return new EncodedData
            {
                Encoded = Encrypt(seed, password, salt),
                Encoding = new Model.EncodingInfo
                {
                    Content = new List<string> { "pkcs8", keyType.ToString().ToLower() },
                    Type = new List<string> { "scrypt", "xsalsa20-poly1305" },
                    Version = "3"
                },
                Address = address,
                Meta = new Metadata
                {
                    GenesisHash = Utils.Bytes2HexString(hash),
                    IsHardware = false,
                    Name = "SUBSTRATE",
                    Tags = new List<string>(),
                    WhenCreated = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
                }
            };
        }

        private bool Save(string password)
        {
            if (!IsValidPassword(password))
            {
                Logger.Warning(
                    "Password is invalid, please provide a proper password. Minmimu eight size and must have upper, lower and digits.");
                return false;
            }

            if (!IsUnlocked)
            {
                Logger.Warning("Unlock wallet first, before you store it.");
                return false;
            }

            Caching.Persist(Wallet.ConcatWalletFileType(FileName), FileStore);

            return true;
        }

        /// <summary>
        /// Encrypts the specified data.
        /// </summary>
        /// <param name="data"></param>
        /// <param name="password"></param>
        /// <param name="salt"></param>
        /// <returns></returns>
        public static string Encrypt(byte[] data, string password, byte[] salt)
        {
            // Derive the encryption key from the password using Scrypt
            byte[] derivedKey = DeriveKeyUsingScrypt(password, salt, 32); // 32 bytes = 256 bits

            // Encrypt the content using the derived key and XSalsa20-Poly1305
            byte[] nonce;
            byte[] encryptedDataBytes = EncryptUsingXSalsa20Poly1305(data, derivedKey, out nonce);

            // Combine nonce and encrypted data
            byte[] combined = new byte[nonce.Length + encryptedDataBytes.Length];
            Array.Copy(nonce, 0, combined, 0, nonce.Length);
            Array.Copy(encryptedDataBytes, 0, combined, nonce.Length, encryptedDataBytes.Length);

            return Convert.ToBase64String(combined);
        }

        /// <summary>
        /// Decrypts the specified encoded.
        /// </summary>
        /// <param name="encoded"></param>
        /// <param name="password"></param>
        /// <param name="salt"></param>
        /// <returns></returns>
        public static byte[] Decrypt(string encoded, string password, byte[] salt)
        {
            byte[] combined = Convert.FromBase64String(encoded);

            // Extract nonce and encrypted data
            byte[] nonce = new byte[24];
            byte[] encryptedDataBytes = new byte[combined.Length - nonce.Length];
            Array.Copy(combined, 0, nonce, 0, nonce.Length);
            Array.Copy(combined, nonce.Length, encryptedDataBytes, 0, encryptedDataBytes.Length);

            // Derive the encryption key from the password using Scrypt
            byte[] derivedKey = DeriveKeyUsingScrypt(password, salt, 32); // 32 bytes = 256 bits

            // Decrypt the content using the derived key and XSalsa20-Poly1305
            return DecryptUsingXSalsa20Poly1305(encryptedDataBytes, derivedKey, nonce);
        }

        /// <summary>
        /// Derives the key using scrypt.
        /// </summary>
        /// <param name="password"></param>
        /// <param name="salt"></param>
        /// <param name="keyLengthInBytes"></param>
        /// <returns></returns>
        private static byte[] DeriveKeyUsingScrypt(string password, byte[] salt, int keyLengthInBytes)
            => PasswordHash.ScryptHashBinary(Encoding.UTF8.GetBytes(password), salt, PasswordHash.Strength.Medium, keyLengthInBytes);

        /// <summary>
        /// Encrypts the using XSalsa20Poly1305.
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="key"></param>
        /// <param name="nonce"></param>
        /// <returns></returns>
        private static byte[] EncryptUsingXSalsa20Poly1305(byte[] plainText, byte[] key, out byte[] nonce)
        {
            nonce = SecretBox.GenerateNonce();
            return SecretBox.Create(plainText, nonce, key);
        }

        /// <summary>
        /// Decrypts the using XSalsa20Poly1305.
        /// </summary>
        /// <param name="cipherText"></param>
        /// <param name="key"></param>
        /// <param name="nonce"></param>
        /// <returns></returns>
        private static byte[] DecryptUsingXSalsa20Poly1305(byte[] cipherText, byte[] key, byte[] nonce)
        {
            return SecretBox.Open(cipherText, nonce, key);
        }

        /// <summary>
        /// Creates the from mnemonic.
        /// </summary>
        /// <param name="password"></param>
        /// <param name="mnemonic"></param>
        /// <param name="keyType"></param>
        /// <param name="bIP39Wordlist"></param>
        /// <param name="walletName"></param>
        /// <param name="wallet"></param>
        /// <param name="tryPersist"></param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        public static bool CreateFromMnemonic(string password, string mnemonic, KeyType keyType, Mnemonic.BIP39Wordlist bIP39Wordlist, string walletName, out Wallet wallet, bool tryPersist = true)
        {
            wallet = null;

            if (!IsValidWalletName(walletName))
            {
                Logger.Warning("Wallet name is invalid, please provide a proper wallet name. [A-Za-Z_]{20}.");
                return false;
            }

            if (!IsValidPassword(password))
            {
                Logger.Warning(
                    "Password isn't is invalid, please provide a proper password. Minmimu eight size and must have upper, lower and digits.");
                return false;
            }

            Logger.Information("Creating new wallet from mnemonic.");

            var seed = Mnemonic.GetSecretKeyFromMnemonic(mnemonic, "", bIP39Wordlist);

            Account account;
            switch (keyType)
            {
                case KeyType.Ed25519:
                    Ed25519.KeyPairFromSeed(out byte[] pubKey, out byte[] priKey, seed.Take(32).ToArray());
                    account = Account.Build(KeyType.Ed25519, priKey, pubKey);
                    break;

                case KeyType.Sr25519:
                    var miniSecret = new MiniSecret(seed, ExpandMode.Ed25519);
                    account = Account.Build(KeyType.Sr25519, miniSecret.ExpandToSecret().ToBytes(), miniSecret.GetPair().Public.Key);
                    break;

                default:
                    throw new NotImplementedException($"KeyType {keyType} isn't implemented!");
            }

            var randomBytes = new byte[48];

            _random.GetBytes(randomBytes);

            var memoryBytes = randomBytes.AsMemory();

            var hash = memoryBytes.Slice(0, 16).ToArray();

            var fileStore = GetFileStore(account.Value, account.KeyType, hash, seed, password);

            if (tryPersist)
            {
                try
                {
                    Caching.Persist(Wallet.ConcatWalletFileType(walletName), fileStore);
                }
                catch (Exception e)
                {
                    Logger.Warning("Failed to persist wallet file '{walletFileName}'! {error}", walletName, e);
                    return false;
                }
            }

            wallet = new Wallet(account, walletName, fileStore);

            return true;
        }

        /// <summary>
        /// Tries the sign message.
        /// </summary>
        /// <param name="signer">The signer.</param>
        /// <param name="data">The data.</param>
        /// <param name="signature">The signature.</param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException">KeyType {signer.KeyType} is currently not implemented for signing.</exception>
        public static bool TrySignMessage(Account signer, byte[] data, out byte[] signature, bool wrap = true)
        {
            signature = null;

            if (signer?.PrivateKey == null)
            {
                Logger.Warning("Account or private key doesn't exists.");
                return false;
            }

            if (wrap && !WrapMessage.IsWrapped(data))
            {
                data = WrapMessage.Wrap(data);
            }

            switch (signer.KeyType)
            {
                case KeyType.Ed25519:
                    signature = Ed25519.Sign(data, signer.PrivateKey);
                    break;

                case KeyType.Sr25519:
                    signature = Sr25519v091.SignSimple(signer.Bytes, signer.PrivateKey, data);
                    break;

                default:
                    throw new NotImplementedException(
                        $"KeyType {signer.KeyType} is currently not implemented for signing.");
            }

            return true;
        }

        /// <summary>
        /// Verifies the signature.
        /// </summary>
        /// <param name="signer">The signer.</param>
        /// <param name="data">The data.</param>
        /// <param name="signature">The signature.</param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException">KeyType {signer.KeyType} is currently not implemented for verifying signatures.</exception>
        public static bool VerifySignature(Account signer, byte[] data, byte[] signature, bool wrap = true)
        {
            if (wrap && !WrapMessage.IsWrapped(data))
            {
                data = WrapMessage.Wrap(data);
            }

            switch (signer.KeyType)
            {
                case KeyType.Ed25519:
                    return Ed25519.Verify(signature, data, signer.Bytes);

                case KeyType.Sr25519:
                    return Sr25519v091.Verify(signature, signer.Bytes, data);

                default:
                    throw new NotImplementedException(
                        $"KeyType {signer.KeyType} is currently not implemented for verifying signatures.");
            }
        }

        /// <summary>
        /// Determines whether [is valid wallet name] [the specified wallet name].
        /// </summary>
        /// <param name="walletName">Name of the wallet.</param>
        /// <returns>
        ///   <c>true</c> if [is valid wallet name] [the specified wallet name]; otherwise, <c>false</c>.
        /// </returns>
        public static bool IsValidWalletName(string walletName) => walletName.Length > 4 && walletName.Length < 21 &&
                   walletName.All(c => char.IsLetterOrDigit(c) || c.Equals('_'));

        /// <summary>
        /// Determines whether [is valid password] [the specified password].
        /// </summary>
        /// <param name="password">The password.</param>
        /// <returns>
        ///   <c>true</c> if [is valid password] [the specified password]; otherwise, <c>false</c>.
        /// </returns>
        public static bool IsValidPassword(string password)
            => password.Length > 7 && password.Length < 21 && password.Any(char.IsUpper) &&
                   password.Any(char.IsLower) && password.Any(char.IsDigit);

        /// <summary>
        /// Adds the type of the wallet file.
        /// </summary>
        /// <param name="walletName">Name of the wallet.</param>
        /// <returns></returns>
        public static string ConcatWalletFileType(string walletName)
            => $"{walletName}.{FileType}";
    }
}