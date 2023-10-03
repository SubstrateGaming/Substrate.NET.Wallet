using Chaos.NaCl;
using Schnorrkel;
using Schnorrkel.Keys;
using Serilog;
using Substrate.NetApi;
using Substrate.NetApi.Model.Types;
using Substrate.NetApi.Sign;
using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

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

        public FileStore FileStore { get; private set; }

        /// <summary>
        ///
        /// </summary>
        /// <param name="account"></param>
        /// <param name="walletName"></param>
        /// <param name="fileStore"></param>
        private Wallet(Account account, string walletName, FileStore fileStore)
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

            try
            {
                var pswBytes = Encoding.UTF8.GetBytes(password);

                pswBytes = SHA256.Create().ComputeHash(pswBytes);

                var seed = ManagedAes.DecryptStringFromBytes_Aes(FileStore.EncryptedSeed, pswBytes, FileStore.Salt);

                byte[] publicKey = null;
                byte[] privateKey = null;
                switch (FileStore.KeyType)
                {
                    case KeyType.Ed25519:
                        Ed25519.KeyPairFromSeed(out publicKey, out privateKey, Utils.HexToByteArray(seed));
                        break;

                    case KeyType.Sr25519:
                        var miniSecret = new MiniSecret(Utils.HexToByteArray(seed), ExpandMode.Ed25519);
                        var getPair = miniSecret.GetPair();
                        privateKey = getPair.Secret.ToBytes();
                        publicKey = getPair.Public.Key;
                        break;
                }

                if (!noCheck && !publicKey.SequenceEqual(FileStore.PublicKey))
                {
                    throw new NotSupportedException("Public key check failed!");
                }

                Account = Account.Build(FileStore.KeyType, privateKey, publicKey);
            }
            catch (Exception e)
            {
                Logger.Warning("Couldn't unlock the wallet with this password. {error}", e);
                return false;
            }

            return true;
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

            try
            {
                Account = Account.Build(FileStore.KeyType, null, Account.Bytes);
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
            if (!Caching.TryReadFile(walletFileName, out FileStore fileStore))
            {
                Logger.Warning("Failed to load wallet file '{walletFileName}'!", walletFileName);
                return false;
            }

            var newAccount = new Account();
            newAccount.Create(fileStore.KeyType, fileStore.PublicKey);

            wallet = new Wallet(newAccount, walletName, fileStore);

            return true;
        }

        /// <summary>
        /// Load the wallet from file store object.
        /// </summary>
        /// <param name="walletName"></param>
        /// <param name="fileStore"></param>
        /// <param name="wallet"></param>
        /// <returns></returns>
        public static bool Load(string walletName, FileStore fileStore, out Wallet wallet)
        {
            wallet = null;

            if (!IsValidWalletName(walletName))
            {
                Logger.Warning("Wallet name is invalid, please provide a proper wallet name. [A-Za-Z_]{20}.");
                return false;
            }

            var newAccount = new Account();
            newAccount.Create(fileStore.KeyType, fileStore.PublicKey);

            wallet = new Wallet(newAccount, walletName, fileStore);

            return true;
        }

        /// <summary>
        /// Creates the asynchronous.
        /// </summary>
        /// <param name="password">The password.</param>
        /// <param name="walletName">Name of the wallet.</param>
        /// <returns></returns>
        public static bool CreateFromRandom(string password, KeyType keyType, string walletName, out Wallet wallet)
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

            Logger.Information("Creating new wallet.");

            var randomBytes = new byte[48];

            _random.GetBytes(randomBytes);

            var memoryBytes = randomBytes.AsMemory();

            var pswBytes = Encoding.UTF8.GetBytes(password);

            var salt = memoryBytes.Slice(0, 16).ToArray();

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

            pswBytes = SHA256.Create().ComputeHash(pswBytes);

            var encryptedSeed =
                ManagedAes.EncryptStringToBytes_Aes(
                    Utils.Bytes2HexString(seed, Utils.HexStringFormat.Pure), pswBytes, salt);

            var fileStore = new FileStore(keyType, account.Bytes, encryptedSeed, salt);
            Caching.Persist(Wallet.ConcatWalletFileType(walletName), fileStore);

            wallet = new Wallet(account, walletName, fileStore);

            return true;
        }

        /// <summary>
        /// Creates the asynchronous.
        /// </summary>
        /// <param name="password">The password.</param>
        /// <param name="mnemonic">The mnemonic.</param>
        /// <param name="walletName">Name of the wallet.</param>
        /// <returns></returns>
        public static bool CreateFromMnemonic(string password, string mnemonic, KeyType keyType, Mnemonic.BIP39Wordlist bIP39Wordlist, string walletName, out Wallet wallet)
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

            var pswBytes = Encoding.UTF8.GetBytes(password);

            var salt = memoryBytes.Slice(0, 16).ToArray();

            pswBytes = SHA256.Create().ComputeHash(pswBytes);

            var encryptedSeed =
                ManagedAes.EncryptStringToBytes_Aes(
                    Utils.Bytes2HexString(seed, Utils.HexStringFormat.Pure), pswBytes, salt);

            var fileStore = new FileStore(keyType, account.Bytes, encryptedSeed, salt);
            Caching.Persist(Wallet.ConcatWalletFileType(walletName), fileStore);

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