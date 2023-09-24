using Chaos.NaCl;
using Schnorrkel;
using Schnorrkel.Keys;
using Serilog;
using Substrate.NetApi;
using Substrate.NetApi.Model.Types;
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

        private const string FileType = "dat";

        private const string DefaultWalletName = "wallet";

        private readonly Random _random = new Random();

        private FileStore _walletFile;

        /// <summary>
        /// Constructor
        /// </summary>
        public Wallet()
        {
        }

        /// <summary>
        /// Gets a value indicating whether this instance is unlocked.
        /// </summary>
        /// <value>
        ///   <c>true</c> if this instance is unlocked; otherwise, <c>false</c>.
        /// </value>
        public bool IsUnlocked => Account != null;

        /// <summary>
        /// Gets a value indicating whether this instance is created.
        /// </summary>
        /// <value>
        ///   <c>true</c> if this instance is created; otherwise, <c>false</c>.
        /// </value>
        public bool IsCreated => _walletFile != null;

        public Account Account { get; private set; }

        /// <summary>
        /// Determines whether [is valid wallet name] [the specified wallet name].
        /// </summary>
        /// <param name="walletName">Name of the wallet.</param>
        /// <returns>
        ///   <c>true</c> if [is valid wallet name] [the specified wallet name]; otherwise, <c>false</c>.
        /// </returns>
        public bool IsValidWalletName(string walletName)
        {
            return walletName.Length > 4 && walletName.Length < 21 &&
                   walletName.All(c => char.IsLetterOrDigit(c) || c.Equals('_'));
        }

        /// <summary>
        /// Determines whether [is valid password] [the specified password].
        /// </summary>
        /// <param name="password">The password.</param>
        /// <returns>
        ///   <c>true</c> if [is valid password] [the specified password]; otherwise, <c>false</c>.
        /// </returns>
        public bool IsValidPassword(string password)
        {
            return password.Length > 7 && password.Length < 21 && password.Any(char.IsUpper) &&
                   password.Any(char.IsLower) && password.Any(char.IsDigit);
        }

        /// <summary>
        /// Adds the type of the wallet file.
        /// </summary>
        /// <param name="walletName">Name of the wallet.</param>
        /// <returns></returns>
        public string AddWalletFileType(string walletName)
        {
            return $"{walletName}.{FileType}";
        }

        /// <summary>
        /// Load an existing wallet
        /// </summary>
        /// <param name="walletName"></param>
        /// <returns></returns>
        public bool Load(string walletName = DefaultWalletName)
        {
            if (!IsValidWalletName(walletName))
            {
                Logger.Warning("Wallet name is invalid, please provide a proper wallet name. [A-Za-Z_]{20}.");
                return false;
            }

            var walletFileName = AddWalletFileType(walletName);
            if (!Caching.TryReadFile(walletFileName, out _walletFile))
            {
                Logger.Warning("Failed to load wallet file '{walletFileName}'!", walletFileName);
                return false;
            }

            return true;
        }

        /// <summary>
        /// Creates the asynchronous.
        /// </summary>
        /// <param name="password">The password.</param>
        /// <param name="mnemonic">The mnemonic.</param>
        /// <param name="walletName">Name of the wallet.</param>
        /// <returns></returns>
        public bool Create(string password, string mnemonic, KeyType keyType = KeyType.Sr25519, Mnemonic.BIP39Wordlist bIP39Wordlist = Mnemonic.BIP39Wordlist.English, string walletName = DefaultWalletName)
        {
            if (IsCreated)
            {
                Logger.Warning("Wallet already created.");
                return true;
            }

            if (!IsValidPassword(password))
            {
                Logger.Warning(
                    "Password isn't is invalid, please provide a proper password. Minmimu eight size and must have upper, lower and digits.");
                return false;
            }

            Logger.Information("Creating new wallet from mnemonic.");

            var seed = Mnemonic.GetSecretKeyFromMnemonic(mnemonic, password, bIP39Wordlist);
            switch (keyType)
            {
                case KeyType.Ed25519:
                    Ed25519.KeyPairFromSeed(out byte[] pubKey, out byte[] priKey, seed);
                    Account = Account.Build(KeyType.Ed25519, priKey, pubKey);
                    break;

                case KeyType.Sr25519:
                    var miniSecret = new MiniSecret(seed, ExpandMode.Ed25519);
                    Account = Account.Build(KeyType.Sr25519, miniSecret.ExpandToSecret().ToBytes(), miniSecret.GetPair().Public.Key);
                    break;

                default:
                    throw new NotImplementedException($"KeyType {keyType} isn't implemented!");
            }

            var randomBytes = new byte[48];

            _random.NextBytes(randomBytes);

            var memoryBytes = randomBytes.AsMemory();

            var pswBytes = Encoding.UTF8.GetBytes(password);

            var salt = memoryBytes.Slice(0, 16).ToArray();

            pswBytes = SHA256.Create().ComputeHash(pswBytes);

            var encryptedSeed =
                ManagedAes.EncryptStringToBytes_Aes(
                    Utils.Bytes2HexString(seed, Utils.HexStringFormat.Pure), pswBytes, salt);

            _walletFile = new FileStore(keyType, Account.Bytes, encryptedSeed, salt);

            Caching.Persist(AddWalletFileType(walletName), _walletFile);

            return true;
        }

        /// <summary>
        /// Creates the asynchronous.
        /// </summary>
        /// <param name="password">The password.</param>
        /// <param name="walletName">Name of the wallet.</param>
        /// <returns></returns>
        public bool Create(string password, KeyType keyType = KeyType.Sr25519, string walletName = DefaultWalletName)
        {
            if (IsCreated)
            {
                Logger.Warning("Wallet already created.");
                return true;
            }

            if (!IsValidPassword(password))
            {
                Logger.Warning(
                    "Password isn't is invalid, please provide a proper password. Minmimu eight size and must have upper, lower and digits.");
                return false;
            }

            Logger.Information("Creating new wallet.");

            var randomBytes = new byte[48];

            _random.NextBytes(randomBytes);

            var memoryBytes = randomBytes.AsMemory();

            var pswBytes = Encoding.UTF8.GetBytes(password);

            var salt = memoryBytes.Slice(0, 16).ToArray();

            var seed = memoryBytes.Slice(16, 32).ToArray();

            switch (keyType)
            {
                case KeyType.Ed25519:
                    Ed25519.KeyPairFromSeed(out byte[] pubKey, out byte[] priKey, seed);
                    Account = Account.Build(KeyType.Ed25519, priKey, pubKey);
                    break;

                case KeyType.Sr25519:
                    var miniSecret = new MiniSecret(seed, ExpandMode.Ed25519);
                    Account = Account.Build(KeyType.Sr25519, miniSecret.ExpandToSecret().ToBytes(), miniSecret.GetPair().Public.Key);
                    break;

                default:
                    throw new NotImplementedException($"KeyType {keyType} isn't implemented!");
            }

            pswBytes = SHA256.Create().ComputeHash(pswBytes);

            var encryptedSeed =
                ManagedAes.EncryptStringToBytes_Aes(
                    Utils.Bytes2HexString(seed, Utils.HexStringFormat.Pure), pswBytes, salt);

            _walletFile = new FileStore(keyType, Account.Bytes, encryptedSeed, salt);

            Caching.Persist(AddWalletFileType(walletName), _walletFile);

            return true;
        }

        /// <summary>
        /// Unlocks the asynchronous.
        /// </summary>
        /// <param name="password">The password.</param>
        /// <param name="noCheck">if set to <c>true</c> [no check].</param>
        /// <returns></returns>
        /// <exception cref="Exception">Public key check failed!</exception>
        public bool Unlock(string password, bool noCheck = false)
        {
            if (IsUnlocked || !IsCreated)
            {
                Logger.Warning("Wallet is already unlocked or doesn't exist.");
                return IsUnlocked && IsCreated;
            }

            Logger.Information("Unlock new wallet.");

            try
            {
                var pswBytes = Encoding.UTF8.GetBytes(password);

                pswBytes = SHA256.Create().ComputeHash(pswBytes);

                var seed = ManagedAes.DecryptStringFromBytes_Aes(_walletFile.EncryptedSeed, pswBytes, _walletFile.Salt);

                byte[] publicKey = null;
                byte[] privateKey = null;
                switch (_walletFile.KeyType)
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

                if (noCheck || !publicKey.SequenceEqual(_walletFile.PublicKey))
                    throw new Exception("Public key check failed!");

                Account = Account.Build(_walletFile.KeyType, privateKey, publicKey);
            }
            catch (Exception e)
            {
                Logger.Warning("Couldn't unlock the wallet with this password. {error}", e);
                return false;
            }

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
        public bool TrySignMessage(Account signer, byte[] data, out byte[] signature)
        {
            signature = null;

            if (signer?.PrivateKey == null)
            {
                Logger.Warning("Account or private key doesn't exists.");
                return false;
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
        public bool VerifySignature(Account signer, byte[] data, byte[] signature)
        {
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
    }
}