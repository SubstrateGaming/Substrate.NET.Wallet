using Serilog;
using Substrate.NET.Schnorrkel;
using Substrate.NET.Wallet.Extensions;
using Substrate.NET.Wallet.Keyring;
using Substrate.NetApi;
using Substrate.NetApi.Extensions;
using Substrate.NetApi.Model.Types;
using Substrate.NetApi.Sign;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;

namespace Substrate.NET.Wallet
{
    /// <summary>
    /// Basic Wallet implementation
    /// </summary>
    public class Wallet
    {
        /// <summary> The logger. </summary>
        private static readonly ILogger Logger = new LoggerConfiguration().CreateLogger();

        private const string FileType = "json";

        /// <summary>
        /// Account address
        /// </summary>
        public string Address { get; internal set; }

        /// <summary>
        /// Encoded value in JSON file
        /// </summary>
        public byte[] Encoded { get; internal set; }

        public List<WalletJson.EncryptedJsonEncoding> EncryptedEncoding { get; internal set; }
        public KeyType KeyType { get; internal set; }
        public Meta Meta { get; internal set; }
        public Account Account { get; private set; }
        public string FileName => Meta?.Name != null ? ConcatWalletFileType(Meta.Name) : string.Empty;
        public WalletFile FileStore { get; private set; }

        /// <summary>
        /// Account name policy for this wallet
        /// </summary>
        public WordManager AccountNamePolicy { get; set; } = WordManager.StandardAccountName;

        /// <summary>
        /// Password policy for this wallet
        /// </summary>
        public WordManager PasswordPolicy { get; set; } = WordManager.StandardPassword;

        /// <summary>
        /// Initializes a new instance of the wallet.
        /// </summary>
        /// <param name="address"></param>
        /// <param name="encoded"></param>
        /// <param name="meta"></param>
        /// <param name="publicKey"></param>
        /// <param name="privateKey"></param>
        /// <param name="keyType"></param>
        /// <param name="encryptedEncoding"></param>
        internal Wallet(string address, byte[] encoded, Meta meta, byte[] publicKey, byte[] privateKey, KeyType keyType, List<WalletJson.EncryptedJsonEncoding> encryptedEncoding)
        {
            Address = address;
            Encoded = encoded;
            Meta = meta;
            Account = new Account();
            Account.Create(keyType, privateKey, publicKey);
            EncryptedEncoding = encryptedEncoding;
            KeyType = keyType;
        }

        /// <summary>
        /// Gets a value indicating whether this instance is unlocked.
        /// </summary>
        /// <value>
        ///   <c>true</c> if this instance is unlocked; otherwise, <c>false</c>.
        /// </value>
        public bool IsUnlocked => Account != null && !Pair.IsLocked(Account.PrivateKey);

        public bool IsLocked => !IsUnlocked;

        /// <summary>
        /// Gets a value indicating whether this file has been created.
        /// </summary>
        /// <value>
        ///   <c>true</c> if this instance is created; otherwise, <c>false</c>.
        /// </value>
        public bool IsStored
        {
            get
            {
                if (FileName == null) return false;
                try
                {
                    return Caching.TryReadFile(FileName, out WalletFile _);
                }
                catch (Exception)
                {
                    Logger.Warning($"Caching error, please check all {nameof(SystemInteraction)} properties are set");
                }

                return false;
            }
        }

        /// <summary>
        /// Unlocks the account
        /// </summary>
        /// <param name="password">The password.</param>
        /// <param name="userEncoded"></param>
        /// <returns></returns>
        public bool Unlock(string password, byte[] userEncoded = null)
        {
            if (IsUnlocked)
            {
                Logger.Warning("Wallet is already unlocked or doesn't exist.");
                return IsUnlocked;
            }

            Logger.Information("Unlock wallet.");

            try
            {
                Account = Pkcs8.Decode(password, !Pair.IsLocked(userEncoded) ? userEncoded : Encoded, EncryptedEncoding);
            }
            catch (Exception ex)
            {
                Logger.Error($"Unable to unlock : {ex.Message}");
                return false;
            }

            return true;
        }

        /// <summary>
        /// Lock the account
        /// </summary>
        /// <returns></returns>
        public bool Lock()
        {
            if (!IsUnlocked)
            {
                Logger.Warning("Wallet is already locked.");
                return !IsUnlocked;
            }

            Logger.Information("Lock wallet.");

            try
            {
                Account = Account.Build(KeyType, null, Account.Bytes);
            }
            catch (Exception e)
            {
                Logger.Warning("Couldn't lock the wallet. {error}", e);
                return false;
            }

            return true;
        }

        /// <summary>
        /// Transform to wallet file.
        /// </summary>
        /// <param name="walletName"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        /// <exception cref="InvalidOperationException"></exception>
        public WalletFile ToWalletFile(string walletName, string password)
        {
            if (!IsUnlocked)
                Unlock(password);

            if (!AccountNamePolicy.IsValid(walletName))
            {
                throw new InvalidOperationException($"Wallet name is invalid : {string.Concat(" | ", AccountNamePolicy.GetErrors(walletName))}");
            }

            if (!PasswordPolicy.IsValid(password))
            {
                throw new InvalidOperationException($"Wallet password is invalid, please provide a proper wallet password. {string.Concat(" | ", AccountNamePolicy.GetErrors(walletName))}");
            }

            Encoded = Recode(password);

            var generatedMeta = new Meta()
            {
                IsHardware = false,
                Tags = new List<object>(),
                WhenCreated = DateTime.Now.Ticks,
                Name = walletName,
                GenesisHash = string.Empty
            };

            this.Meta = generatedMeta;

            return Pair.ToJsonPair(KeyType, Address, generatedMeta, Encoded, !string.IsNullOrEmpty(password));
        }

        /// <summary>
        /// To the json.
        /// </summary>
        /// <param name="walletName"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        public string ToJson(string walletName, string password)
        {
            return JsonSerializer.Serialize(ToWalletFile(walletName, password));
        }

        /// <summary>
        /// Recode the account
        /// </summary>
        /// <param name="password"></param>
        /// <returns></returns>
        public byte[] Recode(string password)
        {
            return Pair.EncodePair(password, Account.Clone());
        }

        /// <summary>
        /// Derive a new account from the current account
        /// </summary>
        /// <param name="sUri"></param>
        /// <returns></returns>
        public Wallet Derive(string sUri) => Derive(sUri, null);

        /// <summary>
        /// Derive a new account from the current account
        /// </summary>
        /// <param name="sUri"></param>
        /// <param name="meta"></param>
        /// <returns></returns>
        /// <exception cref="InvalidCastException"></exception>
        /// <exception cref="InvalidOperationException"></exception>
        public Wallet Derive(string sUri, Meta meta)
        {
            if (!IsUnlocked)
                throw new InvalidCastException("Cannot derive on a locked account");

            var res = Keyring.Uri.KeyExtractPath(sUri);

            if (KeyType == KeyType.Ed25519 && res.Path.Any(x => x.IsSoft))
            {
                throw new InvalidOperationException($"Soft derivation paths are not allowed on {KeyType}");
            }

            var derived = Keyring.Uri.KeyFromPath(Account.Clone(), res.Path, KeyType);

            return Pair.CreatePair(new KeyringAddress(KeyType), derived, Meta, null, EncryptedEncoding, Keyring.Keyring.DEFAULT_SS58);
        }

        /// <summary>
        /// Save the account
        /// </summary>
        /// <returns></returns>
        public void Save(string walletName, string password)
        {
            Caching.Persist(Wallet.ConcatWalletFileType(walletName), ToWalletFile(walletName, password));
        }

        /// <summary>
        /// Load the wallet from the file system.
        /// </summary>
        /// <param name="walletName"></param>
        /// <param name="wallet"></param>
        /// <returns></returns>
        public static bool TryLoad(string walletName, out Wallet wallet)
        {
            wallet = null;

            var walletFileName = ConcatWalletFileType(walletName);
            if (!Caching.TryReadFile(walletFileName, out WalletFile fileStore))
            {
                Logger.Warning("Failed to load wallet file '{walletFileName}'!", walletFileName);
                return false;
            }

            return TryLoad(walletName, fileStore, out wallet);
        }

        /// <summary>
        /// Load the wallet from file store object.
        /// </summary>
        /// <param name="walletName"></param>
        /// <param name="fileStore"></param>
        /// <param name="wallet"></param>
        /// <returns></returns>
        public static bool TryLoad(string walletName, WalletFile fileStore, out Wallet wallet)
        {
            wallet = Keyring.Keyring.CreateFromJson(fileStore, 42);

            return true;
        }

        #region Sign

        /// <summary>
        /// Sign the message
        /// </summary>
        /// <param name="message"></param>
        /// <param name="wrap"></param>
        /// <returns></returns>
        public byte[] Sign(string message, bool wrap = true)
                => Sign(message.ToBytes(), wrap);

        /// <summary>
        /// Sign the message
        /// </summary>
        /// <param name="message"></param>
        /// <param name="wrap"></param>
        /// <returns></returns>
        /// <exception cref="InvalidOperationException"></exception>
        public byte[] Sign(byte[] message, bool wrap = true)
        {
            if (!IsUnlocked)
                throw new InvalidOperationException("Cannot sign a message on a locked account");

            if (wrap && !WrapMessage.IsWrapped(message))
            {
                message = WrapMessage.Wrap(message);
            }

            return Account.Sign(message);
        }

        /// <summary>
        /// Tries the sign message.
        /// </summary>
        /// <param name="signer">The signer.</param>
        /// <param name="message">The data.</param>
        /// <param name="signature">The signature.</param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException">KeyType {signer.KeyType} is currently not implemented for signing.</exception>
        public static bool TrySignMessage(Account signer, byte[] message, out byte[] signature, bool wrap = true)
        {
            signature = null;

            if (signer?.PrivateKey == null)
            {
                Logger.Warning("Account or private key doesn't exists.");
                return false;
            }

            if (wrap && !WrapMessage.IsWrapped(message))
            {
                message = WrapMessage.Wrap(message);
            }

            signature = signer.Sign(message);
            return true;
        }

        #endregion Sign

        #region Verify

        /// <summary>
        /// Verify the message
        /// </summary>
        /// <param name="signature"></param>
        /// <param name="message"></param>
        /// <param name="wrap"></param>
        /// <returns></returns>
        public bool Verify(byte[] signature, string message, bool wrap = true)
            => Verify(signature, message.ToBytes(), wrap);

        /// <summary>
        /// Verify the message
        /// </summary>
        /// <param name="signature"></param>
        /// <param name="message"></param>
        /// <param name="wrap"></param>
        /// <returns></returns>
        /// <exception cref="InvalidOperationException"></exception>
        public bool Verify(byte[] signature, byte[] message, bool wrap = true)
        {
            if (!IsUnlocked)
                throw new InvalidOperationException("Cannot verify a message on a locked account");

            if (wrap && !WrapMessage.IsWrapped(message))
            {
                message = WrapMessage.Wrap(message);
            }

            try
            {
                return Account.Verify(signature, message);
            }
            catch (Exception ex)
            {
                Logger.Warning(ex.Message);
                return false;
            }
        }

        #endregion Verify

        /// <summary>
        /// Determines whether [is valid wallet name] [the specified wallet name].
        /// </summary>
        /// <param name="walletName">Name of the wallet.</param>
        /// <returns>
        ///   <c>true</c> if [is valid wallet name] [the specified wallet name]; otherwise, <c>false</c>.
        /// </returns>
        public static bool IsValidWalletName(string walletName)
            => WordManager.StandardAccountName.IsValid(walletName);

        /// <summary>
        /// Determines whether [is valid password] [the specified password].
        /// </summary>
        /// <param name="password">The password.</param>
        /// <returns>
        ///   <c>true</c> if [is valid password] [the specified password]; otherwise, <c>false</c>.
        /// </returns>
        public static bool IsValidPassword(string password)
            => WordManager.StandardPassword.IsValid(password);

        /// <summary>
        /// Adds the type of the wallet file.
        /// </summary>
        /// <param name="walletName">Name of the wallet.</param>
        /// <returns></returns>
        public static string ConcatWalletFileType(string walletName)
            => $"{walletName}.{FileType}";
    }
}