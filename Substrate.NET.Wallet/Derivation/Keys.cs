using System.Collections.Generic;

namespace Substrate.NET.Wallet.Derivation
{
    /// <summary>
    /// Constants definition
    /// </summary>
    public static class Keys
    {
        /// <summary>
        /// The length of a Ristretto Schnorr `MiniSecretKey`, in bytes.
        /// </summary>
        public const int MINI_SECRET_KEY_LENGTH = 32;

        /// <summary>
        /// The length of a Ristretto Schnorr `PublicKey`, in bytes.
        /// </summary>
        public const int PUBLIC_KEY_LENGTH = 32;

        /// <summary>
        /// The length of the "key" portion of a Ristretto Schnorr secret key, in bytes.
        /// </summary>
        public const int SECRET_KEY_KEY_LENGTH = 32;

        /// <summary>
        /// The length of the "nonce" portion of a Ristretto Schnorr secret key, in bytes.
        /// </summary>
        public const int SECRET_KEY_NONCE_LENGTH = 32;

        /// <summary>
        /// The length of a Ristretto Schnorr key, `SecretKey`, in bytes.
        /// </summary>
        public const int SECRET_KEY_LENGTH = SECRET_KEY_KEY_LENGTH + SECRET_KEY_NONCE_LENGTH;

        /// <summary>
        /// The length of an Ristretto Schnorr `Keypair`, in bytes.
        /// </summary>
        public const int KEYPAIR_LENGTH = SECRET_KEY_LENGTH + PUBLIC_KEY_LENGTH;

        /// <summary>
        /// Length in bytes of our chain codes.
        /// </summary>
        public const int CHAIN_CODE_LENGTH = 32;
    }

    /// <summary>
    /// 
    /// </summary>
    public class KeyExtractResult
    {
        /// <summary>
        /// Derivation phrase
        /// </summary>
        public string DerivePath { get; set; }

        /// <summary>
        /// Password use in the derivation
        /// </summary>
        public string Password { get; set; }

        /// <summary>
        /// List of derivations
        /// </summary>
        public IList<DeriveJunction> Path { get; set; }

        /// <summary>
        /// Mnemonic phrase
        /// </summary>
        public string Phrase { get; set; }
    }

    /// <summary>
    /// Result of derivation path
    /// </summary>
    public class KeyExtractPathResult
    {
        /// <summary>
        /// Derivation string splitted
        /// </summary>
        public IList<string> Parts { get; set; }

        /// <summary>
        /// List of derivations
        /// </summary>
        public IList<DeriveJunction> Path { get; set; }
    }
}