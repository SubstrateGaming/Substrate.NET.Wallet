using System.Collections.Generic;

namespace Substrate.NET.Wallet.Derivation
{
    public static class Keys
    {
        // The length of a Ristretto Schnorr `MiniSecretKey`, in bytes.
        public const int MINI_SECRET_KEY_LENGTH = 32;

        // The length of a Ristretto Schnorr `PublicKey`, in bytes.
        public const int PUBLIC_KEY_LENGTH = 32;

        // The length of the "key" portion of a Ristretto Schnorr secret key, in bytes.
        public const int SECRET_KEY_KEY_LENGTH = 32;

        // The length of the "nonce" portion of a Ristretto Schnorr secret key, in bytes.
        public const int SECRET_KEY_NONCE_LENGTH = 32;

        // The length of a Ristretto Schnorr key, `SecretKey`, in bytes.
        public const int SECRET_KEY_LENGTH = SECRET_KEY_KEY_LENGTH + SECRET_KEY_NONCE_LENGTH;

        // The length of an Ristretto Schnorr `Keypair`, in bytes.
        public const int KEYPAIR_LENGTH = SECRET_KEY_LENGTH + PUBLIC_KEY_LENGTH;

        public const int CHAIN_CODE_LENGTH = 32;
    }

    public class KeyExtractResult
    {
        public string DerivePath { get; set; }
        public string Password { get; set; }
        public IList<DeriveJunction> Path { get; set; }
        public string Phrase { get; set; }
    }

    public class KeyExtractPathResult
    {
        public IList<string> Parts { get; set; }
        public IList<DeriveJunction> Path { get; set; }
    }
}