using Substrate.NetApi.Model.Types;
using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Substrate.NET.Wallet.Keyring
{
    /// <summary>
    /// Wallet JSON
    /// </summary>
    public static class WalletJson
    {
        /// <summary>
        /// Encrypted JSON encoding
        /// </summary>
        public enum EncryptedJsonEncoding
        {
            /// <summary>
            /// No encoding
            /// </summary>
            None,

            /// <summary>
            /// Scrypt encoding
            /// </summary>
            Scrypt,

            /// <summary>
            /// Xsalsa20Poly1305 encoding
            /// </summary>
            Xsalsa20Poly1305
        }

        /// <summary>
        /// Encrypted to string
        /// </summary>
        /// <param name="encrypt"></param>
        /// <returns></returns>
        /// <exception cref="InvalidOperationException"></exception>
        public static string EncryptedToString(EncryptedJsonEncoding encrypt)
        {
            switch (encrypt)
            {
                case EncryptedJsonEncoding.None:
                    return "none";

                case EncryptedJsonEncoding.Scrypt:
                    return "scrypt";

                case EncryptedJsonEncoding.Xsalsa20Poly1305:
                    return "xsalsa20-poly1305";

                default:
                    throw new InvalidOperationException($"{encrypt} encryption is not supported");
            }
        }

        /// <summary>
        /// Encrypted from string
        /// </summary>
        /// <param name="encrypt"></param>
        /// <returns></returns>
        /// <exception cref="InvalidOperationException"></exception>
        public static EncryptedJsonEncoding EncryptedFromString(string encrypt)
        {
            switch (encrypt)
            {
                case "none":
                    return EncryptedJsonEncoding.None;

                case "scrypt":
                    return EncryptedJsonEncoding.Scrypt;

                case "xsalsa20-poly1305":
                    return EncryptedJsonEncoding.Xsalsa20Poly1305;

                default:
                    throw new InvalidOperationException($"{encrypt} encryption is not supported");
            }
        }
    }

    /// <summary>
    /// Wallet file
    /// </summary>
    public class WalletFile
    {
        /// <summary>
        /// Encoded
        /// </summary>
        [JsonPropertyName("encoded")]
        public string Encoded { get; set; }

        /// <summary>
        /// Encoding
        /// </summary>
        [JsonPropertyName("encoding")]
        public Encoding Encoding { get; set; }

        /// <summary>
        /// Address
        /// </summary>
        [JsonPropertyName("address")]
        public string Address { get; set; }

        /// <summary>
        /// Meta
        /// </summary>
        [JsonPropertyName("meta")]
        public Meta Meta { get; set; }

        /// <summary>
        /// Convert to json
        /// </summary>
        /// <returns></returns>
        public string ToJson()
        {
            return System.Text.Json.JsonSerializer.Serialize(this);
        }

        /// <summary>
        /// Get the key type
        /// </summary>
        /// <returns></returns>
        /// <exception cref="InvalidOperationException"></exception>
        public KeyType GetKeyType()
        {
            switch (Encoding.Content[1].ToLowerInvariant())
            {
                case "ed25519":
                    return KeyType.Ed25519;

                case "sr25519":
                    return KeyType.Sr25519;

                default: throw new InvalidOperationException($"{Encoding.Content[1]} type is not supported");
            }
        }
    }

    /// <summary>
    /// Encoding for the wallet file
    /// </summary>
    public class Encoding
    {
        /// <summary>
        /// Content
        /// </summary>
        [JsonPropertyName("content")]
        public List<string> Content { get; set; }

        /// <summary>
        /// Type
        /// </summary>
        [JsonPropertyName("type")]
        public List<string> Type { get; set; }

        /// <summary>
        /// Version
        /// </summary>
        [JsonPropertyName("version")]
        [JsonNumberHandling(JsonNumberHandling.AllowReadingFromString)]
        public int Version { get; set; }
    }

    /// <summary>
    /// Metadata for the wallet file
    /// </summary>
    public class Meta
    {
        /// <summary>
        /// Genesis hash
        /// </summary>
        [JsonPropertyName("genesisHash")]
        public string GenesisHash { get; set; }

        /// <summary>
        /// Is hardware wallet
        /// </summary>
        [JsonPropertyName("isHardware")]
        public bool IsHardware { get; set; }

        /// <summary>
        /// Name of the wallet
        /// </summary>
        [JsonPropertyName("name")]
        public string Name { get; set; }

        /// <summary>
        /// Tags
        /// </summary>
        [JsonPropertyName("tags")]
        public List<object> Tags { get; set; }

        /// <summary>
        /// When created
        /// </summary>
        [JsonPropertyName("whenCreated")]
        public long WhenCreated { get; set; }
    }
}