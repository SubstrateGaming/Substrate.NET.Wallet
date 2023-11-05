using CryptSharp.Utility;
using Newtonsoft.Json;
using Substrate.NetApi.Model.Types;
using System;
using System.Collections.Generic;
using System.Text;

namespace Substrate.NET.Wallet.Keyring
{
    public static class WalletJson
    {
        public enum EncryptedJsonEncoding
        {
            None,
            Scrypt,
            Xsalsa20Poly1305
        }

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

    public class WalletFile
    {
        public string encoded { get; set; }
        public Encoding encoding { get; set; }
        public string address { get; set; }
        public Meta meta { get; set; }

        public string ToJson()
        {
            return JsonConvert.SerializeObject(this);
        }

        public KeyType GetKeyType()
        {
            switch (encoding.content[1].ToLowerInvariant())
            {
                case "ed25519":
                    return KeyType.Ed25519;
                case "sr25519":
                    return KeyType.Sr25519;
                default: throw new InvalidOperationException($"{encoding.content[1]} type is not supported");
            }
        }
    }

    public class Encoding
    {
        public List<string> content { get; set; }
        public List<string> type { get; set; }
        public int version { get; set; }
    }

    public class Meta
    {
        public string genesisHash { get; set; }
        public bool isHardware { get; set; }
        public string name { get; set; }
        public List<object> tags { get; set; }
        public long whenCreated { get; set; }
    }
}
