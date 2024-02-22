using Substrate.NET.Schnorrkel;
using Substrate.NET.Schnorrkel.Keys;
using Substrate.NET.Wallet.Derivation;
using Substrate.NetApi;
using Substrate.NetApi.Model.Meta;
using Substrate.NetApi.Model.Types;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace Substrate.NET.Wallet.Keyring
{
    /// <summary>
    /// URI
    /// </summary>
    public static class Uri
    {
        /// <summary>
        /// DEV PHRASE
        /// </summary>
        public const string DEV_PHRASE = "bottom drive obey lake curtain smoke basket hold race lonely fit walk";

        /// <summary>
        /// DEV SEED
        /// </summary>
        public const string DEV_SEED = "0xfac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e";

        /// <summary>
        /// Capture URI pattern
        /// </summary>
        public const string CaptureUriPattern = "^(\\w+( \\w+)*)((\\/\\/?[^\\/]+)*)(\\/\\/\\/(.*))?$";

        /// <summary>
        /// Capture junction pattern
        /// </summary>
        public const string CaptureJunctionPattern = "\\/(\\/?)([^/]+)";

        /// <summary>
        /// Key extract uri
        /// </summary>
        /// <param name="suri"></param>
        /// <returns></returns>
        /// <exception cref="InvalidOperationException"></exception>
        public static KeyExtractResult KeyExtractUri(string suri)
        {
            var match = Regex.Match(suri, CaptureUriPattern, RegexOptions.None, TimeSpan.FromMilliseconds(100));

            if (!match.Success)
                throw new InvalidOperationException("Unable to match provided value to a secret URI");

            var phrase = match.Groups[1].Value;
            var derivePath = match.Groups[3].Value;
            var password = match.Groups[6].Value;

            return new KeyExtractResult()
            {
                DerivePath = derivePath,
                Password = string.IsNullOrEmpty(password) ? null : password,
                Path = KeyExtractPath(derivePath).Path,
                Phrase = phrase
            };
        }

        /// <summary>
        /// Key extract path
        /// </summary>
        /// <param name="derivePath"></param>
        /// <returns></returns>
        /// <exception cref="InvalidOperationException"></exception>
        public static KeyExtractPathResult KeyExtractPath(string derivePath)
        {
            var matches = Regex.Matches(derivePath, CaptureJunctionPattern, RegexOptions.None, TimeSpan.FromMilliseconds(100));
            var paths = new List<DeriveJunction>();

            var parts = new List<string>();
            string constructed = string.Empty;

            if (matches.Count > 0)
            {
                constructed = string.Join("", matches);

                foreach (Match match in matches)
                {
                    parts.Add(match.Value);
                    paths.Add(DeriveJunction.From(match.Value.Substring(1)));
                }
            }

            if (constructed != derivePath)
            {
                throw new InvalidOperationException($"Re-constructed path ${constructed} does not match input");
            }

            return new KeyExtractPathResult()
            {
                Parts = parts,
                Path = paths
            };
        }

        /// <summary>
        /// Key from path
        /// </summary>
        /// <param name="pair"></param>
        /// <param name="paths"></param>
        /// <param name="keyType"></param>
        /// <returns></returns>
        public static Account KeyFromPath(Account pair, IList<DeriveJunction> paths, KeyType keyType)
        {
            foreach (var path in paths)
            {
                pair = CreateDerive(keyType, path, pair);
            }
            return pair;
        }

        /// <summary>
        /// Create derive
        /// </summary>
        /// <param name="keyType"></param>
        /// <param name="path"></param>
        /// <param name="pair"></param>
        /// <returns></returns>
        /// <exception cref="InvalidOperationException"></exception>
        /// <exception cref="NotImplementedException"></exception>
        private static Account CreateDerive(KeyType keyType, DeriveJunction path, Account pair)
        {
            // Construct a KeyPair from the concatenation of PrivateKey and Bytes, transformed into an array.
            KeyPair keyPair = KeyPair.FromHalfEd25519Bytes(pair.PrivateKey.Concat(pair.Bytes).ToArray());

            switch (keyType)
            {
                case KeyType.Sr25519:
                    // Derivation might return a byte array, assumed to be done here.
                    byte[] res = path.IsHard ?
                                Sr25519DeriveHard(keyPair, path.ChainCode) :
                                Sr25519DeriveSoft(keyPair, path.ChainCode);

                    // Convert the result to Span<byte> for efficient slicing
                    Span<byte> resSpan = new Span<byte>(res);

                    // Use Span.Slice for secret and public key portions
                    var secretKeySpan = resSpan.Slice(0, Keys.SECRET_KEY_LENGTH).ToArray();
                    var publicKeySpan = resSpan.Slice(Keys.SECRET_KEY_LENGTH, Keys.PUBLIC_KEY_LENGTH).ToArray();

                    // Account.Build presumably accepts byte[] for keys, so .ToArray() conversion is used
                    return Account.Build(keyType, secretKeySpan, publicKeySpan);

                case KeyType.Ed25519:
                    if (!path.IsHard)
                    {
                        throw new InvalidOperationException($"Soft derivation paths are not allowed on {keyType}.");
                    }

                    // Assuming Ed25519DeriveHard returns a byte array suitable for Account.FromSeed
                    return Account.FromSeed(keyType, Ed25519DeriveHard(pair.PrivateKey, path.ChainCode));

                default:
                    throw new NotImplementedException("This key type is not implemented.");
            }
        }


        /// <summary>
        /// Sr25519 derive hard
        /// </summary>
        /// <param name="seed"></param>
        /// <param name="chainCode"></param>
        /// <returns></returns>
        public static byte[] Sr25519DeriveHard(byte[] seed, byte[] chainCode)
        {
            var miniSecret = new MiniSecret(seed, ExpandMode.Ed25519);
            return Sr25519DeriveHard(miniSecret.GetPair(), chainCode);
        }

        /// <summary>
        /// Sr25519 derive hard
        /// </summary>
        /// <param name="pair"></param>
        /// <param name="chainCode"></param>
        /// <returns></returns>
        /// <exception cref="InvalidOperationException"></exception>
        public static byte[] Sr25519DeriveHard(KeyPair pair, byte[] chainCode)
        {
            if (chainCode.Length != 32)
                throw new InvalidOperationException("Invalid chainCode passed to derive");

            var (miniSecretderived, _) = pair.Secret.HardDerive(chainCode);

            return miniSecretderived.GetPair().ToHalfEd25519Bytes();
        }

        /// <summary>
        /// Sr25519 derive soft
        /// </summary>
        /// <param name="seed"></param>
        /// <param name="chainCode"></param>
        /// <returns></returns>
        public static byte[] Sr25519DeriveSoft(byte[] seed, byte[] chainCode)
        {
            var miniSecret = new MiniSecret(seed, ExpandMode.Ed25519);
            return Sr25519DeriveSoft(miniSecret.GetPair(), chainCode);
        }

        /// <summary>
        /// Sr25519 derive soft
        /// </summary>
        /// <param name="pair"></param>
        /// <param name="chainCode"></param>
        /// <returns></returns>
        /// <exception cref="InvalidOperationException"></exception>
        public static byte[] Sr25519DeriveSoft(KeyPair pair, byte[] chainCode)
        {
            if (chainCode.Length != 32)
                throw new InvalidOperationException("Invalid chainCode passed to derive");

            var (keyPairDerived, _) = pair.SoftDerive(chainCode);

            return keyPairDerived.ToHalfEd25519Bytes();
        }

        /// <summary>
        /// Ed25519 derive
        /// </summary>
        /// <param name="secretKey">64 bytes private key + nonce</param>
        /// <param name="chainCode"></param>
        /// <returns></returns>
        public static byte[] Ed25519DeriveHard(byte[] secretKey, byte[] chainCode)
        {
            var seed = new Span<byte>(secretKey, 0, 32).ToArray();
            var HDKS = DeriveJunction.CompactAddLength(System.Text.Encoding.UTF8.GetBytes("Ed25519HDKD"));

            var all = HDKS.Concat(seed).Concat(chainCode).ToArray();
            var res = HashExtension.Hash(Storage.Hasher.BlakeTwo256, all);

            return res;
        }
    }
}