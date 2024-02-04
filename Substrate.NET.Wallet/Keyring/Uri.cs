using Substrate.NET.Schnorrkel.Keys;
using Substrate.NET.Wallet.Derivation;
using Substrate.NET.Wallet.Extensions;
using Substrate.NetApi;
using Substrate.NetApi.Model.Types;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace Substrate.NET.Wallet.Keyring
{
    public static class Uri
    {
        public const string DEV_PHRASE = "bottom drive obey lake curtain smoke basket hold race lonely fit walk";
        public const string DEV_SEED = "0xfac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e";

        public const string CaptureUriPattern = "^(\\w+( \\w+)*)((\\/\\/?[^\\/]+)*)(\\/\\/\\/(.*))?$";
        public const string CaptureJunctionPattern = "\\/(\\/?)([^/]+)";

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

        public static PairInfo KeyFromPath(PairInfo pair, IList<DeriveJunction> paths, KeyType keyType)
        {
            foreach (var path in paths)
            {
                pair = CreateDerive(keyType, path, pair);
            }
            return pair;
        }

        private static PairInfo CreateDerive(KeyType keyType, DeriveJunction path, PairInfo pair)
        {
            var keyPair = KeyPair.FromHalfEd25519Bytes(pair.ToBytes());

            switch (keyType)
            {
                case KeyType.Sr25519:
                    var res = path.IsHard ?
                        Sr25519DeriveHard(keyPair, path.ChainCode) :
                        Sr25519DeriveSoft(keyPair, path.ChainCode);

                    return new PairInfo(
                        res.SubArray(Keys.SECRET_KEY_LENGTH, Keys.SECRET_KEY_LENGTH + Keys.PUBLIC_KEY_LENGTH),
                        res.SubArray(0, Keys.SECRET_KEY_LENGTH));

                case KeyType.Ed25519:
                    if (path.IsHard)
                    {
                        return Keyring.KeyPairFromSeed(
                            KeyType.Ed25519,
                            Ed25519DeriveHard(pair.SecretKey, path.ChainCode));
                    }
                    else
                    {
                        throw new InvalidOperationException($"Soft derivation paths are not allowed on {KeyType.Ed25519}");
                    }
            }

            throw new NotImplementedException();
        }

        public static byte[] Sr25519DeriveHard(byte[] seed, byte[] chainCode)
        {
            var miniSecret = new MiniSecret(seed, ExpandMode.Ed25519);
            return Sr25519DeriveHard(miniSecret.GetPair(), chainCode);
        }

        public static byte[] Sr25519DeriveHard(KeyPair pair, byte[] chainCode)
        {
            if (chainCode.Length != 32)
                throw new InvalidOperationException("Invalid chainCode passed to derive");

            var (miniSecretderived, _) = pair.Secret.HardDerive(chainCode);

            return miniSecretderived.GetPair().ToHalfEd25519Bytes();
        }

        public static byte[] Sr25519DeriveSoft(byte[] seed, byte[] chainCode)
        {
            var miniSecret = new MiniSecret(seed, ExpandMode.Ed25519);
            return Sr25519DeriveSoft(miniSecret.GetPair(), chainCode);
        }

        public static byte[] Sr25519DeriveSoft(KeyPair pair, byte[] chainCode)
        {
            if (chainCode.Length != 32)
                throw new InvalidOperationException("Invalid chainCode passed to derive");

            var (keyPairDerived, _) = pair.SoftDerive(chainCode);

            return keyPairDerived.ToHalfEd25519Bytes();
        }

        /// <summary>
        ///
        /// </summary>
        /// <param name="secretKey">64 bytes private key + nonce</param>
        /// <param name="chainCode"></param>
        /// <returns></returns>
        public static byte[] Ed25519DeriveHard(byte[] secretKey, byte[] chainCode)
        {
            var seed = secretKey.SubArray(0, 32);
            var HDKS = DeriveJunction.CompactAddLength(System.Text.Encoding.UTF8.GetBytes("Ed25519HDKD"));

            var all = HDKS.Concat(seed).Concat(chainCode).ToArray();
            var res = HashExtension.Hash(NetApi.Model.Meta.Storage.Hasher.BlakeTwo256, all);

            return res;
        }
    }
}