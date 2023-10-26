using Newtonsoft.Json;
using Substrate.NET.Wallet.Extensions;
using Substrate.NetApi;
using Substrate.NetApi.Extensions;
using Substrate.NetApi.Model.Types;
using System;
using System.Collections.Generic;
using System.Dynamic;
using System.Text;

namespace Substrate.NET.Wallet.Keyring
{
    /// <summary>
    /// A Keyring pair is an account
    /// It can be created from a mnemonic phrase, a json file, a seed, or a uri
    /// </summary>
    public class KeyringPair
    {
        public KeyringPair(string address, byte[] addressRaw, byte[] encoded, Meta meta, PairInfo pair, KeyType keyType, List<WalletJson.EncryptedJsonEncoding> encryptedEncoding)
        {
            PairInformation = pair;
            Address = address;
            Encoded = encoded;
            AddressRaw = addressRaw;
            Meta = meta;
            KeyType = keyType;
            EncryptedEncoding = encryptedEncoding;
        }

        public string Address { get; internal set; }
        public byte[] AddressRaw { get; internal set; }
        public byte[] Encoded { get; internal set; }
        public Meta Meta { get; internal set; }
        public PairInfo PairInformation { get; internal set; }
        public KeyType KeyType { get; internal set; }
        public List<WalletJson.EncryptedJsonEncoding> EncryptedEncoding { get; internal set; }

        //public Wallet ToWallet()
        //{
        //    return new Wallet(Encoded, Meta, PairInformation.PublicKey, PairInformation.SecretKey, KeyType, EncryptedEncoding);
        //}

        //public bool IsLocked => Pair.IsLocked(PairInformation.SecretKey);

        //public void Lock()
        //{
        //    PairInformation.SecretKey = null;
        //}

        //public void Unlock(string password, byte[] userEncoded = null)
        //{
        //    PairInformation = Pkcs8.Decode(password, !Pair.IsLocked(userEncoded) ? userEncoded : Encoded, EncryptedEncoding);
        //}

        //public byte[] EncodePkcs8(string password)
        //{
        //    return Pkcs8.Encode(password, null, EncryptedEncoding);
        //}

        //public byte[] Recode(string password)
        //{
        //    //return Pkcs8.Encode(password, Encoded, EncryptedEncoding);
        //    return Pair.EncodePair(password, PairInformation);
        //}

        //public WalletFile ToWalletEncryption(string password)
        //{
        //    if (Meta.whenCreated == default)
        //        Meta.whenCreated = DateTime.Now.Ticks;

        //    if (IsLocked) 
        //        Unlock(password);

        //    Encoded = Recode(password);
        //    return Pair.ToJsonPair(KeyType, Address, Meta, Encoded, !string.IsNullOrEmpty(password));
        //}

        //public string ToJson(string password)
        //{
        //    return JsonConvert.SerializeObject(ToWalletEncryption(password));
        //}

        //public KeyringPair Derive(string sUri) => Derive(sUri, null);
        //public KeyringPair Derive(string sUri, Meta meta)
        //{
        //    if (IsLocked)
        //        throw new InvalidCastException("Cannot derive on a locked KeyPair");

        //    var path = Uri.KeyExtractPath(sUri);
        //    var derived = Uri.KeyFromPath(PairInformation, path.Path, KeyType);

        //    return Pair.CreatePair(KeyringAddress.Standard(KeyType), derived, Meta, null, EncryptedEncoding, Keyring.DEFAULT_SS58);
        //}

        /// <summary>
        /// Build an account instance from KeyPair
        /// </summary>
        /// <returns></returns>
        /// <exception cref="InvalidOperationException"></exception>
        //public Account GetAccount()
        //{
        //    if (IsLocked)
        //        throw new InvalidOperationException("Cannot build account instance on locked KeyPair");

        //    return Account.Build(KeyType, PairInformation.SecretKey, PairInformation.PublicKey);
        //}

        //public byte[] Sign(string message)
        //{
        //    return GetAccount().Sign(message.ToBytes());
        //}

        //public bool Verify(byte[] signature, string message)
        //    => Verify(signature, PairInformation.PublicKey, message);

        //public bool Verify(byte[] signature, byte[] publicKey, string message)
        //    => Verify(signature, publicKey, message.ToBytes());

        //public bool Verify(byte[] signature, byte[] publicKey, byte[] message)
        //{
        //    try
        //    {
        //        return GetAccount().Verify(signature, publicKey, message);
        //    } catch(Exception)
        //    {
        //        return false;
        //    }
            
        //}
    }
}
