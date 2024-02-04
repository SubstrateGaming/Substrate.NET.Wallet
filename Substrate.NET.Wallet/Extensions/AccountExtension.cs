using Substrate.NET.Wallet.Keyring;
using Substrate.NetApi.Model.Types;

namespace Substrate.NET.Wallet.Extensions
{
    public static class AccountExtension
    {
        public static PairInfo ToPair(this Account account) => new PairInfo(account.Bytes, account.PrivateKey);
    }
}