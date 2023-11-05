using Substrate.NET.Wallet.Keyring;
using Substrate.NetApi.Model.Types;
using System;
using System.Collections.Generic;
using System.Text;

namespace Substrate.NET.Wallet.Extensions
{
    public static class AccountExtension
    {
        public static PairInfo ToPair(this Account account) => new PairInfo(account.Bytes, account.PrivateKey);
    }
}
