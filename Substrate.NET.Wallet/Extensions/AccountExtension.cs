using Substrate.NET.Wallet.Keyring;
using Substrate.NetApi.Model.Types;

namespace Substrate.NET.Wallet.Extensions
{
    /// <summary>
    /// Account extension methods
    /// </summary>
    public static class AccountExtension
    {
        /// <summary>
        /// Clone an instance of an Account
        /// </summary>
        /// <param name="account"></param>
        /// <returns></returns>
        public static Account Clone(this Account account)
        {
            var clonedAccount = new Account();
            clonedAccount.Create(account.KeyType, account.PrivateKey, account.Bytes);

            return clonedAccount;
        }
    }
}