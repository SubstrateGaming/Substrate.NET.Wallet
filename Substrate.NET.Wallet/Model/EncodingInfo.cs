using System.Collections.Generic;

namespace Substrate.NET.Wallet.Model
{
    public class EncodingInfo
    {
        public List<string> Content { get; set; } = new List<string>();
        public List<string> Type { get; set; } = new List<string>();
        public string Version { get; set; }
    }
}