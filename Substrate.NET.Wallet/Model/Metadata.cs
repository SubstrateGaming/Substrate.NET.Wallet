using System.Collections.Generic;

namespace Substrate.NET.Wallet.Model
{
    public class Metadata
    {
        public string GenesisHash { get; set; }
        public bool IsHardware { get; set; }
        public string Name { get; set; }
        public List<string> Tags { get; set; } = new List<string>();
        public long WhenCreated { get; set; }  // This seems to be a Unix timestamp in milliseconds
    }
}