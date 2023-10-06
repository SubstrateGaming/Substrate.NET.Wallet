namespace Substrate.NET.Wallet.Model
{
    public class EncodedData
    {
        public string Encoded { get; set; }
        public EncodingInfo Encoding { get; set; }
        public string Address { get; set; }
        public Metadata Meta { get; set; }
    }
}