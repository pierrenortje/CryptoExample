namespace CrytoExample.Models
{
    public class EncryptedContentModel
    {
        public string Ciphertext { get; set; }
    }

    public class DecryptContentModel
    {
        public string Ciphertext { get; set; }
        public string Nonce { get; set; }
    }
}
