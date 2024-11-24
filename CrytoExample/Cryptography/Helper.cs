using System.Security.Cryptography;
using System.Text;

namespace CrytoExample.Cryptography
{
    public static class Helper
    {
        public static (string EncryptedText, string Nonce, string Tag) Encrypt(string plaintext, string base64Key)
        {
            byte[] key = Convert.FromBase64String(base64Key);
            byte[] nonce = new byte[12]; // 96-bit nonce
            RandomNumberGenerator.Fill(nonce);

            byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
            byte[] ciphertext = new byte[plaintextBytes.Length];
            byte[] tag = new byte[16]; // 128-bit authentication tag

            using (var aesGcm = new AesGcm(key))
            {
                aesGcm.Encrypt(nonce, plaintextBytes, ciphertext, tag);
            }

            return (
                Convert.ToBase64String(ciphertext),
                Convert.ToBase64String(nonce),
                Convert.ToBase64String(tag)
            );
        }

        public static string Decrypt(string base64Ciphertext, string base64Nonce, string base64Tag, string base64Key)
        {
            byte[] key = Convert.FromBase64String(base64Key);
            byte[] nonce = Convert.FromBase64String(base64Nonce);
            byte[] ciphertext = Convert.FromBase64String(base64Ciphertext);
            byte[] tag = Convert.FromBase64String(base64Tag);
            byte[] plaintext = new byte[ciphertext.Length];

            using (var aesGcm = new AesGcm(key))
            {
                aesGcm.Decrypt(nonce, ciphertext, tag, plaintext);
            }

            return Encoding.UTF8.GetString(plaintext);
        }
    }
}
