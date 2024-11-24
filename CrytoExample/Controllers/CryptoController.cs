using CrytoExample.Models;
using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace CrytoExample.Controllers
{
    [ApiController]
    [Route("api/crypto")]
    public class RSAController : ControllerBase
    {
        #region Private Fields
        private static RSAParameters _publicKey;
        private static RSAParameters _privateKey;
        private static string _symKey;
        #endregion

        #region Static Constructor
        static RSAController()
        {
            // Load the certificate from the current machine's certificate store
            var certificate = Helper.LoadCertificateFromMachineStore(Configuration.CertificateThumbprint);
            var rsa = certificate.GetRSAPrivateKey();
            if (rsa == null)
                throw new Exception("Failed to load certificate.");

            _publicKey = rsa.ExportParameters(false);
            _privateKey = rsa.ExportParameters(true);
        }
        #endregion

        #region Action Results
        [HttpGet("public-key")]
        public IActionResult GetPublicKey()
        {
            string mod = Convert.ToBase64String(_publicKey.Modulus);
            string exp = Convert.ToBase64String(_publicKey.Exponent);

            var jwk = new
            {
                // Key type (RSA)
                kty = "RSA",

                // Public key modulus
                n = mod.Base64ToBase64Url(),

                // Exponent
                e = exp.Base64ToBase64Url(),

                // Signature algorithm
                alg = "RSA-OAEP-256",

                // Key use (enc = encryption i.e. the public key)
                use = "enc"
            };

            return Ok(jwk);
        }

        [HttpPost("encrypted-data")]
        public IActionResult GetEncryptedData([FromBody] EncryptedContentModel data)
        {
            try
            {
                byte[] encryptedData = null;
                using (var rsa = RSA.Create())
                {
                    // Import our private key before we can decrypt
                    rsa.ImportParameters(_privateKey);

                    // Convert the body content to bytes
                    byte[] encBytes = Convert.FromBase64String(data.Ciphertext);

                    // And decrypt it using RSA
                    encryptedData = rsa.Decrypt(encBytes, RSAEncryptionPadding.OaepSHA256);
                }

                // Convert the bytes back to string
                string clientPK = Encoding.UTF8.GetString(encryptedData);

                // And convert the base64Url to base64
                _symKey = clientPK.Base64UrlToBase64();

                // The secret content
                string secretMessage = "Keep it secret! Keep it safe!";

                // Perform the encryption using the symmetric public key the client has sent us
                var result = Cryptography.Helper.Encrypt(secretMessage, _symKey);

                // And send them the nonce (IV), tag and encrypted content
                return Ok(new
                {
                    // Nonce
                    n = result.Nonce,

                    // Encrypted value
                    v = result.EncryptedText,

                    // AES-GCM Tag
                    t = result.Tag
                });
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        [HttpPost("decrypt-data")]
        public IActionResult DecryptData([FromBody] DecryptContentModel data)
        {
            try
            {
                byte[] encryptedData = Convert.FromBase64String(data.Ciphertext);

                // Separate IV, ciphertext, and tag
                int tagLength = 16; // AES-GCM standard tag length

                byte[] tag = new byte[tagLength];
                byte[] ciphertext = new byte[encryptedData.Length - tagLength];

                // Extract ciphertext
                Buffer.BlockCopy(encryptedData, 0, ciphertext, 0, ciphertext.Length);
                // Extract tag
                Buffer.BlockCopy(encryptedData, ciphertext.Length, tag, 0, tagLength);

                string tagb64 = Convert.ToBase64String(tag);
                string ciphertextb64 = Convert.ToBase64String(ciphertext);

                // Decrypt it using the symmetric key
                var result = Cryptography.Helper.Decrypt(ciphertextb64, data.Nonce, tagb64, _symKey);

                return Ok(new { success = true, message= result });
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }
        #endregion
    }
}
