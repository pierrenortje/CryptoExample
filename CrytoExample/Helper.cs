using System.Security.Cryptography.X509Certificates;

namespace CrytoExample
{
    public static class Helper
    {
        public static X509Certificate2 LoadCertificateFromMachineStore(string thumbprint)
        {
            // Open the local machine's My store (Personal certificates)
            using (X509Store store = new X509Store(StoreName.My, StoreLocation.LocalMachine))
            {
                store.Open(OpenFlags.ReadOnly);  // Open the store in read-only mode

                // Find the certificate by thumbprint
                X509Certificate2Collection certCollection = store.Certificates.Find(
                    X509FindType.FindByThumbprint,
                    thumbprint,
                    validOnly: false // Include all certificates, even if they're not valid
                );

                // If found, return the first certificate
                if (certCollection.Count > 0)
                {
                    return certCollection[0]; // Return the first certificate found
                }
            }

            return null; // Return null if the certificate was not found
        }
    }
}
