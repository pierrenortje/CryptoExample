namespace CrytoExample
{
    public static class Extensions
    {
        public static string Base64UrlToBase64(this string base64Url)
        {
            // Replace URL-specific characters with standard Base64 characters
            string base64 = base64Url
                .Replace('-', '+')  // Base64 URL to Base64
                .Replace('_', '/');  // Base64 URL to Base64

            // Add padding if necessary
            int paddingLength = base64.Length % 4;
            if (paddingLength > 0)
            {
                base64 = base64.PadRight(base64.Length + (4 - paddingLength), '=');
            }

            return base64;
        }

        public static string Base64ToBase64Url(this string base64)
        {
            // Remove padding
            base64 = base64.TrimEnd('=');

            // Replace standard Base64 characters with Base64 URL characters
            string base64Url = base64
                .Replace('+', '-')  // Base64 to Base64 URL
                .Replace('/', '_'); // Base64 to Base64 URL

            return base64Url;
        }
    }
}
