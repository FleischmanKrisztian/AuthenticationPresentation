using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;

namespace ResourceServer
{
    public class RsaKeyFetcher
    {
        private readonly HttpClient _httpClient;

        public RsaKeyFetcher(HttpClient httpClient)
        {
            _httpClient = httpClient;
        }

        public async Task<RsaSecurityKey> GetRsaPublicKeyAsync(string authorizationServerUrl)
        {
            var response = await _httpClient.GetAsync($"{authorizationServerUrl}/Authentication/GetPublicKey");
            response.EnsureSuccessStatusCode();

            var keyData = await response.Content.ReadFromJsonAsync<RsaKeyResponse>();

            if (keyData == null || string.IsNullOrEmpty(keyData.Modulus) || string.IsNullOrEmpty(keyData.Exponent))
            {
                throw new InvalidOperationException("Invalid RSA key data received from Authorization Server.");
            }

            // Convert Modulus and Exponent from Base64 to byte arrays
            var modulus = Convert.FromBase64String(keyData.Modulus);
            var exponent = Convert.FromBase64String(keyData.Exponent);

            // Create RSA Parameters
            var rsaParameters = new RSAParameters
            {
                Modulus = modulus,
                Exponent = exponent
            };

            // Return an RsaSecurityKey
            return new RsaSecurityKey(rsaParameters);
        }

        private class RsaKeyResponse
        {
            public string Modulus { get; set; } = string.Empty;
            public string Exponent { get; set; } = string.Empty;
        }
    }

}
