using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Text;

namespace AuthorizationServer
{
    public class JwtSigningService
    {
        private readonly RsaSecurityKey _rsaSecurityKey;
        private readonly SigningCredentials _signingCredentials;
        public RSAParameters PublicKey { get; }

        public JwtSigningService()
        {
            //SymmetricSecurityKey
            //var securitykey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("jwtsupersecretkey_12345678901543534"));
            //_signingCredentials = new SigningCredentials(securitykey, SecurityAlgorithms.HmacSha256);

            //ASymmetricSecurityKey //6
            //Generate the RSA Key Pair(this happens once)
            var rsa = new RSACryptoServiceProvider(2048);
            PublicKey = rsa.ExportParameters(false); // Export only the public key
            string modulusBase64 = Convert.ToBase64String(PublicKey.Modulus);
            string exponentBase64 = Convert.ToBase64String(PublicKey.Exponent);
            _rsaSecurityKey = new RsaSecurityKey(rsa.ExportParameters(true)); // Private + Public key
            _signingCredentials = new SigningCredentials(_rsaSecurityKey, SecurityAlgorithms.RsaSha256);
        }

        // Expose Signing Credentials
        public SigningCredentials GetSigningCredentials()
        {
            return _signingCredentials;
        }
    }
}