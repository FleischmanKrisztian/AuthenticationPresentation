namespace AuthorizationServer
{
    public class AuthorizationCodeInformation
    {
        public string UserId { get; set; }
        public string AuthorizationCode { get; set; }

        public string RedirectURI { get; set; }

        public string Scopes { get; set; }

        public string Client { get; set; }

        public string Username { get; set; }

        public long ExpirationDate { get; set; }
    }
}