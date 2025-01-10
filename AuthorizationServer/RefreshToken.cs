namespace AuthorizationServer
{
    public class RefreshToken
    {
        public string UserId { get; set; }
        public string Token { get; set; } = string.Empty;
        public DateTime Created { get; set; }
        public DateTime Expires { get; set; }
        public string Scopes { get; set; }
    }
}