using AuthorizationServer;

public class RefreshTokenStore
{
    // This list will persist for the entire application lifecycle
    public List<RefreshToken> RefreshTokens { get; set; }

    public RefreshTokenStore()
    {
        RefreshTokens = new List<RefreshToken>();
    }
}