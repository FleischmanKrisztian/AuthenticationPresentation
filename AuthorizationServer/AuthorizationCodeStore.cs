using AuthorizationServer;

public class AuthorizationCodeStore
{
    // This list will persist for the entire application lifecycle
    public List<AuthorizationCodeInformation> AuthorizationCodeInformations { get; set; }

    public AuthorizationCodeStore()
    {
        AuthorizationCodeInformations = new List<AuthorizationCodeInformation>();
    }
}