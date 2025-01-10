using Microsoft.AspNetCore.Mvc;

namespace WebApplicationProject.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AuthenticationController : ControllerBase
    {
        private readonly ILogger<AuthenticationController> _logger;

        public AuthenticationController(ILogger<AuthenticationController> logger)
        {
            _logger = logger;
        }


        //FRONTEND/UNSECURE (Front channel)
        [HttpPost("Login")]
        public string Login()
        {
            var payload = new Dictionary<string, string>
            {
                { "Client" , "MyWebApplication"},
                { "ResponseType", "code" }, //1
                { "RedirectURI", "https://localhost:7141/Authentication/ExchangeAuthCodeForAccessToken/" },
                { "Scopes", "openid read write" }//2,3
            };

            using var request = new HttpRequestMessage(HttpMethod.Get, "https://localhost:7051/Authentication/GetAuthorizationCode")
            {
                Content = new FormUrlEncodedContent(payload)
            };

            var client = new HttpClient();

            var response = client.Send(request, HttpCompletionOption.ResponseHeadersRead);

            if (response.IsSuccessStatusCode)
            {
                return response.Content.ReadAsStringAsync().Result;
            }
            return "no token";
        }


        //BACKEND/SECURE (Back channel)
        [HttpPost("ExchangeAuthCodeForAccessToken")]
        public string ExchangeAuthCodeForAccessToken()
        {
            var authorizationCode = HttpContext.Request.Query["code"].ToString();

            if (string.IsNullOrEmpty(authorizationCode))
            {
                return "Invalid authorization code";
            }

            var payload = new Dictionary<string, string>
            {
                { "Client" , "MyWebApplication"},
                { "AuthorizationCode" , authorizationCode},
                { "Secret" , "MyTopSecret123"}//This secret is configured for my client in the authorization server
            };

            using var request = new HttpRequestMessage(HttpMethod.Get, "https://localhost:7051/Authentication/GetAccessToken")
            {
                Content = new FormUrlEncodedContent(payload)
            };

            var client = new HttpClient();

            var response = client.Send(request, HttpCompletionOption.ResponseHeadersRead);

            if (response.IsSuccessStatusCode)
            {
                return response.Content.ReadAsStringAsync().Result;
            }
            return "AuthorizationCode or Secret was not good!";
        }
    }
}