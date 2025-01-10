using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace AuthorizationServer.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AuthenticationController : ControllerBase
    {
        private static RSAParameters rsaPublicKey;
        private readonly JwtSigningService _jwtSigningService;

        private readonly ILogger<AuthenticationController> _logger;
        private readonly AuthorizationCodeStore _authorizationCodeStore;
        private readonly RefreshTokenStore _refreshTokenStore;
        private readonly UserStore _userStore;

        public AuthenticationController(ILogger<AuthenticationController> logger, AuthorizationCodeStore authorizationCodeStore, RefreshTokenStore refreshTokenStore, UserStore userStore, JwtSigningService jwtSigningService)
        {
            _logger = logger;
            _authorizationCodeStore = authorizationCodeStore;
            _refreshTokenStore = refreshTokenStore;
            _userStore = userStore;
            _jwtSigningService = jwtSigningService;
        }

        [HttpGet("GetAuthorizationCode")]
        public ActionResult<string> GetAuthorizationCode()
        {


            Console.WriteLine("Enter Username");
            //var username = Console.ReadLine();
            var username = "fleischman";

            Console.WriteLine("Enter Password");
            //var password = Console.ReadLine();
            var password = "test1234";

            var formData = Request.Form.ToDictionary(x => x.Key, x => x.Value.ToString());

            var scopes = formData.GetValueOrDefault("Scopes");

            //if (scopes.Contains("read"))
            //{
            //    Console.WriteLine("Do you consent for the application to have read access? (y/n)");
            //    var consent = Console.ReadLine();
            //    if (consent == "n")
            //    {
            //        scopes.Replace(" read", "");
            //    }
            //}

            //if (scopes.Contains("write"))
            //{
            //    Console.WriteLine("Do you consent for the application to have write access? (y/n)");
            //    var consent = Console.ReadLine();
            //    if (consent == "n")
            //    {
            //        scopes.Replace(" write", "");
            //    }
            //}

            //if (scopes.Contains("delete"))
            //{
            //    Console.WriteLine("Do you consent for the application to have delete access? (y/n)");
            //    var consent = Console.ReadLine();
            //    if (consent == "n")
            //    {
            //        scopes.Replace(" delete", "");
            //    }
            //}

            var myUser = _userStore.Users.FirstOrDefault(user => user.Username == username && user.Password == password);

            if (myUser != null)
            {
                var authorizationCode = Guid.NewGuid().ToString();

                var authorizationcodeInfo = new AuthorizationCodeInformation
                {
                    UserId = myUser.UserId,
                    AuthorizationCode = authorizationCode,
                    Username = username,
                    Client = formData.GetValueOrDefault("Client"),
                    Scopes = scopes,
                    ExpirationDate = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds()//4
                };

                _authorizationCodeStore.AuthorizationCodeInformations.Add(authorizationcodeInfo);
                var redirectUri = formData.GetValueOrDefault("RedirectURI") + "?code=" + authorizationCode;

                using var request = new HttpRequestMessage(HttpMethod.Post, redirectUri);

                var client = new HttpClient();

                var response = client.Send(request, HttpCompletionOption.ResponseHeadersRead);

                return Ok(response.Content.ReadAsStringAsync().Result);
            }
            else
            {
                return Unauthorized("Invalid username or password.");
            }
        }

        [HttpGet("GetAccessToken")]
        public ActionResult<string> GetAccessToken()
        {
            var formData = Request.Form.ToDictionary(x => x.Key, x => x.Value.ToString());

            var client = formData.GetValueOrDefault("Client");
            var authorizationCode = formData.GetValueOrDefault("AuthorizationCode");
            var secret = formData.GetValueOrDefault("Secret");

            var savedAuthorizationCode = _authorizationCodeStore.AuthorizationCodeInformations.FirstOrDefault(x => x.Client == client);

            if (savedAuthorizationCode != null)
            {
                var clientsFromDatabase = new List<KeyValuePair<string, string>>
                {
                    new KeyValuePair<string, string>("MyWebApplication", "MyTopSecret123")
                };

                var clientInfo = clientsFromDatabase.FirstOrDefault(c => c.Key == client && c.Value == secret);
                if (clientInfo.Key != null)
                {
                    if (savedAuthorizationCode.AuthorizationCode == authorizationCode && savedAuthorizationCode.ExpirationDate > DateTimeOffset.UtcNow.ToUnixTimeSeconds())
                    {
                        var user = _userStore.Users.FirstOrDefault(x => x.UserId == savedAuthorizationCode.UserId);

                        _authorizationCodeStore.AuthorizationCodeInformations.Remove(savedAuthorizationCode);

                        var newRefreshToken = GenerateRefreshToken(savedAuthorizationCode.UserId, savedAuthorizationCode.Scopes);
                        SetRefreshTokenToCookies(newRefreshToken);
                        _refreshTokenStore.RefreshTokens.Add(newRefreshToken);

                        var jwtToken = GenerateJwtToken(user, savedAuthorizationCode.Scopes);

                        return Ok(jwtToken);
                    }
                    else
                    {
                        return BadRequest("Invalid authorization code or it has expired.");
                    }
                }
                else
                {
                    return Unauthorized("Client or secret is incorrect.");
                }
            }

            return BadRequest("Authorization code not found.");
        }

        [HttpGet("InitializeRefreshToken")]
        public ActionResult<string> InitializeRefreshToken()
        {
            var registeredUser = new User
            {
                UserId = Guid.NewGuid().ToString(),
                Username = "fleischman",
                Password = "test1234",
                Client = "MyWebApplication"
            };

            _userStore.Users.Add(registeredUser);

            var newRefreshToken = GenerateRefreshToken("1234", "openid read write");
            SetRefreshTokenToCookies(newRefreshToken);
            return "Initialised RefreshToken";
        }

        [HttpPost("RefreshJwtToken")]
        public async Task<ActionResult<string>> RefreshJwtToken()
        {
            var currentUser = GetCurrentUser();
            if (currentUser == null)
            {
                return Unauthorized("Please login before trying to refresh token!");
            }

            var tokenDetails = _refreshTokenStore.RefreshTokens.FirstOrDefault(x => x.UserId == currentUser.UserId);

            if (tokenDetails == null)
            {
                return Unauthorized("Token does not Exist!");
            }

            var refreshToken = Request.Cookies["refreshToken"];

            if (!tokenDetails.Token.Equals(refreshToken))
            {
                return Unauthorized("Invalid Refresh Token.");
            }
            else if (tokenDetails.Expires < DateTime.Now)
            {
                return Unauthorized("Token expired.");
            }

            var newJwtToken = GenerateJwtToken(currentUser, tokenDetails.Scopes);
            var newRefreshToken = GenerateRefreshToken(currentUser.UserId, tokenDetails.Scopes);
            SetRefreshTokenToCookies(newRefreshToken);

            _refreshTokenStore.RefreshTokens.RemoveAll(x => x.UserId == currentUser.UserId);
            _refreshTokenStore.RefreshTokens.Add(newRefreshToken);

            return Ok(newJwtToken);
        }

        [HttpGet("GetPublicKey")]
        public IActionResult GetPublicKey()
        {
            var publicKey = _jwtSigningService.PublicKey;
            return Ok(new
            {
                Modulus = Convert.ToBase64String(publicKey.Modulus),
                Exponent = Convert.ToBase64String(publicKey.Exponent)
            });
        }

        private string GenerateJwtToken(User user, string scopes)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var credentials = _jwtSigningService.GetSigningCredentials();          

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.Sid, user.UserId),
                    new Claim(ClaimTypes.Name, user.Username),
                    new Claim("scope", scopes),
                    new Claim("client", user.Client)
                }),
                Expires = DateTime.UtcNow.AddMinutes(5),
                Issuer = "https://localhost:7051",//AuthorizationServer
                Audience = "https://localhost:7242/",//ResourceServer
                SigningCredentials = credentials,
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        private RefreshToken GenerateRefreshToken(string userid, string scopes)
        {
            var refreshToken = new RefreshToken
            {
                UserId = userid,
                Token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
                Expires = DateTime.Now.AddDays(7),
                Created = DateTime.Now,
                Scopes = scopes
            };

            return refreshToken;
        }

        private void SetRefreshTokenToCookies(RefreshToken newRefreshToken)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,//7
                Expires = newRefreshToken.Expires,
                Path = "/",
                SameSite = SameSiteMode.Strict,
                Secure = true
            };
            Response.Cookies.Append("refreshToken", newRefreshToken.Token, cookieOptions);
        }

        private User GetCurrentUser()
        {
            var identity = HttpContext.User.Identity as ClaimsIdentity;

            if (identity.Claims.Count() != 0)
            {
                var userClaims = identity.Claims;

                return _userStore.Users.FirstOrDefault(x => x.UserId == userClaims.FirstOrDefault(o => o.Type == ClaimTypes.Sid).Value);
            }
            return null;
        }
    }
}