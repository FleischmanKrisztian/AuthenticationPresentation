using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using ResourceServer;
using System.Security.Cryptography;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();

//Asymmetric Signing Key
builder.Services.AddHttpClient<RsaKeyFetcher>(client =>
{
    client.BaseAddress = new Uri("https://localhost:7051"); // Authorization Server URL
});
var rsaKeyFetcher = new RsaKeyFetcher(new HttpClient { BaseAddress = new Uri("https://localhost:7051") });
var rsaPublicKey = await rsaKeyFetcher.GetRsaPublicKeyAsync("https://localhost:7051");

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = "https://localhost:7051",
            ValidateAudience = true,
            ValidAudience = "https://localhost:7242",
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero,
            ValidateIssuerSigningKey = true,

            //Symmetric Signing Key
            //IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("JWTSuperSecretKey_12345678901543534")),
            //Asymmetric Signing Key
            IssuerSigningKey = rsaPublicKey, // Use the public key to verify the token

        };
    });

builder.Services.AddAuthorization(options =>
{
    // Policy for "read" scope
    options.AddPolicy("ReadScope", policy =>
    {
        policy.RequireAssertion(context =>
        {
            var scopeClaim = context.User.FindFirst("scope");
            if (scopeClaim != null)
            {
                var scopes = scopeClaim.Value.Split(' ');
                return scopes.Contains("read");
            }
            return false;
        });
    });

    // Policy for "write" scope
    options.AddPolicy("WriteScope", policy =>
    {
        policy.RequireAssertion(context =>
        {
            var scopeClaim = context.User.FindFirst("scope");
            if (scopeClaim != null)
            {
                var scopes = scopeClaim.Value.Split(' ');
                return scopes.Contains("write");
            }
            return false;
        });
    });
});

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
