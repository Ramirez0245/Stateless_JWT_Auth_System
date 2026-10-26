using AuthApi.Data;
using AuthApi.Options;
using AuthApi.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

// ---- Options (fail fast on bad config) ----
builder.Services.Configure<JwtOptions>(
    builder.Configuration.GetSection(JwtOptions.Section));

var jwt = builder.Configuration.GetSection(JwtOptions.Section).Get<JwtOptions>()
    ?? throw new InvalidOperationException("Missing 'Jwt' configuration.");

byte[] keyBytes;
try { keyBytes = Convert.FromBase64String(jwt.Key); }
catch { throw new InvalidOperationException("Jwt:Key must be a base64 string."); }
if (keyBytes.Length < 32)
    throw new InvalidOperationException("Jwt:Key must decode to at least 32 bytes.");

// ---- Database ----
/* Adjust the MySqlServerVersion to match your server. I use a fixed version 
instead of AutoDetect so the app doesn’t need a live DB connection at startup. */
var connectionString = builder.Configuration.GetConnectionString("Default")
    ?? throw new InvalidOperationException("Missing connection string 'Default'.");

builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseMySql(connectionString, new MySqlServerVersion(new Version(8, 4, 0))));

// ---- Services ----
/* This registers PasswordService with ASP.NET Core’s dependency injection (DI) container.
- IPasswordService is the service contract—the interface your code can depend on.
- PasswordService is the concrete class ASP.NET Core will create to fulfill that contract.
- AddSingleton means the container creates one PasswordService instance and reuses it wherever 
    IPasswordService is requested, for the lifetime of the application. */
builder.Services.AddSingleton<IPasswordService, PasswordService>();
builder.Services.AddSingleton<ITokenService, TokenService>();

// ---- Authentication / Authorization ----
builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(o =>
    {
        o.MapInboundClaims = false; // keep "sub" and "role" as-is
        o.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = jwt.Issuer,
            ValidateAudience = true,
            ValidAudience = jwt.Audience,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(keyBytes),
            ValidAlgorithms = new[] { SecurityAlgorithms.HmacSha256 },
            ValidateLifetime = true,
            RequireExpirationTime = true,
            ClockSkew = TimeSpan.FromSeconds(30),
            NameClaimType = "sub",
            RoleClaimType = "role"
        };
    });

builder.Services.AddAuthorization();
builder.Services.AddControllers();

var app = builder.Build();

app.UseHttpsRedirection();
app.UseAuthentication();   // must come before UseAuthorization
app.UseAuthorization();
app.MapControllers();

app.Run();